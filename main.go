package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	ecrcreds "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/caarlos0/env/v11"
	cloudevents "github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	maxTimestampAge   = 300 // seconds
	signaturePrefix   = "v1,"
	imageCreatedEvent = "io.root.cr.image.created.v1"

	headerWebhookID        = "webhook-id"
	headerWebhookTimestamp = "webhook-timestamp"
	headerWebhookSignature = "webhook-signature"

	osLinux = "linux"
)

type Config struct {
	WebhookSecretARN string   `env:"WEBHOOK_SECRET_ARN,required"`
	RootAPIKeyARN    string   `env:"ROOT_API_KEY_ARN,required"`
	DstRepoURL       string   `env:"DST_REPO_URL,required"`
	RegistryHost     string   `env:"ROOT_REGISTRY_HOST" envDefault:"cr.root.io"`
	AllowedRepos     []string `env:"ALLOWED_REPOS" envSeparator:","`
}

type ecrAPI interface {
	CreateRepository(ctx context.Context, params *ecr.CreateRepositoryInput, optFns ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error)
	GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
	SetRepositoryPolicy(ctx context.Context, params *ecr.SetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.SetRepositoryPolicyOutput, error)
	GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
	PutLifecyclePolicy(ctx context.Context, params *ecr.PutLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.PutLifecyclePolicyOutput, error)
}

type Handler struct {
	webhookSecret string
	cfg           Config
	dstRepoName   string
	ecrClient     ecrAPI
	keychain      authn.Keychain
}

func NewHandler(ctx context.Context) (*Handler, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	sm := secretsmanager.NewFromConfig(awsCfg)

	webhookSecret, err := getSecret(ctx, sm, cfg.WebhookSecretARN)
	if err != nil {
		return nil, fmt.Errorf("loading webhook secret: %w", err)
	}

	rootAPIKey, err := getSecret(ctx, sm, cfg.RootAPIKeyARN)
	if err != nil {
		return nil, fmt.Errorf("loading root API key: %w", err)
	}

	amazonKeychain := authn.NewKeychainFromHelper(ecrcreds.NewECRHelper(ecrcreds.WithLogger(os.Stderr)))

	rootKeychain := &staticKeychain{
		registry: cfg.RegistryHost,
		auth:     &authn.Basic{Username: "root", Password: rootAPIKey},
	}

	dstRepoName := cfg.DstRepoURL
	if i := strings.Index(cfg.DstRepoURL, "/"); i != -1 {
		dstRepoName = cfg.DstRepoURL[i+1:]
	}

	return &Handler{
		webhookSecret: webhookSecret,
		cfg:           cfg,
		dstRepoName:   dstRepoName,
		ecrClient:     ecr.NewFromConfig(awsCfg),
		keychain:      authn.NewMultiKeychain(rootKeychain, amazonKeychain),
	}, nil
}

func main() {
	ctx := context.Background()

	h, err := NewHandler(ctx)
	if err != nil {
		slog.Error("failed to initialize handler", "error", err)
		os.Exit(1)
	}

	lambda.Start(h.Handle)
}

func (h *Handler) Handle(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	if err := h.verifySignature(req); err != nil {
		slog.Warn("signature verification failed", "error", err)
		return respond(http.StatusUnauthorized, "signature verification failed")
	}

	var ce cloudevents.Event
	if err := ce.UnmarshalJSON([]byte(req.Body)); err != nil {
		slog.Error("failed to parse CloudEvents payload", "error", err)
		return respond(http.StatusBadRequest, "invalid payload")
	}

	var data ImageEventData
	if err := ce.DataAs(&data); err != nil {
		slog.Error("failed to parse event data", "error", err)
		return respond(http.StatusBadRequest, "invalid event data")
	}

	log := slog.With("webhook_id", req.Headers[headerWebhookID], "event_id", ce.ID())

	log.Info("received event",
		"type", ce.Type(),
		"subject", ce.Subject(),
		"image_repo", data.ImageRepo,
		"image_tag", data.ImageTag,
	)

	if ce.Type() != imageCreatedEvent {
		log.Info("skipping unhandled event type", "type", ce.Type())
		return respond(http.StatusOK, "event type ignored")
	}

	if ce.Subject() == "" || data.ImageRepo == "" || data.ImageTag == "" {
		log.Warn("missing required fields in event data")
		return respond(http.StatusBadRequest, "missing subject, image_repo, or image_tag")
	}

	src := ce.Subject()

	if !h.isRepoAllowed(data.ImageRepo) {
		log.Info("repo not in allowlist, skipping", "repo", data.ImageRepo)
		return respond(http.StatusOK, "repo not allowed")
	}

	ecrRepoName := fmt.Sprintf("%s/%s", h.dstRepoName, data.ImageRepo)
	if err := h.ensureECRRepo(ctx, ecrRepoName); err != nil {
		log.Error("failed to ensure ECR repo", "error", err, "repo", ecrRepoName)
		return respond(http.StatusInternalServerError, "internal error")
	}

	dst := fmt.Sprintf("%s/%s:%s", h.cfg.DstRepoURL, data.ImageRepo, data.ImageTag)

	log.Info("copying image", "src", src, "dst", dst)
	if err := crane.Copy(src, dst, buildCopyOptions(h.keychain, ctx, data.Arch)...); err != nil {
		log.Error("failed to copy image", "error", err, "src", src, "dst", dst)
		return respond(http.StatusInternalServerError, "image copy failed")
	}

	log.Info("image copied successfully", "src", src, "dst", dst)
	return respond(http.StatusOK, "ok")
}

func buildCopyOptions(keychain authn.Keychain, ctx context.Context, arch string) []crane.Option {
	opts := []crane.Option{
		crane.WithAuthFromKeychain(keychain),
		crane.WithContext(ctx),
	}
	if arch != "" {
		opts = append(opts, crane.WithPlatform(&v1.Platform{OS: osLinux, Architecture: arch}))
	}
	return opts
}

// --- Standard Webhooks signature verification ---

func (h *Handler) verifySignature(req events.LambdaFunctionURLRequest) error {
	msgID := req.Headers[headerWebhookID]
	ts := req.Headers[headerWebhookTimestamp]
	sig := req.Headers[headerWebhookSignature]

	if msgID == "" || ts == "" || sig == "" {
		return errors.New("missing required webhook headers")
	}

	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	diff := time.Now().Unix() - tsInt
	if diff > maxTimestampAge || diff < -maxTimestampAge {
		return errors.New("timestamp too old or too far in the future")
	}

	signedPayload := fmt.Sprintf("%s.%s.%s", msgID, ts, req.Body)
	mac := hmac.New(sha256.New, []byte(h.webhookSecret))
	mac.Write([]byte(signedPayload))
	expected := hex.EncodeToString(mac.Sum(nil))

	for _, part := range strings.Split(sig, " ") {
		if !strings.HasPrefix(part, signaturePrefix) {
			continue
		}
		candidate := strings.TrimPrefix(part, signaturePrefix)
		if hmac.Equal([]byte(expected), []byte(candidate)) {
			return nil
		}
	}

	return errors.New("no matching signature found")
}

// --- ECR helpers ---

func (h *Handler) ensureECRRepo(ctx context.Context, repoName string) error {
	slog.Debug("creating repo...", "repo", repoName)
	_, err := h.ecrClient.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName:     &repoName,
		ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
	})
	if err != nil {
		var exists *ecrtypes.RepositoryAlreadyExistsException
		if errors.As(err, &exists) {
			slog.Debug("repo already exists, skipping creation", "repo", repoName)
			return nil
		}
		return fmt.Errorf("creating ECR repo %s: %w", repoName, err)
	}
	slog.Info("created ECR repo", "repo", repoName)

	slog.Debug("copying repo policy...", "baseRepo", h.dstRepoName, "repo", repoName)
	if err := h.copyRepoPolicy(ctx, repoName); err != nil {
		return err
	}
	slog.Debug("copied repo policy", "baseRepo", h.dstRepoName, "repo", repoName)

	slog.Debug("copying lifecycle policy...", "baseRepo", h.dstRepoName, "repo", repoName)
	if err := h.copyLifecyclePolicy(ctx, repoName); err != nil {
		return err
	}
	slog.Debug("copied lifecycle policy", "baseRepo", h.dstRepoName, "repo", repoName)

	return nil
}

func (h *Handler) copyRepoPolicy(ctx context.Context, newRepo string) error {
	slog.Debug("getting repo policy...", "baseRepo", h.dstRepoName)
	out, err := h.ecrClient.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
		RepositoryName: &h.dstRepoName,
	})
	if err != nil {
		var notFound *ecrtypes.RepositoryPolicyNotFoundException
		if errors.As(err, &notFound) {
			slog.Debug("no repo policy found in base repo, skipping", "baseRepo", h.dstRepoName)
			return nil
		}
		return fmt.Errorf("getting repo policy from base repo: %w", err)
	}

	slog.Debug("setting repo policy...", "baseRepo", h.dstRepoName, "repo", newRepo)
	_, err = h.ecrClient.SetRepositoryPolicy(ctx, &ecr.SetRepositoryPolicyInput{
		RepositoryName: &newRepo,
		PolicyText:     out.PolicyText,
	})
	return err
}

func (h *Handler) copyLifecyclePolicy(ctx context.Context, newRepo string) error {
	slog.Debug("getting lifecycle policy...", "repo", h.dstRepoName)
	out, err := h.ecrClient.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: &h.dstRepoName,
	})
	if err != nil {
		var notFound *ecrtypes.LifecyclePolicyNotFoundException
		if errors.As(err, &notFound) {
			slog.Debug("no lifecycle policy found in base repo, skipping", "repo", h.dstRepoName)
			return nil
		}
		return fmt.Errorf("getting lifecycle policy from base repo: %w", err)
	}

	slog.Debug("setting lifecycle policy...", "baseRepo", h.dstRepoName, "repo", newRepo)
	_, err = h.ecrClient.PutLifecyclePolicy(ctx, &ecr.PutLifecyclePolicyInput{
		RepositoryName:      &newRepo,
		LifecyclePolicyText: out.LifecyclePolicyText,
	})
	return err
}

func (h *Handler) isRepoAllowed(repo string) bool {
	log := slog.With("repo", repo)
	if len(h.cfg.AllowedRepos) == 0 {
		log.Debug("no AllowedRepos configured, allowing all repos")
		return true
	}
	for _, allowedRepo := range h.cfg.AllowedRepos {
		log.Debug("checking AllowedRepos", "allowedRepo", allowedRepo)
		if allowedRepo == repo {
			log.Debug("repo allowed", "allowedRepo", allowedRepo)
			return true
		}
	}
	log.Debug("repo not allowed")

	return false
}

// --- Auth ---

// staticKeychain returns fixed credentials for a single registry
// and Anonymous for everything else.
type staticKeychain struct {
	registry string
	auth     authn.Authenticator
}

func (k *staticKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	if res.RegistryStr() != k.registry {
		return authn.Anonymous, nil
	}
	return k.auth, nil
}

// ImageEventData is the custom data payload for Root image events.
type ImageEventData struct {
	ImageRepo   string `json:"image_repo"`
	ImageTag    string `json:"image_tag"`
	ImageDigest string `json:"image_digest"`
	Arch        string `json:"arch"`
}

// --- Utilities ---

func getSecret(ctx context.Context, sm *secretsmanager.Client, arn string) (string, error) {
	out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &arn,
	})
	if err != nil {
		return "", fmt.Errorf("getting secret %s: %w", arn, err)
	}
	return *out.SecretString, nil
}

func respond(status int, body string) (events.LambdaFunctionURLResponse, error) {
	return events.LambdaFunctionURLResponse{
		StatusCode: status,
		Body:       body,
	}, nil
}
