package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	ecrcreds "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/caarlos0/env/v11"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
)

const (
	maxTimestampAge   = 300 // seconds
	signaturePrefix   = "v1,"
	imageCreatedEvent = "io.root.cr.image.created.v1"

	headerWebhookID        = "webhook-id"
	headerWebhookTimestamp = "webhook-timestamp"
	headerWebhookSignature = "webhook-signature"
)

type Config struct {
	WebhookSecretARN string `env:"WEBHOOK_SECRET_ARN,required"`
	RootAPIKeyARN    string `env:"ROOT_API_KEY_ARN,required"`
	DstRepoURL       string `env:"DST_REPO_URL,required"`
	RegistryHost     string `env:"ROOT_REGISTRY_HOST" envDefault:"cr.root.io"`
}

type Handler struct {
	webhookSecret string
	cfg           Config
	dstRepoName   string
	ecrClient     *ecr.Client
	keychain      authn.Keychain
}

func NewHandler(ctx context.Context) (*Handler, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	awsCfg, err := config.LoadDefaultConfig(ctx)
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

	var ce CloudEvent
	if err := json.Unmarshal([]byte(req.Body), &ce); err != nil {
		slog.Error("failed to parse CloudEvents payload", "error", err)
		return respond(http.StatusBadRequest, "invalid payload")
	}

	log := slog.With("webhook_id", req.Headers[headerWebhookID], "event_id", ce.ID)

	log.Info("received event",
		"type", ce.Type,
		"subject", ce.Subject,
		"image_repo", ce.Data.ImageRepo,
		"image_tag", ce.Data.ImageTag,
	)

	if ce.Type != imageCreatedEvent {
		log.Info("skipping unhandled event type", "type", ce.Type)
		return respond(http.StatusOK, "event type ignored")
	}

	if ce.Subject == "" || ce.Data.ImageRepo == "" || ce.Data.ImageTag == "" {
		log.Warn("missing required fields in event data")
		return respond(http.StatusBadRequest, "missing subject, image_repo, or image_tag")
	}

	src := ce.Subject

	ecrRepoName := fmt.Sprintf("%s/%s", h.dstRepoName, ce.Data.ImageRepo)
	if err := h.ensureECRRepo(ctx, ecrRepoName); err != nil {
		log.Error("failed to ensure ECR repo", "error", err, "repo", ecrRepoName)
		return respond(http.StatusInternalServerError, "internal error")
	}

	dst := fmt.Sprintf("%s/%s:%s", h.cfg.DstRepoURL, ce.Data.ImageRepo, ce.Data.ImageTag)

	log.Info("copying image", "src", src, "dst", dst)
	if err := crane.Copy(src, dst, crane.WithAuthFromKeychain(h.keychain), crane.WithContext(ctx)); err != nil {
		log.Error("failed to copy image", "error", err, "src", src, "dst", dst)
		return respond(http.StatusInternalServerError, "image copy failed")
	}

	log.Info("image copied successfully", "src", src, "dst", dst)
	return respond(http.StatusOK, "ok")
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
	_, err := h.ecrClient.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName:     &repoName,
		ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
	})
	if err != nil {
		var exists *ecrtypes.RepositoryAlreadyExistsException
		if errors.As(err, &exists) {
			return nil
		}
		return fmt.Errorf("creating ECR repo %s: %w", repoName, err)
	}
	slog.Info("created ECR repo", "repo", repoName)
	return nil
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

// --- CloudEvents types ---

type CloudEvent struct {
	SpecVersion     string         `json:"specversion"`
	Type            string         `json:"type"`
	Source          string         `json:"source"`
	ID              string         `json:"id"`
	Time            string         `json:"time"`
	Subject         string         `json:"subject"`
	DataContentType string         `json:"datacontenttype"`
	Data            CloudEventData `json:"data"`
}

type CloudEventData struct {
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
