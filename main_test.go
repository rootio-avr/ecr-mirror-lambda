package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// --- fakeECR test double ---

type setPolicyCall struct {
	repo   string
	policy string
}

type setLifecycleCall struct {
	repo   string
	policy string
}

type fakeECR struct {
	repos           map[string]bool
	repoPolicy      map[string]string
	lifecyclePolicy map[string]string

	createdRepos      []string
	setPolicyCalls    []setPolicyCall
	setLifecycleCalls []setLifecycleCall
}

func newFakeECR() *fakeECR {
	return &fakeECR{
		repos:           make(map[string]bool),
		repoPolicy:      make(map[string]string),
		lifecyclePolicy: make(map[string]string),
	}
}

func (f *fakeECR) CreateRepository(_ context.Context, params *ecr.CreateRepositoryInput, _ ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error) {
	n := *params.RepositoryName
	if f.repos[n] {
		return nil, &ecrtypes.RepositoryAlreadyExistsException{}
	}
	f.repos[n] = true
	f.createdRepos = append(f.createdRepos, n)
	return &ecr.CreateRepositoryOutput{}, nil
}

func (f *fakeECR) GetRepositoryPolicy(_ context.Context, params *ecr.GetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	n := *params.RepositoryName
	policy, ok := f.repoPolicy[n]
	if !ok {
		return nil, &ecrtypes.RepositoryPolicyNotFoundException{}
	}
	return &ecr.GetRepositoryPolicyOutput{PolicyText: &policy}, nil
}

func (f *fakeECR) SetRepositoryPolicy(_ context.Context, params *ecr.SetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.SetRepositoryPolicyOutput, error) {
	f.setPolicyCalls = append(f.setPolicyCalls, setPolicyCall{
		repo:   *params.RepositoryName,
		policy: *params.PolicyText,
	})
	return &ecr.SetRepositoryPolicyOutput{}, nil
}

func (f *fakeECR) GetLifecyclePolicy(_ context.Context, params *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	n := *params.RepositoryName
	policy, ok := f.lifecyclePolicy[n]
	if !ok {
		return nil, &ecrtypes.LifecyclePolicyNotFoundException{}
	}
	return &ecr.GetLifecyclePolicyOutput{LifecyclePolicyText: &policy}, nil
}

func (f *fakeECR) PutLifecyclePolicy(_ context.Context, params *ecr.PutLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.PutLifecyclePolicyOutput, error) {
	f.setLifecycleCalls = append(f.setLifecycleCalls, setLifecycleCall{
		repo:   *params.RepositoryName,
		policy: *params.LifecyclePolicyText,
	})
	return &ecr.PutLifecyclePolicyOutput{}, nil
}

// --- allowlist tests ---

func TestIsRepoAllowed(t *testing.T) {
	t.Run("allows all repos when allowlist is empty", func(t *testing.T) {
		h := &Handler{cfg: Config{AllowedRepos: nil}}
		if !h.isRepoAllowed("any-repo") {
			t.Error("expected repo to be allowed when allowlist is empty")
		}
	})

	t.Run("allows repo present in allowlist", func(t *testing.T) {
		h := &Handler{cfg: Config{AllowedRepos: []string{"python", "golang"}}}
		if !h.isRepoAllowed("python") {
			t.Error("expected python to be allowed")
		}
	})

	t.Run("rejects repo not in allowlist", func(t *testing.T) {
		h := &Handler{cfg: Config{AllowedRepos: []string{"python", "golang"}}}
		if h.isRepoAllowed("ruby") {
			t.Error("expected ruby to be rejected")
		}
	})
}

// --- ensureECRRepo tests ---

func TestEnsureECRRepo(t *testing.T) {
	ctx := context.Background()
	const baseRepo = "root-mirror"

	t.Run("copies repo policy and lifecycle policy from base for new repo", func(t *testing.T) {
		fake := newFakeECR()
		fake.repoPolicy[baseRepo] = `{"Version":"2012-10-17"}`
		fake.lifecyclePolicy[baseRepo] = `{"rules":[]}`

		h := &Handler{dstRepoName: baseRepo, ecrClient: fake}
		if err := h.ensureECRRepo(ctx, baseRepo+"/python"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(fake.setPolicyCalls) != 1 {
			t.Fatalf("expected 1 SetRepositoryPolicy call, got %d", len(fake.setPolicyCalls))
		}
		if fake.setPolicyCalls[0].repo != baseRepo+"/python" {
			t.Errorf("SetRepositoryPolicy on wrong repo: %s", fake.setPolicyCalls[0].repo)
		}
		if fake.setPolicyCalls[0].policy != `{"Version":"2012-10-17"}` {
			t.Errorf("unexpected policy text: %s", fake.setPolicyCalls[0].policy)
		}

		if len(fake.setLifecycleCalls) != 1 {
			t.Fatalf("expected 1 PutLifecyclePolicy call, got %d", len(fake.setLifecycleCalls))
		}
		if fake.setLifecycleCalls[0].repo != baseRepo+"/python" {
			t.Errorf("PutLifecyclePolicy on wrong repo: %s", fake.setLifecycleCalls[0].repo)
		}
		if fake.setLifecycleCalls[0].policy != `{"rules":[]}` {
			t.Errorf("unexpected lifecycle policy text: %s", fake.setLifecycleCalls[0].policy)
		}
	})

	t.Run("does not copy policies for already-existing repo", func(t *testing.T) {
		fake := newFakeECR()
		fake.repos[baseRepo+"/python"] = true
		fake.repoPolicy[baseRepo] = `{"Version":"2012-10-17"}`
		fake.lifecyclePolicy[baseRepo] = `{"rules":[]}`

		h := &Handler{dstRepoName: baseRepo, ecrClient: fake}
		if err := h.ensureECRRepo(ctx, baseRepo+"/python"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(fake.setPolicyCalls) != 0 {
			t.Errorf("expected no SetRepositoryPolicy calls for existing repo, got %v", fake.setPolicyCalls)
		}
		if len(fake.setLifecycleCalls) != 0 {
			t.Errorf("expected no PutLifecyclePolicy calls for existing repo, got %v", fake.setLifecycleCalls)
		}
	})

	t.Run("skips repo policy copy if base has no repo policy", func(t *testing.T) {
		fake := newFakeECR()
		fake.lifecyclePolicy[baseRepo] = `{"rules":[]}`

		h := &Handler{dstRepoName: baseRepo, ecrClient: fake}
		if err := h.ensureECRRepo(ctx, baseRepo+"/python"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(fake.setPolicyCalls) != 0 {
			t.Errorf("expected no SetRepositoryPolicy calls, got %v", fake.setPolicyCalls)
		}
		if len(fake.setLifecycleCalls) != 1 {
			t.Errorf("expected PutLifecyclePolicy to be called, got %d calls", len(fake.setLifecycleCalls))
		}
	})

	t.Run("skips lifecycle policy copy if base has no lifecycle policy", func(t *testing.T) {
		fake := newFakeECR()
		fake.repoPolicy[baseRepo] = `{"Version":"2012-10-17"}`

		h := &Handler{dstRepoName: baseRepo, ecrClient: fake}
		if err := h.ensureECRRepo(ctx, baseRepo+"/python"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(fake.setPolicyCalls) != 1 {
			t.Errorf("expected SetRepositoryPolicy to be called, got %d calls", len(fake.setPolicyCalls))
		}
		if len(fake.setLifecycleCalls) != 0 {
			t.Errorf("expected no PutLifecyclePolicy calls, got %v", fake.setLifecycleCalls)
		}
	})

	t.Run("returns error on unexpected GetRepositoryPolicy failure", func(t *testing.T) {
		fake := newFakeECR()
		fake.repoPolicy["__error__"] = "" // sentinel unused; we'll override below

		// Use a custom fake that returns an unexpected error
		h := &Handler{dstRepoName: baseRepo, ecrClient: &erroringECR{inner: fake}}
		err := h.ensureECRRepo(ctx, baseRepo+"/python")
		if err == nil {
			t.Fatal("expected error but got nil")
		}
	})
}

// erroringECR wraps fakeECR but returns an unexpected error from GetRepositoryPolicy.
type erroringECR struct {
	inner *fakeECR
}

func (e *erroringECR) CreateRepository(ctx context.Context, params *ecr.CreateRepositoryInput, optFns ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error) {
	return e.inner.CreateRepository(ctx, params, optFns...)
}

func (e *erroringECR) GetRepositoryPolicy(_ context.Context, _ *ecr.GetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	return nil, errors.New("unexpected AWS error")
}

func (e *erroringECR) SetRepositoryPolicy(ctx context.Context, params *ecr.SetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.SetRepositoryPolicyOutput, error) {
	return e.inner.SetRepositoryPolicy(ctx, params, optFns...)
}

func (e *erroringECR) GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	return e.inner.GetLifecyclePolicy(ctx, params, optFns...)
}

func (e *erroringECR) PutLifecyclePolicy(ctx context.Context, params *ecr.PutLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.PutLifecyclePolicyOutput, error) {
	return e.inner.PutLifecyclePolicy(ctx, params, optFns...)
}

// --- existing tests ---

func makeMultiArchIndex(t *testing.T) v1.ImageIndex {
	t.Helper()
	amd64Img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("creating amd64 image: %v", err)
	}
	arm64Img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("creating arm64 image: %v", err)
	}
	return mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{
			Add:        amd64Img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		},
		mutate.IndexAddendum{
			Add:        arm64Img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		},
	)
}

func TestBuildCopyOptions(t *testing.T) {
	srcServer := httptest.NewServer(registry.New())
	defer srcServer.Close()
	srcHost := strings.TrimPrefix(srcServer.URL, "http://")

	dstServer := httptest.NewServer(registry.New())
	defer dstServer.Close()
	dstHost := strings.TrimPrefix(dstServer.URL, "http://")

	// Push multi-arch index to source registry
	idx := makeMultiArchIndex(t)
	srcRef, err := name.NewTag(srcHost+"/test/image:latest", name.Insecure)
	if err != nil {
		t.Fatalf("parsing src ref: %v", err)
	}
	if err := remote.WriteIndex(srcRef, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		t.Fatalf("pushing index to source: %v", err)
	}

	srcTagStr := srcHost + "/test/image:latest"

	t.Run("with arch copies single platform image", func(t *testing.T) {
		dstTagStr := dstHost + "/test/single-arch:latest"
		opts := append(buildCopyOptions(authn.DefaultKeychain, context.Background(), "amd64"), crane.Insecure)
		if err := crane.Copy(srcTagStr, dstTagStr, opts...); err != nil {
			t.Fatalf("copying: %v", err)
		}

		dstRef, _ := name.NewTag(dstTagStr, name.Insecure)
		desc, err := remote.Get(dstRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			t.Fatalf("getting dst manifest: %v", err)
		}
		if desc.MediaType == types.OCIImageIndex || desc.MediaType == types.DockerManifestList {
			t.Errorf("expected single image but got image index (mediaType=%s)", desc.MediaType)
		}
	})

	t.Run("without arch copies full image index", func(t *testing.T) {
		dstTagStr := dstHost + "/test/multi-arch:latest"
		opts := append(buildCopyOptions(authn.DefaultKeychain, context.Background(), ""), crane.Insecure)
		if err := crane.Copy(srcTagStr, dstTagStr, opts...); err != nil {
			t.Fatalf("copying: %v", err)
		}

		dstRef, _ := name.NewTag(dstTagStr, name.Insecure)
		desc, err := remote.Get(dstRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			t.Fatalf("getting dst manifest: %v", err)
		}
		if desc.MediaType != types.OCIImageIndex && desc.MediaType != types.DockerManifestList {
			t.Errorf("expected image index but got mediaType=%s", desc.MediaType)
		}
	})
}
