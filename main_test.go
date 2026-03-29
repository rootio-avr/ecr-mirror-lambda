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
	"github.com/stretchr/testify/mock"
)

// --- mockECRAPI ---

type mockECRAPI struct {
	mock.Mock
}

func (m *mockECRAPI) CreateRepository(ctx context.Context, params *ecr.CreateRepositoryInput, _ ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*ecr.CreateRepositoryOutput), args.Error(1)
}

func (m *mockECRAPI) GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*ecr.GetRepositoryPolicyOutput), args.Error(1)
}

func (m *mockECRAPI) SetRepositoryPolicy(ctx context.Context, params *ecr.SetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.SetRepositoryPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*ecr.SetRepositoryPolicyOutput), args.Error(1)
}

func (m *mockECRAPI) GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*ecr.GetLifecyclePolicyOutput), args.Error(1)
}

func (m *mockECRAPI) PutLifecyclePolicy(ctx context.Context, params *ecr.PutLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.PutLifecyclePolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*ecr.PutLifecyclePolicyOutput), args.Error(1)
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

func ptr(s string) *string { return &s }

func TestEnsureECRRepo(t *testing.T) {
	ctx := context.Background()
	const baseRepo = "root-mirror"
	const newRepo = baseRepo + "/python"
	const repoPolicy = `{"Version":"2012-10-17"}`
	const lifecyclePolicy = `{"rules":[]}`

	t.Run("copies repo policy and lifecycle policy from base for new repo", func(t *testing.T) {
		m := &mockECRAPI{}
		m.On("CreateRepository", ctx, mock.MatchedBy(func(p *ecr.CreateRepositoryInput) bool { return *p.RepositoryName == newRepo })).
			Return(&ecr.CreateRepositoryOutput{}, nil)
		m.On("GetRepositoryPolicy", ctx, mock.MatchedBy(func(p *ecr.GetRepositoryPolicyInput) bool { return *p.RepositoryName == baseRepo })).
			Return(&ecr.GetRepositoryPolicyOutput{PolicyText: ptr(repoPolicy)}, nil)
		m.On("SetRepositoryPolicy", ctx, mock.MatchedBy(func(p *ecr.SetRepositoryPolicyInput) bool {
			return *p.RepositoryName == newRepo && *p.PolicyText == repoPolicy
		})).Return(&ecr.SetRepositoryPolicyOutput{}, nil)
		m.On("GetLifecyclePolicy", ctx, mock.MatchedBy(func(p *ecr.GetLifecyclePolicyInput) bool { return *p.RepositoryName == baseRepo })).
			Return(&ecr.GetLifecyclePolicyOutput{LifecyclePolicyText: ptr(lifecyclePolicy)}, nil)
		m.On("PutLifecyclePolicy", ctx, mock.MatchedBy(func(p *ecr.PutLifecyclePolicyInput) bool {
			return *p.RepositoryName == newRepo && *p.LifecyclePolicyText == lifecyclePolicy
		})).Return(&ecr.PutLifecyclePolicyOutput{}, nil)

		h := &Handler{dstRepoName: baseRepo, ecrClient: m}
		if err := h.ensureECRRepo(ctx, newRepo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("does not copy policies for already-existing repo", func(t *testing.T) {
		m := &mockECRAPI{}
		m.On("CreateRepository", ctx, mock.Anything).
			Return(&ecr.CreateRepositoryOutput{}, &ecrtypes.RepositoryAlreadyExistsException{})

		h := &Handler{dstRepoName: baseRepo, ecrClient: m}
		if err := h.ensureECRRepo(ctx, newRepo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
		m.AssertNotCalled(t, "GetRepositoryPolicy")
		m.AssertNotCalled(t, "GetLifecyclePolicy")
	})

	t.Run("skips repo policy copy if base has no repo policy", func(t *testing.T) {
		m := &mockECRAPI{}
		m.On("CreateRepository", ctx, mock.Anything).Return(&ecr.CreateRepositoryOutput{}, nil)
		m.On("GetRepositoryPolicy", ctx, mock.Anything).
			Return(&ecr.GetRepositoryPolicyOutput{}, &ecrtypes.RepositoryPolicyNotFoundException{})
		m.On("GetLifecyclePolicy", ctx, mock.Anything).
			Return(&ecr.GetLifecyclePolicyOutput{LifecyclePolicyText: ptr(lifecyclePolicy)}, nil)
		m.On("PutLifecyclePolicy", ctx, mock.Anything).Return(&ecr.PutLifecyclePolicyOutput{}, nil)

		h := &Handler{dstRepoName: baseRepo, ecrClient: m}
		if err := h.ensureECRRepo(ctx, newRepo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
		m.AssertNotCalled(t, "SetRepositoryPolicy")
	})

	t.Run("skips lifecycle policy copy if base has no lifecycle policy", func(t *testing.T) {
		m := &mockECRAPI{}
		m.On("CreateRepository", ctx, mock.Anything).Return(&ecr.CreateRepositoryOutput{}, nil)
		m.On("GetRepositoryPolicy", ctx, mock.Anything).
			Return(&ecr.GetRepositoryPolicyOutput{PolicyText: ptr(repoPolicy)}, nil)
		m.On("SetRepositoryPolicy", ctx, mock.Anything).Return(&ecr.SetRepositoryPolicyOutput{}, nil)
		m.On("GetLifecyclePolicy", ctx, mock.Anything).
			Return(&ecr.GetLifecyclePolicyOutput{}, &ecrtypes.LifecyclePolicyNotFoundException{})

		h := &Handler{dstRepoName: baseRepo, ecrClient: m}
		if err := h.ensureECRRepo(ctx, newRepo); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
		m.AssertNotCalled(t, "PutLifecyclePolicy")
	})

	t.Run("returns error on unexpected GetRepositoryPolicy failure", func(t *testing.T) {
		m := &mockECRAPI{}
		m.On("CreateRepository", ctx, mock.Anything).Return(&ecr.CreateRepositoryOutput{}, nil)
		m.On("GetRepositoryPolicy", ctx, mock.Anything).
			Return(&ecr.GetRepositoryPolicyOutput{}, errors.New("unexpected AWS error"))

		h := &Handler{dstRepoName: baseRepo, ecrClient: m}
		if err := h.ensureECRRepo(ctx, newRepo); err == nil {
			t.Fatal("expected error but got nil")
		}
		m.AssertExpectations(t)
	})
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
