# Robust Multi-Arch Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the ECR mirror Lambda to copy each arch variant to an arch-qualified tag and maintain an OCI Image Index at the base tag, using a DynamoDB distributed lock to prevent race conditions.

**Architecture:** When a webhook fires with an `arch` field, the handler (1) copies the single-arch image to `{tag}-{arch}` in ECR, (2) acquires a DynamoDB lock on `{repo}:{tag}`, (3) reads the existing OCI Image Index at `{tag}` (if any), replaces the entry for this arch, and writes the updated index back. When no `arch` is present the existing whole-index copy behaviour is preserved. The lock uses DynamoDB conditional writes with a TTL for safety.

**Tech Stack:** Go 1.25, AWS SDK v2 (DynamoDB), google/go-containerregistry (crane, remote, mutate), Terraform

---

## File Structure

**New files:**
- `lock.go` — `dynamoLockClient` interface, `acquireLock`, `releaseLock`
- `index.go` — `updateImageIndex`, `readExistingIndex`
- `lock_test.go` — unit tests for lock functions with a mock DynamoDB client
- `index_test.go` — unit tests for index functions using in-memory registries
- `terraform/dynamodb.tf` — DynamoDB table resource

**Modified files:**
- `main.go` — add `DynamoLockTable` to `Config`; add `dynamoClient dynamoLockClient`, `nameOpts []name.Option`, `craneOpts []crane.Option` to `Handler`; update `NewHandler` and `Handle`
- `main_test.go` — add `TestHandle_MultiArch` integration test
- `terraform/lambda.tf` — add DynamoDB IAM statement and `DYNAMO_LOCK_TABLE` env var
- `go.mod` / `go.sum` — add `github.com/aws/aws-sdk-go-v2/service/dynamodb`

---

## Task 1: Add DynamoDB SDK dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the dependency**

```bash
rtk go get github.com/aws/aws-sdk-go-v2/service/dynamodb
```

Expected: `go.mod` and `go.sum` updated with `github.com/aws/aws-sdk-go-v2/service/dynamodb`.

- [ ] **Step 2: Verify build still passes**

```bash
rtk go build ./...
```

Expected: exits 0, no errors.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add DynamoDB SDK dependency"
```

---

## Task 2: Implement distributed lock (TDD)

**Files:**
- Create: `lock.go`
- Create: `lock_test.go`

- [ ] **Step 1: Write the failing tests**

Create `lock_test.go`:

```go
package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// mockDynamoClient implements dynamoLockClient using an in-memory map.
type mockDynamoClient struct {
	items  map[string]struct{}
	putErr error // if non-nil, PutItem returns this (non-conditional) error
}

func newMockDynamo() *mockDynamoClient {
	return &mockDynamoClient{items: make(map[string]struct{})}
}

func (m *mockDynamoClient) PutItem(_ context.Context, params *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	key := params.Item[lockPKAttr].(*dynamodbtypes.AttributeValueMemberS).Value
	if _, exists := m.items[key]; exists {
		return nil, &dynamodbtypes.ConditionalCheckFailedException{}
	}
	m.items[key] = struct{}{}
	return &dynamodb.PutItemOutput{}, nil
}

func (m *mockDynamoClient) DeleteItem(_ context.Context, params *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	key := params.Key[lockPKAttr].(*dynamodbtypes.AttributeValueMemberS).Value
	delete(m.items, key)
	return &dynamodb.DeleteItemOutput{}, nil
}

func TestAcquireLock_Success(t *testing.T) {
	mock := newMockDynamo()
	if err := acquireLock(context.Background(), mock, "test-table", "repo:tag"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, ok := mock.items["repo:tag"]; !ok {
		t.Error("lock item not present in DynamoDB after acquire")
	}
}

func TestAcquireLock_Timeout(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = struct{}{} // pre-lock so acquire always fails
	ctx, cancel := context.WithTimeout(context.Background(), 2*lockRetryDelay)
	defer cancel()
	if err := acquireLock(ctx, mock, "test-table", "repo:tag"); err == nil {
		t.Fatal("expected error when lock cannot be acquired, got nil")
	}
}

func TestAcquireLock_NonConditionalError(t *testing.T) {
	mock := newMockDynamo()
	mock.putErr = fmt.Errorf("network failure")
	if err := acquireLock(context.Background(), mock, "test-table", "repo:tag"); err == nil {
		t.Fatal("expected error on non-conditional PutItem failure, got nil")
	}
}

func TestReleaseLock(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = struct{}{}
	releaseLock(context.Background(), mock, "test-table", "repo:tag")
	if _, ok := mock.items["repo:tag"]; ok {
		t.Error("lock item still present after release")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
rtk go test ./... -run "TestAcquireLock|TestReleaseLock" -v
```

Expected: compile error — `acquireLock`, `releaseLock`, `lockPKAttr`, `lockRetryDelay` undefined.

- [ ] **Step 3: Create lock.go**

Create `lock.go`:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	lockPKAttr     = "pk"
	lockTTLAttr    = "ttl"
	lockTTL        = 60 * time.Second
	lockRetryDelay = 1 * time.Second
	lockTimeout    = 30 * time.Second
)

// dynamoLockClient is the subset of dynamodb.Client used for locking.
type dynamoLockClient interface {
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// acquireLock attempts to create a lock item in DynamoDB using a conditional
// write. It retries until the context is cancelled or lockTimeout elapses.
func acquireLock(ctx context.Context, client dynamoLockClient, tableName, key string) error {
	ttl := strconv.FormatInt(time.Now().Add(lockTTL).Unix(), 10)
	deadline := time.Now().Add(lockTimeout)

	for time.Now().Before(deadline) {
		_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: aws.String(tableName),
			Item: map[string]dynamodbtypes.AttributeValue{
				lockPKAttr:  &dynamodbtypes.AttributeValueMemberS{Value: key},
				lockTTLAttr: &dynamodbtypes.AttributeValueMemberN{Value: ttl},
			},
			ConditionExpression: aws.String("attribute_not_exists(pk)"),
		})
		if err == nil {
			return nil
		}
		var condErr *dynamodbtypes.ConditionalCheckFailedException
		if !errors.As(err, &condErr) {
			return fmt.Errorf("acquiring lock %q: %w", key, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockRetryDelay):
		}
	}
	return fmt.Errorf("timed out acquiring lock %q", key)
}

// releaseLock deletes the lock item from DynamoDB. Errors are logged but not
// returned — the TTL will expire the lock automatically if this fails.
func releaseLock(ctx context.Context, client dynamoLockClient, tableName, key string) {
	if _, err := client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(tableName),
		Key: map[string]dynamodbtypes.AttributeValue{
			lockPKAttr: &dynamodbtypes.AttributeValueMemberS{Value: key},
		},
	}); err != nil {
		slog.Warn("failed to release lock", "key", key, "error", err)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
rtk go test ./... -run "TestAcquireLock|TestReleaseLock" -v
```

Expected: all four tests PASS.

- [ ] **Step 5: Commit**

```bash
git add lock.go lock_test.go
git commit -m "feat: add DynamoDB distributed lock"
```

---

## Task 3: Implement OCI image index management (TDD)

**Files:**
- Create: `index.go`
- Create: `index_test.go`

- [ ] **Step 1: Write the failing tests**

Create `index_test.go`:

```go
package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// pushRandomImage pushes a random single-arch image to host/ref and returns it.
func pushRandomImage(t *testing.T, host, ref string) v1.Image {
	t.Helper()
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("creating random image: %v", err)
	}
	tag, err := name.NewTag(host+"/"+ref, name.Insecure)
	if err != nil {
		t.Fatalf("parsing ref %s: %v", ref, err)
	}
	if err := remote.Write(tag, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		t.Fatalf("pushing image to %s: %v", ref, err)
	}
	return img
}

// indexManifestArchs returns a map of architecture → true for all entries in
// the OCI Image Index at host/ref.
func indexManifestArchs(t *testing.T, host, ref string) map[string]bool {
	t.Helper()
	tag, err := name.NewTag(host+"/"+ref, name.Insecure)
	if err != nil {
		t.Fatalf("parsing ref: %v", err)
	}
	desc, err := remote.Get(tag, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		t.Fatalf("fetching %s: %v", ref, err)
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		t.Fatalf("not an image index: %v", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("reading index manifest: %v", err)
	}
	archs := make(map[string]bool, len(manifest.Manifests))
	for _, m := range manifest.Manifests {
		if m.Platform != nil {
			archs[m.Platform.Architecture] = true
		}
	}
	return archs
}

func newTestRegistry(t *testing.T) (srv *httptest.Server, host string) {
	t.Helper()
	srv = httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host = strings.TrimPrefix(srv.URL, "http://")
	return
}

func TestUpdateImageIndex_CreatesNewIndex(t *testing.T) {
	_, host := newTestRegistry(t)

	pushRandomImage(t, host, "test/img:v1-amd64")

	err := updateImageIndex(
		context.Background(), authn.DefaultKeychain,
		host+"/test/img:v1-amd64",
		host+"/test/img:v1",
		"amd64",
		name.Insecure,
	)
	if err != nil {
		t.Fatalf("updateImageIndex: %v", err)
	}

	archs := indexManifestArchs(t, host, "test/img:v1")
	if len(archs) != 1 || !archs["amd64"] {
		t.Errorf("expected index with only amd64, got: %v", archs)
	}
}

func TestUpdateImageIndex_AddsSecondArch(t *testing.T) {
	_, host := newTestRegistry(t)

	pushRandomImage(t, host, "test/img:v1-amd64")
	pushRandomImage(t, host, "test/img:v1-arm64")

	if err := updateImageIndex(
		context.Background(), authn.DefaultKeychain,
		host+"/test/img:v1-amd64", host+"/test/img:v1", "amd64", name.Insecure,
	); err != nil {
		t.Fatalf("first updateImageIndex: %v", err)
	}
	if err := updateImageIndex(
		context.Background(), authn.DefaultKeychain,
		host+"/test/img:v1-arm64", host+"/test/img:v1", "arm64", name.Insecure,
	); err != nil {
		t.Fatalf("second updateImageIndex: %v", err)
	}

	archs := indexManifestArchs(t, host, "test/img:v1")
	if len(archs) != 2 || !archs["amd64"] || !archs["arm64"] {
		t.Errorf("expected index with amd64 and arm64, got: %v", archs)
	}
}

func TestUpdateImageIndex_ReplacesExistingArch(t *testing.T) {
	_, host := newTestRegistry(t)

	pushRandomImage(t, host, "test/img:v1-amd64")
	if err := updateImageIndex(
		context.Background(), authn.DefaultKeychain,
		host+"/test/img:v1-amd64", host+"/test/img:v1", "amd64", name.Insecure,
	); err != nil {
		t.Fatalf("first updateImageIndex: %v", err)
	}

	// Push a fresh image to the same arch tag (simulates a re-push)
	pushRandomImage(t, host, "test/img:v1-amd64")
	if err := updateImageIndex(
		context.Background(), authn.DefaultKeychain,
		host+"/test/img:v1-amd64", host+"/test/img:v1", "amd64", name.Insecure,
	); err != nil {
		t.Fatalf("second updateImageIndex: %v", err)
	}

	archs := indexManifestArchs(t, host, "test/img:v1")
	if len(archs) != 1 {
		t.Errorf("expected exactly 1 manifest (no duplicates), got: %v", archs)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
rtk go test ./... -run TestUpdateImageIndex -v
```

Expected: compile error — `updateImageIndex` undefined.

- [ ] **Step 3: Create index.go**

Create `index.go`:

```go
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// updateImageIndex fetches the arch image at archRef, reads the current OCI
// Image Index at indexRef (if any), replaces the entry for arch, and pushes
// the updated index back to indexRef. nameOpts are forwarded to name.NewTag
// (e.g. name.Insecure for tests).
func updateImageIndex(ctx context.Context, keychain authn.Keychain, archRef, indexRef, arch string, nameOpts ...name.Option) error {
	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(keychain),
		remote.WithContext(ctx),
	}

	archTag, err := name.NewTag(archRef, nameOpts...)
	if err != nil {
		return fmt.Errorf("parsing arch ref %q: %w", archRef, err)
	}
	indexTag, err := name.NewTag(indexRef, nameOpts...)
	if err != nil {
		return fmt.Errorf("parsing index ref %q: %w", indexRef, err)
	}

	archDesc, err := remote.Get(archTag, remoteOpts...)
	if err != nil {
		return fmt.Errorf("fetching arch image %q: %w", archRef, err)
	}
	archImg, err := archDesc.Image()
	if err != nil {
		return fmt.Errorf("loading arch image %q as v1.Image: %w", archRef, err)
	}

	base := readExistingIndex(ctx, indexTag, arch, remoteOpts)

	newIndex := mutate.AppendManifests(base, mutate.IndexAddendum{
		Add: archImg,
		Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: osLinux, Architecture: arch},
		},
	})

	if err := remote.WriteIndex(indexTag, newIndex, remoteOpts...); err != nil {
		return fmt.Errorf("writing index to %q: %w", indexRef, err)
	}
	return nil
}

// readExistingIndex fetches the current OCI Image Index at ref and removes the
// entry for arch (so the caller can append a fresh one). Returns empty.Index
// if the tag does not exist or is not an image index.
func readExistingIndex(ctx context.Context, ref name.Tag, arch string, remoteOpts []remote.Option) v1.ImageIndex {
	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return empty.Index
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		slog.WarnContext(ctx, "existing tag is not an image index; starting fresh", "ref", ref.String())
		return empty.Index
	}
	return mutate.RemoveManifests(idx, func(d v1.Descriptor) bool {
		return d.Platform != nil && d.Platform.Architecture == arch
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
rtk go test ./... -run TestUpdateImageIndex -v
```

Expected: all three tests PASS.

- [ ] **Step 5: Commit**

```bash
git add index.go index_test.go
git commit -m "feat: add OCI image index management"
```

---

## Task 4: Update main handler (TDD)

**Files:**
- Modify: `main.go`
- Modify: `main_test.go`

- [ ] **Step 1: Write the failing integration test**

Add the following to `main_test.go` (after existing imports — extend the import block):

Add these imports to `main_test.go`:
```go
import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
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
```

Add the following test function to `main_test.go`:

```go
func signRequest(t *testing.T, secret, id, body string) events.LambdaFunctionURLRequest {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id + "." + ts + "." + body))
	sig := "v1," + hex.EncodeToString(mac.Sum(nil))
	return events.LambdaFunctionURLRequest{
		Body: body,
		Headers: map[string]string{
			"webhook-id":        id,
			"webhook-timestamp": ts,
			"webhook-signature": sig,
		},
	}
}

func TestHandle_MultiArch(t *testing.T) {
	srcSrv := httptest.NewServer(registry.New())
	defer srcSrv.Close()
	srcHost := strings.TrimPrefix(srcSrv.URL, "http://")

	dstSrv := httptest.NewServer(registry.New())
	defer dstSrv.Close()
	dstHost := strings.TrimPrefix(dstSrv.URL, "http://")

	// Push multi-arch index to source so crane.Copy can resolve platform variants.
	idx := makeMultiArchIndex(t)
	srcRef, _ := name.NewTag(srcHost+"/library/nginx:v1", name.Insecure)
	if err := remote.WriteIndex(srcRef, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		t.Fatalf("pushing source index: %v", err)
	}

	dynamo := newMockDynamo()
	h := &Handler{
		webhookSecret: "test-secret",
		cfg: Config{
			DstRepoURL:      dstHost + "/mirror",
			RegistryHost:    srcHost,
			DynamoLockTable: "test-table",
		},
		dstRepoName:  "mirror",
		dynamoClient: dynamo,
		keychain:     authn.DefaultKeychain,
		nameOpts:     []name.Option{name.Insecure},
		craneOpts:    []crane.Option{crane.Insecure},
	}

	sendEvent := func(arch string) {
		t.Helper()
		body := fmt.Sprintf(
			`{"specversion":"1.0","type":"io.root.cr.image.created.v1","source":"https://src","id":"evt1","time":"2026-01-01T00:00:00Z","subject":%q,"datacontenttype":"application/json","data":{"image_repo":"library/nginx","image_tag":"v1","arch":%q}}`,
			srcHost+"/library/nginx:v1", arch,
		)
		req := signRequest(t, "test-secret", "id1", body)
		resp, err := h.Handle(context.Background(), req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("Handle(%s): err=%v status=%d body=%s", arch, err, resp.StatusCode, resp.Body)
		}
	}

	sendEvent("amd64")
	sendEvent("arm64")

	// Each arch must have its own tagged image.
	for _, arch := range []string{"amd64", "arm64"} {
		archRef, _ := name.NewTag(dstHost+"/mirror/library/nginx:v1-"+arch, name.Insecure)
		if _, err := remote.Get(archRef, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
			t.Errorf("arch-tagged image v1-%s not found in ECR: %v", arch, err)
		}
	}

	// Base tag must be an OCI Image Index referencing both arches.
	indexRef, _ := name.NewTag(dstHost+"/mirror/library/nginx:v1", name.Insecure)
	desc, err := remote.Get(indexRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		t.Fatalf("base tag not found: %v", err)
	}
	idx2, err := desc.ImageIndex()
	if err != nil {
		t.Fatalf("base tag is not an image index: %v", err)
	}
	manifest, _ := idx2.IndexManifest()
	archs := make(map[string]bool)
	for _, m := range manifest.Manifests {
		if m.Platform != nil {
			archs[m.Platform.Architecture] = true
		}
	}
	if !archs["amd64"] || !archs["arm64"] {
		t.Errorf("expected amd64 and arm64 in index, got: %v", archs)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
rtk go test ./... -run TestHandle_MultiArch -v
```

Expected: compile error — `Handler` has no fields `dynamoClient`, `nameOpts`, `craneOpts`; `Config` has no field `DynamoLockTable`.

- [ ] **Step 3: Update Config and Handler structs in main.go**

Replace the existing `Config` struct:

```go
type Config struct {
	WebhookSecretARN string `env:"WEBHOOK_SECRET_ARN,required"`
	RootAPIKeyARN    string `env:"ROOT_API_KEY_ARN,required"`
	DstRepoURL       string `env:"DST_REPO_URL,required"`
	RegistryHost     string `env:"ROOT_REGISTRY_HOST" envDefault:"cr.root.io"`
	DynamoLockTable  string `env:"DYNAMO_LOCK_TABLE,required"`
}
```

Replace the existing `Handler` struct:

```go
type Handler struct {
	webhookSecret string
	cfg           Config
	dstRepoName   string
	ecrClient     *ecr.Client
	dynamoClient  dynamoLockClient
	keychain      authn.Keychain
	nameOpts      []name.Option   // extra name options (e.g. name.Insecure in tests)
	craneOpts     []crane.Option  // extra crane options (e.g. crane.Insecure in tests)
}
```

- [ ] **Step 4: Update NewHandler to initialise the DynamoDB client**

Add `"github.com/aws/aws-sdk-go-v2/service/dynamodb"` and `"github.com/google/go-containerregistry/pkg/name"` to the import block in `main.go`.

Replace the `return &Handler{...}` at the end of `NewHandler` with:

```go
	return &Handler{
		webhookSecret: webhookSecret,
		cfg:           cfg,
		dstRepoName:   dstRepoName,
		ecrClient:     ecr.NewFromConfig(awsCfg),
		dynamoClient:  dynamodb.NewFromConfig(awsCfg),
		keychain:      authn.NewMultiKeychain(rootKeychain, amazonKeychain),
	}, nil
```

- [ ] **Step 5: Update ensureECRRepo to be a no-op when ecrClient is nil**

Replace the existing `ensureECRRepo` function body with:

```go
func (h *Handler) ensureECRRepo(ctx context.Context, repoName string) error {
	if h.ecrClient == nil {
		return nil
	}
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
```

- [ ] **Step 6: Replace the Handle function body**

Replace the entire `Handle` method with:

```go
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
	ecrRepoName := fmt.Sprintf("%s/%s", h.dstRepoName, data.ImageRepo)
	if err := h.ensureECRRepo(ctx, ecrRepoName); err != nil {
		log.Error("failed to ensure ECR repo", "error", err, "repo", ecrRepoName)
		return respond(http.StatusInternalServerError, "internal error")
	}

	if data.Arch == "" {
		// No arch info: copy the whole image index as-is (existing behaviour).
		dst := fmt.Sprintf("%s/%s:%s", h.cfg.DstRepoURL, data.ImageRepo, data.ImageTag)
		log.Info("copying image (no arch)", "src", src, "dst", dst)
		opts := append(buildCopyOptions(h.keychain, ctx, ""), h.craneOpts...)
		if err := crane.Copy(src, dst, opts...); err != nil {
			log.Error("failed to copy image", "error", err)
			return respond(http.StatusInternalServerError, "image copy failed")
		}
		log.Info("image copied successfully", "dst", dst)
		return respond(http.StatusOK, "ok")
	}

	// Arch-specific flow:
	// 1. Copy this arch's image to an arch-qualified tag.
	archDst := fmt.Sprintf("%s/%s:%s-%s", h.cfg.DstRepoURL, data.ImageRepo, data.ImageTag, data.Arch)
	log.Info("copying arch image", "src", src, "dst", archDst, "arch", data.Arch)
	opts := append(buildCopyOptions(h.keychain, ctx, data.Arch), h.craneOpts...)
	if err := crane.Copy(src, archDst, opts...); err != nil {
		log.Error("failed to copy arch image", "error", err)
		return respond(http.StatusInternalServerError, "image copy failed")
	}

	// 2. Under a distributed lock, update the OCI Image Index at the base tag.
	lockKey := fmt.Sprintf("%s:%s", data.ImageRepo, data.ImageTag)
	if err := acquireLock(ctx, h.dynamoClient, h.cfg.DynamoLockTable, lockKey); err != nil {
		log.Error("failed to acquire lock", "key", lockKey, "error", err)
		return respond(http.StatusInternalServerError, "lock acquisition failed")
	}
	defer releaseLock(ctx, h.dynamoClient, h.cfg.DynamoLockTable, lockKey)

	indexDst := fmt.Sprintf("%s/%s:%s", h.cfg.DstRepoURL, data.ImageRepo, data.ImageTag)
	log.Info("updating image index", "index_dst", indexDst, "arch_src", archDst)
	if err := updateImageIndex(ctx, h.keychain, archDst, indexDst, data.Arch, h.nameOpts...); err != nil {
		log.Error("failed to update image index", "error", err)
		return respond(http.StatusInternalServerError, "index update failed")
	}

	log.Info("image index updated successfully", "dst", indexDst, "arch", data.Arch)
	return respond(http.StatusOK, "ok")
}
```

- [ ] **Step 7: Run all tests**

```bash
rtk go test ./... -v -count=1
```

Expected: all tests PASS (TestBuildCopyOptions, TestAcquireLock*, TestReleaseLock, TestUpdateImageIndex*, TestHandle_MultiArch).

- [ ] **Step 8: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: update handler for robust multi-arch support"
```

---

## Task 5: Terraform infrastructure for DynamoDB

**Files:**
- Create: `terraform/dynamodb.tf`
- Modify: `terraform/lambda.tf`

- [ ] **Step 1: Create terraform/dynamodb.tf**

```hcl
resource "aws_dynamodb_table" "mirror_locks" {
  name         = "root-ecr-mirror-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}
```

- [ ] **Step 2: Add DynamoDB IAM statement to lambda.tf**

In `terraform/lambda.tf`, inside the `data "aws_iam_policy_document" "lambda_permissions"` block, add after the `SecretsRead` statement:

```hcl
  statement {
    sid    = "DynamoDBLock"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
    ]
    resources = [aws_dynamodb_table.mirror_locks.arn]
  }
```

- [ ] **Step 3: Add DYNAMO_LOCK_TABLE env var to lambda.tf**

In `terraform/lambda.tf`, inside the `resource "aws_lambda_function" "mirror"` `environment.variables` block, add:

```hcl
      DYNAMO_LOCK_TABLE = aws_dynamodb_table.mirror_locks.name
```

- [ ] **Step 4: Validate Terraform**

```bash
cd terraform && terraform validate
```

Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Commit**

```bash
git add terraform/dynamodb.tf terraform/lambda.tf
git commit -m "feat: add DynamoDB lock table and Lambda permissions"
```

---

## Task 6: Final verification

- [ ] **Step 1: Run full test suite**

```bash
rtk go test ./... -v -count=1
```

Expected: all tests PASS, no skips.

- [ ] **Step 2: Verify Docker build**

```bash
docker build --provenance=false --sbom=false -t ecr-mirror-test .
```

Expected: `Successfully built` (or `exporting to image`) — exits 0.

- [ ] **Step 3: Push branch**

```bash
git push origin HEAD
```

---

## Self-Review

**Spec coverage check:**

| Requirement | Covered by |
|---|---|
| Copy each arch to `{tag}-{arch}` | Task 4 Step 6 (`archDst` formatting, `crane.Copy`) |
| Acquire DynamoDB lock on `{repo}:{tag}` | Task 2 (`acquireLock`), Task 4 Step 6 |
| Read existing OCI Image Index, add/update arch entry, push | Task 3 (`updateImageIndex`, `readExistingIndex`) |
| Release lock | Task 2 (`releaseLock`), Task 4 Step 6 (`defer`) |
| No arch lost under concurrency | DynamoDB conditional write prevents concurrent writers; test `TestHandle_MultiArch` exercises sequential correctness |
| ECR lifecycle policies can target `*-amd64` | Arch-qualified tags `{tag}-{arch}` satisfy this |
| OCI Image Index at base tag | `updateImageIndex` writes index to base tag |

**Placeholder scan:** No TBD/TODO placeholders found. All code blocks are complete.

**Type consistency check:**
- `dynamoLockClient` interface defined in `lock.go`, used as field type in `Handler` (main.go) and as parameter type in `acquireLock`/`releaseLock` — consistent.
- `mockDynamoClient` in `lock_test.go` implements `dynamoLockClient` — same method signatures.
- `updateImageIndex` signature in `index.go` matches calls in `main.go` and `index_test.go` — consistent.
- `lockPKAttr`, `lockRetryDelay` constants defined in `lock.go`, referenced in `lock_test.go` — same package, consistent.
- `osLinux` constant defined in `main.go` (existing), used in `index.go` — same package, consistent.
