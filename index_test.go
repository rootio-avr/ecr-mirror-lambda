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

// pushRandomImage pushes a random single-arch image to host/ref.
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
