package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

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
