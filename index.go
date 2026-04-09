package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// updateImageIndex fetches the arch image at archRef, reads the current OCI
// Image Index at indexRef (if any), replaces the entry for arch, and pushes
// the updated index back to indexRef. nameOpts are forwarded to name.NewTag
// (e.g. name.Insecure for tests).
func updateImageIndex(
	ctx context.Context,
	keychain authn.Keychain,
	archRef string,
	indexRef string,
	arch string,
	nameOpts ...name.Option,
) error {
	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(keychain),
		remote.WithContext(ctx),
	}

	archTag, archTagErr := name.NewTag(archRef, nameOpts...)
	if archTagErr != nil {
		return fmt.Errorf("parsing arch ref %q: %w", archRef, archTagErr)
	}
	indexTag, idxTagErr := name.NewTag(indexRef, nameOpts...)
	if idxTagErr != nil {
		return fmt.Errorf("parsing index ref %q: %w", indexRef, idxTagErr)
	}

	archDesc, archDescErr := remote.Get(archTag, remoteOpts...)
	if archDescErr != nil {
		return fmt.Errorf("fetching arch image %q: %w", archRef, archDescErr)
	}
	archImg, archImgErr := archDesc.Image()
	if archImgErr != nil {
		return fmt.Errorf("loading arch image %q as v1.Image: %w", archRef, archImgErr)
	}

	// readExistingIndex + WriteIndex is not atomic - it is the caller responsibility to take care of atomicity using a
	// lock
	base, readIdxErr := readExistingIndex(ctx, indexTag, arch, remoteOpts)
	if readIdxErr != nil {
		return fmt.Errorf("reading existing index at %q: %w", indexRef, readIdxErr)
	}

	addendum, addendumErr := archIndexAddendum(archImg, arch)
	if addendumErr != nil {
		return fmt.Errorf("building index addendum for %q: %w", archRef, addendumErr)
	}

	newIndex := mutate.AppendManifests(base, addendum)

	if err := remote.WriteIndex(indexTag, newIndex, remoteOpts...); err != nil {
		return fmt.Errorf("writing index to %q: %w", indexRef, err)
	}
	return nil
}

// archIndexAddendum builds a mutate.IndexAddendum for img using the full
// descriptor derived from the image (correct digest, size, media type) and
// the platform from the webhook arch field.
func archIndexAddendum(img v1.Image, arch string) (mutate.IndexAddendum, error) {
	desc, err := partial.Descriptor(img)
	if err != nil {
		return mutate.IndexAddendum{}, fmt.Errorf("computing image descriptor: %w", err)
	}

	desc.Platform = &v1.Platform{OS: osLinux, Architecture: arch}
	return mutate.IndexAddendum{Add: img, Descriptor: *desc}, nil
}

// readExistingIndex fetches the current OCI Image Index at ref and removes the
// entry for arch (so the caller can append a fresh one). Returns (empty.Index, nil)
// if the tag does not exist (404). Returns an error for any other fetch failure.
func readExistingIndex(
	ctx context.Context,
	ref name.Tag,
	arch string,
	remoteOpts []remote.Option,
) (v1.ImageIndex, error) {
	desc, descErr := remote.Get(ref, remoteOpts...)
	if descErr != nil {
		var transportErr *transport.Error
		if errors.As(descErr, &transportErr) && transportErr.StatusCode == http.StatusNotFound {
			return empty.Index, nil
		}
		return nil, fmt.Errorf("fetching existing index %q: %w", ref.String(), descErr)
	}

	idx, imgIdxErr := desc.ImageIndex()
	if imgIdxErr != nil {
		slog.WarnContext(ctx, "existing tag is not an image index; starting fresh", "ref", ref.String())
		return empty.Index, nil
	}
	return mutate.RemoveManifests(idx, func(d v1.Descriptor) bool {
		return d.Platform != nil && d.Platform.Architecture == arch
	}), nil
}
