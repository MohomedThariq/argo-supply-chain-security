package oci

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/crane"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/sbom/syft"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/attest"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func GenerateSBOMforOCI(ctx context.Context, cfg config.Config, keyRef, oci, payloadType string) error {
	logger := log.FromContext(ctx)

	manifest, err := crane.GetManifest(cfg.AuthKeyChain, oci)
	if err != nil {
		return fmt.Errorf("getting manifest: %w", err)
	}

	isMultiPlatform, indexManifest, err := checkIfMultiMlatformImage(manifest)
	if err != nil {
		return fmt.Errorf("checking if multi-platform: %w", err)
	}

	if isMultiPlatform {
		// multi-platform image
		// following https://www.chainguard.dev/unchained/sboms-in-a-multi-architecture-world
		failed := false
		for _, manifestDescriptor := range indexManifest.Manifests {
			ref, err := name.ParseReference(oci)
			if err != nil {
				failed = true
				logger.Error(err, "parsing reference", "oci", oci)
				continue
			}
			refWithChildDigest := fmt.Sprintf("%s/%s@%s", ref.Context().RegistryStr(), ref.Context().RepositoryStr(), manifestDescriptor.Digest.String())
			sbom, err := syft.GenerateSBOMwithSyft(ctx, cfg.AuthKeyChain, refWithChildDigest)
			if err != nil {
				failed = true
				logger.Error(err, "generating SBOM with syft", "oci", oci, "platform", manifestDescriptor.Platform.String())
				continue
			}
			if _, err := attest.AttestOci(ctx, cfg, refWithChildDigest, keyRef, payloadType, sbom); err != nil {
				failed = true
				logger.Error(err, "attesting SBOM", "oci", refWithChildDigest, "platform", manifestDescriptor.Platform.String())
				continue
			}
			logger.Info("attached SBOM for multi-arch image", "oci", refWithChildDigest, "platform", manifestDescriptor.Platform.String())
		}
		if failed {
			return fmt.Errorf("failed to generate SBOM for all platforms")
		}
		return nil
	}

	sbom, err := syft.GenerateSBOMwithSyft(ctx, cfg.AuthKeyChain, oci)
	if err != nil {
		logger.Error(err, "generating SBOM with syft", "oci", oci)
		return fmt.Errorf("generating SBOM with syft: %w", err)
	}
	if _, err := attest.AttestOci(ctx, cfg, oci, keyRef, payloadType, sbom); err != nil {
		logger.Error(err, "attesting SBOM", "oci", oci)
		return fmt.Errorf("attesting SBOM: %w", err)
	}
	logger.Info("attached SBOM for oci", "oci", oci)

	return nil
}

func checkIfMultiMlatformImage(manifest []byte) (bool, *v1.IndexManifest, error) {
	var indexManifest v1.IndexManifest
	if err := json.Unmarshal(manifest, &indexManifest); err != nil {
		return false, nil, fmt.Errorf("unmarshalling manifest: %w", err)
	}

	if indexManifest.MediaType == types.DockerManifestList {
		return true, &indexManifest, nil
	}

	return false, nil, nil
}
