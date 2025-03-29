package sbom

import (
	"context"
	"fmt"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/sbom/oci"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer"
)

const (
	sbomType = options.PredicateCycloneDX
)

func GenerateSBOMWithConfigOpts(ctx context.Context, ociImage string, cfg config.Config) error {
	switch cfg.SignerType {
	case config.SecretSigner:
		return oci.GenerateSBOMforOCI(ctx, cfg, signer.DefaultSecretKey, ociImage, sbomType)
	case config.KmsSigner:
		return oci.GenerateSBOMforOCI(ctx, cfg, cfg.KmsURL, ociImage, sbomType)
	case config.FulcioSigner:
		return oci.GenerateSBOMforOCI(ctx, cfg, "", ociImage, sbomType)
	}

	return fmt.Errorf("error occured while generating SBOM")
}
