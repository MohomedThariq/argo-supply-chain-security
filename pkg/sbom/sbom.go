package sbom

import (
	"context"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/sbom/oci"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer"
)

func GenerateSBOMWithConfigOpts(ctx context.Context, ociImage string, cfg config.Config) error {
	switch cfg.SignerType {
	case config.SecretSigner:
		return oci.GenerateSBOMforOCI(ctx, cfg, signer.DefaultSecretKey, ociImage)
	case config.KmsSigner:
		return oci.GenerateSBOMforOCI(ctx, cfg, cfg.KmsURL, ociImage)
	case config.FulcioSigner:
		return oci.GenerateSBOMforOCI(ctx, cfg, "", ociImage)
	}

	return fmt.Errorf("error occured while generating SBOM")
}
