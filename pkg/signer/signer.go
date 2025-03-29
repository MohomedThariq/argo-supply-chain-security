package signer

import (
	"context"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/attest"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/sign"
)

const (
	DefaultSecretKey = "k8s://argo-slsa/signing-secret"
)

// SignWithConfigOpts will sign an oci with user defined configurations
func SignWithConfigOpts(ctx context.Context, ociImage string, cfg config.Config) error {
	switch cfg.SignerType {
	case config.SecretSigner:
		return sign.SignOci(ociImage, DefaultSecretKey, ctx, cfg)
	case config.KmsSigner:
		return sign.SignOci(ociImage, cfg.KmsURL, ctx, cfg)
	case config.FulcioSigner:
		return sign.SignOci(ociImage, "", ctx, cfg)
	}

	return fmt.Errorf("error occured while signing")
}

func AttestWithConfigOpts(ctx context.Context, cfg config.Config, ociImage string, payload []byte) ([]any, error) {
	switch cfg.SignerType {
	case config.SecretSigner:
		return attest.AttestOci(ctx, cfg, ociImage, DefaultSecretKey, payload)
	case config.KmsSigner:
		return attest.AttestOci(ctx, cfg, ociImage, cfg.KmsURL, payload)
	case config.FulcioSigner:
		return attest.AttestOci(ctx, cfg, ociImage, "", payload)
	}

	return nil, fmt.Errorf("error occured while attesting")
}
