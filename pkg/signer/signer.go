package signer

import (
	"context"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/attest"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/sign"
)

const (
	defaultSecretKey = "k8s://argo-slsa/signing-secret"
)

// SignWithConfigOpts will sign an oci with user defined configurations
func SignWithConfigOpts(ctx context.Context, ociImage string, cfg config.Config, rcfg config.RuntimeConfig) error {
	switch cfg.SignerType {
	case config.SecretSigner:
		return sign.SignOci(ociImage, defaultSecretKey, ctx, cfg, rcfg)
	case config.KmsSigner:
		return sign.SignOci(ociImage, cfg.KmsURL, ctx, cfg, rcfg)
	case config.FulcioSigner:
		return sign.SignOci(ociImage, "", ctx, cfg, rcfg)
	}

	return fmt.Errorf("error occured while signing")
}

func AttestWithConfigOpts(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig, ociImage string, payload []byte) ([]any, error) {
	switch cfg.SignerType {
	case config.SecretSigner:
		return attest.AttestOci(ctx, cfg, rcfg, ociImage, defaultSecretKey, payload)
	case config.KmsSigner:
		return attest.AttestOci(ctx, cfg, rcfg, ociImage, cfg.KmsURL, payload)
	case config.FulcioSigner:
		return attest.AttestOci(ctx, cfg, rcfg, ociImage, "", payload)
	}

	return nil, fmt.Errorf("error occured while attesting")
}
