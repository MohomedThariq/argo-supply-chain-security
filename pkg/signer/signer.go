package signer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
)

const (
	unsupportedSignerError = "unsupprted signer"
)

var (
	signingSecretPath = ""
)

func ConstructSigner(ctx context.Context, cfg config.Config) (signature.SignerVerifier, error) {
	switch cfg.SignerType {
	case config.SecretSigner:
		return cosignSigner(signingSecretPath)
	case config.KmsSigner:
	case config.FulcioSigner:
		// Signer(ctx, signingSecretPath, true)
	}

	return nil, errors.New(unsupportedSignerError)
}

func cosignSigner(secretPath string) (signature.SignerVerifier, error) {
	privateKeyPath := filepath.Join(secretPath, "cosign.key")
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading cosign.key file: %w", err)
	}

	passwordPath := filepath.Join(secretPath, "cosign.password")
	password, err := os.ReadFile(passwordPath)
	if err != nil {
		return nil, fmt.Errorf("error reading cosign.password file: %w", err)
	}

	signer, err := cosign.LoadPrivateKey(privateKey, password)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// func fulcioSigner(ctx context.Context) (signature.SignerVerifier, error) {
// 	providersEnabled := providers.Enabled(ctx)
// }
