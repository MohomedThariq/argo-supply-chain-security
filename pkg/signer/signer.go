package signer

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio/fulcioverifier"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	// "github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
)

const (
	unsupportedSignerError = "unsupprted signer"
)

var (
	signingSecretPath = ""
)

// func ConstructSigner(ctx context.Context, cfg config.Config) (signature.SignerVerifier, error) {
// 	switch cfg.SignerType {
// 	case config.SecretSigner:
// 		return cosignSigner(signingSecretPath)
// 	case config.KmsSigner:
// 	case config.FulcioSigner:
// 		// Signer(ctx, signingSecretPath, true)
// 	}

// 	return nil, errors.New(unsupportedSignerError)
// }

// func cosignSigner(secretPath string) (signature.SignerVerifier, error) {
// 	privateKeyPath := filepath.Join(secretPath, "cosign.key")
// 	privateKey, err := os.ReadFile(privateKeyPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("error reading cosign.key file: %w", err)
// 	}

// 	passwordPath := filepath.Join(secretPath, "cosign.password")
// 	password, err := os.ReadFile(passwordPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("error reading cosign.password file: %w", err)
// 	}

// 	signer, err := cosign.LoadPrivateKey(privateKey, password)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return signer, nil
// }

// func fulcioSigner(ctx context.Context) (signature.SignerVerifier, error) {
// 	providersEnabled := providers.Enabled(ctx)
// }

// func cosignMock() error {
// 	o := &options.SignOptions{}
// 	// 1. clientSecretFile - passed with oidc-client-secret-file flag if
// 	oidcClientSecret, err := o.OIDC.ClientSecret()
// 	if err != nil {
// 		return err
// 	}
// 	ko := options.KeyOpts{
// 		KeyRef:                         o.Key,
// 		PassFunc:                       generate.GetPass,
// 		Sk:                             o.SecurityKey.Use,
// 		Slot:                           o.SecurityKey.Slot,
// 		FulcioURL:                      o.Fulcio.URL,
// 		IDToken:                        o.Fulcio.IdentityToken,
// 		FulcioAuthFlow:                 o.Fulcio.AuthFlow,
// 		InsecureSkipFulcioVerify:       o.Fulcio.InsecureSkipFulcioVerify,
// 		RekorURL:                       o.Rekor.URL,
// 		OIDCIssuer:                     o.OIDC.Issuer,
// 		OIDCClientID:                   o.OIDC.ClientID,
// 		OIDCClientSecret:               oidcClientSecret,
// 		OIDCRedirectURL:                o.OIDC.RedirectURL,
// 		OIDCDisableProviders:           o.OIDC.DisableAmbientProviders,
// 		OIDCProvider:                   o.OIDC.Provider,
// 		SkipConfirmation:               o.SkipConfirmation,
// 		TSAClientCACert:                o.TSAClientCACert,
// 		TSAClientCert:                  o.TSAClientCert,
// 		TSAClientKey:                   o.TSAClientKey,
// 		TSAServerName:                  o.TSAServerName,
// 		TSAServerURL:                   o.TSAServerURL,
// 		IssueCertificateForExistingKey: o.IssueCertificate,
// 	}

// 	return nil
// }

func Sign() (err error) {
	o := &options.SignOptions{}
	oidcClientSecret := "" // default
	ko := options.KeyOpts{
		KeyRef:                         o.Key, // cosign pvt key path
		PassFunc:                       generate.GetPass,
		FulcioURL:                      o.Fulcio.URL,
		IDToken:                        o.Fulcio.IdentityToken,
		FulcioAuthFlow:                 o.Fulcio.AuthFlow,
		InsecureSkipFulcioVerify:       o.Fulcio.InsecureSkipFulcioVerify,
		RekorURL:                       o.Rekor.URL,
		OIDCIssuer:                     o.OIDC.Issuer,
		OIDCClientID:                   o.OIDC.ClientID,
		OIDCClientSecret:               oidcClientSecret,
		OIDCRedirectURL:                o.OIDC.RedirectURL,
		OIDCDisableProviders:           o.OIDC.DisableAmbientProviders,
		OIDCProvider:                   o.OIDC.Provider,
		SkipConfirmation:               o.SkipConfirmation,
		TSAClientCACert:                o.TSAClientCACert,
		TSAClientCert:                  o.TSAClientCert,
		TSAClientKey:                   o.TSAClientKey,
		TSAServerName:                  o.TSAServerName,
		TSAServerURL:                   o.TSAServerURL,
		IssueCertificateForExistingKey: o.IssueCertificate,
	}
	ctx := context.Background()
	sv, err := SignerFromKeyOpts(ctx, ko, false) // sign verifier
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	dd := cremote.NewDupeDetector(sv)

	var staticPayload []byte
	if o.PayloadPath != "" {
		staticPayload, err = os.ReadFile(filepath.Clean(o.PayloadPath))
		if err != nil {
			return fmt.Errorf("payload from file: %w", err)
		}
	}

	regOpts := o.Registry
	opts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	return nil
}

func SignerFromKeyOpts(ctx context.Context, ko options.KeyOpts, getKmsSigner bool) (sv *sign.SignerVerifier, err error) {
	if ko.KeyRef != "" {
		sv, err = signerFromKeyRef(ctx, ko.KeyRef, getKmsSigner)
		if err != nil {
			return nil, fmt.Errorf("failed to createte keyed signer %w", err)
		}
		return sv, nil
	}

	sv, err = signerFromNewKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemaral keys %w", err)
	}
	return keylessSigner(ctx, ko, sv)
}

func signerFromKeyRef(ctx context.Context, keyRef string, getKmsSigner bool) (*sign.SignerVerifier, error) {
	var (
		k   signature.SignerVerifier
		err error
	)

	if !getKmsSigner {
		k, err = cosignSeecretSigner(ctx, keyRef)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer from secret %w", err)
		}
	} else {
		k, err = kmsSigner(ctx, keyRef)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer from kms  %w", err)
		}
	}

	certSigner := &sign.SignerVerifier{
		SignerVerifier: k,
	}

	// is this needed?
	if pkcs11Key, ok := k.(*pkcs11key.Key); ok {
		certFromPKCS11, _ := pkcs11Key.Certificate()
		// certSigner.close = pkcs11Key.Close

		if certFromPKCS11 == nil {
			fmt.Println(ctx, "no x509 certificate retrieved from the PKCS11 token")
		} else {
			pemBytes, err := cryptoutils.MarshalCertificateToPEM(certFromPKCS11)
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			// Check that the provided public key and certificate key match
			pubKey, err := k.PublicKey()
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			if cryptoutils.EqualKeys(pubKey, certFromPKCS11.PublicKey) != nil {
				pkcs11Key.Close()
				return nil, errors.New("pkcs11 key and certificate do not match")
			}
			certSigner.Cert = pemBytes
		}
	}

	if certSigner.Cert == nil {
		return nil, errors.New("no leaf certificate found or provided while specifying chain")
	}

	return certSigner, nil
}

const (
	cosignKey     = "cosign.key"
	cosignPassKey = "cosign.password"
)

func cosignSeecretSigner(ctx context.Context, keyRef string) (signature.SignerVerifier, error) {
	s, err := kubernetes.GetKeyPairSecret(ctx, keyRef)
	if err != nil {
		return nil, err
	}

	if len(s.Data) == 0 {
		return nil, fmt.Errorf("no data available in secret: %s", s.Name)
	}

	key, ok := s.Data[cosignKey]
	if !ok {
		return nil, fmt.Errorf("no data with %s in secret: %s", cosignKey, s.Name)
	}

	passKey, ok := s.Data[cosignPassKey]
	if !ok {
		return nil, fmt.Errorf("no data with %s in secret: %s", cosignPassKey, s.Name)
	}

	return cosign.LoadPrivateKey(key, passKey)
}

func kmsSigner(ctx context.Context, keyRef string) (signature.SignerVerifier, error) {
	sv, err := kms.Get(ctx, keyRef, crypto.SHA256)
	if err != nil {
		var e *kms.ProviderNotFoundError
		if !errors.As(err, &e) {
			return nil, err
		}
	}

	return sv, nil
}

func signerFromNewKey() (*sign.SignerVerifier, error) {
	privKey, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &sign.SignerVerifier{
		SignerVerifier: sv,
	}, nil
}

func keylessSigner(ctx context.Context, ko options.KeyOpts, sv *sign.SignerVerifier) (*sign.SignerVerifier, error) {
	var (
		k   *fulcio.Signer
		err error
	)

	if k, err = fulcioverifier.NewSigner(ctx, ko, sv); err != nil {
		return nil, fmt.Errorf("getting key from Fulcio: %w", err)
	}

	return &sign.SignerVerifier{
		Cert:           k.Cert,
		Chain:          k.Chain,
		SignerVerifier: k,
	}, nil
}
