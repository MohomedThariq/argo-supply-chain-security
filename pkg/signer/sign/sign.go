package sign

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/cosignauth"
	icosign "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign"
	ifulcio "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign/fulcio"
	ipayload "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign/payload"
	irekor "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign/rekor"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/kubernetes"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	signingSecretPath = ""
)

func SignOci(ociImage, keyRef string, ctx context.Context, cfg config.Config) (err error) {
	o := &options.SignOptions{
		Key:        keyRef,
		TlogUpload: cfg.Transparency,
		Rekor: options.RekorOptions{
			URL: cfg.TransparencyURL,
		},
	}
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

	sv, err := SignerFromKeyOpts(ctx, ko, false)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	dd := cremote.NewDupeDetector(sv)

	// Get registry auth options
	opts, err := cosignauth.CosignRemoteAuthOptsWithKeyChain(ctx, cfg.AuthKeyChain)
	if err != nil {
		return fmt.Errorf("constructing oci client options: %w", err)
	}

	// singning start
	ref, err := name.ParseReference(ociImage)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}
	digest, ok := ref.(name.Digest)
	if !ok {
		return fmt.Errorf("digest not available in oci ref")
	}

	se, err := ociremote.SignedEntity(ref, opts...)
	if _, isEntityNotFoundErr := err.(*ociremote.EntityNotFoundError); isEntityNotFoundErr {
		se = ociremote.SignedUnknown(digest)
	} else if err != nil {
		return fmt.Errorf("accessing image: %w", err)
	}

	err = signDigest(ctx, digest, ko, *o, nil, dd, sv, se, opts)
	if err != nil {
		return fmt.Errorf("signing digest: %w", err)
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

	return keylessSigner(ctx)
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

var (
	identityTokenFilPath = "/var/run/sigstore/cosign"
)

const (
	customTokenPathProvider = "filesystem-custom-path"
	defaultOIDCClientID     = "sigstore"
	defaultFulcioAddress    = "https://fulcio.sigstore.dev"
	defaultOIDCIssuer       = "https://oauth2.sigstore.dev/auth"
)

func keylessSigner(ctx context.Context) (*sign.SignerVerifier, error) {
	logger := log.FromContext(ctx)

	providersEnabled := providers.Enabled(ctx)
	if identityTokenFilPath != "" {
		providersEnabled = true
	}
	if !providersEnabled {
		return nil, fmt.Errorf("no auth provider for fulcio is enabled")
	}

	var token string
	var err error
	logger.Info("Attempting to get id token from provider")
	token, err = providers.Provide(ctx, defaultOIDCClientID)
	if err != nil {
		return nil, fmt.Errorf("getting token from provider: %w", err)
	}

	logger.Info("Signing with fulcio ...")
	privetKey, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("error generating keypair: %w", err)
	}
	signer, err := signature.LoadECDSASignerVerifier(privetKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("error loading sigstore signer: %w", err)
	}
	k, err := fulcio.NewSigner(ctx, options.KeyOpts{
		FulcioURL:    defaultFulcioAddress,
		IDToken:      token,
		OIDCIssuer:   defaultOIDCIssuer,
		OIDCClientID: defaultOIDCClientID,
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("getting Fulcio signer: %w", err)
	}

	return &sign.SignerVerifier{
		SignerVerifier: signer,
		Cert:           k.Cert,
		Chain:          k.Chain,
	}, nil
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

// func keylessSigner(ctx context.Context, ko options.KeyOpts, sv *sign.SignerVerifier) (*sign.SignerVerifier, error) {
// 	var (
// 		k   *fulcio.Signer
// 		err error
// 	)

// 	if k, err = fulcioverifier.NewSigner(ctx, ko, sv); err != nil {
// 		return nil, fmt.Errorf("getting key from Fulcio: %w", err)
// 	}

// 	return &sign.SignerVerifier{
// 		Cert:           k.Cert,
// 		Chain:          k.Chain,
// 		SignerVerifier: k,
// 	}, nil
// }

func signDigest(ctx context.Context, digest name.Digest, ko options.KeyOpts, signOpts options.SignOptions,
	annotations map[string]interface{},
	dd mutate.DupeDetector, sv *sign.SignerVerifier, se oci.SignedEntity, remoteOptions []ociremote.Option) error {
	var err error

	payload, err := (&sigPayload.Cosign{
		Image:           digest,
		ClaimedIdentity: signOpts.SignContainerIdentity,
		Annotations:     annotations,
	}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}

	var s icosign.Signer
	s = ipayload.NewSigner(sv)
	if sv.Cert != nil {
		s = ifulcio.NewSigner(s, sv.Cert, sv.Chain)
	}

	if signOpts.TlogUpload {
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}
		s = irekor.NewSigner(s, rClient)
	}

	ociSig, _, err := s.Sign(ctx, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, ociSig, mutate.WithDupeDetector(dd), mutate.WithRecordCreationTimestamp(signOpts.RecordCreationTimestamp))
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	return ociremote.WriteSignatures(digest.Repository, newSE, remoteOptions...)
}
