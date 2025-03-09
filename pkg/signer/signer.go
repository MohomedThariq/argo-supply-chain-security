package signer

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/auth"
	icosign "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign"
	ifulcio "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign/fulcio"
	ipayload "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign/payload"
	irekor "github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/internal/pkg/cosign/rekor"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio/fulcioverifier"
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
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

const (
	unsupportedSignerError = "unsupprted signer"
	defaultSecretKey       = "k8s://argo-slsa/signing-secret"
)

var (
	signingSecretPath = ""
)

// SignWithConfigOpts will sign an oci with user defined configurations
func SignWithConfigOpts(ctx context.Context, ociImage string, cfg config.Config, rcfg config.RuntimeConfig) error {
	switch cfg.SignerType {
	case config.SecretSigner:
		return signOci(ociImage, defaultSecretKey, cfg, rcfg)
	case config.KmsSigner:
		return signOci(ociImage, cfg.KmsURL, cfg, rcfg)
	case config.FulcioSigner:
		return signOci(ociImage, "", cfg, rcfg)
	}

	return fmt.Errorf("error occured while signing")
}

func signOci(ociImage, keyRef string, cfg config.Config, rcfg config.RuntimeConfig) (err error) {
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

	ctx := context.Background()
	sv, err := signerFromKeyOpts(ctx, ko, false)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	dd := cremote.NewDupeDetector(sv)

	// Get registry auth options
	opts, err := auth.RegistryClientOptsWithK8s(ctx, rcfg.InclusterClient, rcfg.Namespace, rcfg.Workflow)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	// singning start
	ref, err := name.ParseReference(ociImage)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}
	digest, ok := ref.(name.Digest)
	if !ok {
		return fmt.Errorf("digest not awailable in oci ref")
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

func signerFromKeyOpts(ctx context.Context, ko options.KeyOpts, getKmsSigner bool) (sv *sign.SignerVerifier, err error) {
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
