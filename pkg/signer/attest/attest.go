package attest

import (
	"bytes"
	"context"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/cosignauth"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/sign"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	csign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func AttestOci(ctx context.Context, cfg config.Config, ociImage, keyRef, payloadType string, payload []byte) (attestInfo []any, err error) {
	o := &options.AttestOptions{
		Key:            keyRef,
		RekorEntryType: "dsse",
		TlogUpload:     cfg.Transparency,
		Rekor: options.RekorOptions{
			URL: cfg.TransparencyURL,
		},
		Predicate: options.PredicateLocalOptions{
			PredicateOptions: options.PredicateOptions{
				Type: payloadType,
			},
		},
	}
	oidcClientSecret := "" // default
	ko := options.KeyOpts{
		KeyRef:                   o.Key,
		PassFunc:                 generate.GetPass,
		Sk:                       o.SecurityKey.Use,
		Slot:                     o.SecurityKey.Slot,
		FulcioURL:                o.Fulcio.URL,
		IDToken:                  o.Fulcio.IdentityToken,
		FulcioAuthFlow:           o.Fulcio.AuthFlow,
		InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
		RekorURL:                 o.Rekor.URL,
		OIDCIssuer:               o.OIDC.Issuer,
		OIDCClientID:             o.OIDC.ClientID,
		OIDCClientSecret:         oidcClientSecret,
		OIDCRedirectURL:          o.OIDC.RedirectURL,
		OIDCProvider:             o.OIDC.Provider,
		SkipConfirmation:         o.SkipConfirmation,
		TSAServerURL:             o.TSAServerURL,
	}
	c := attest.AttestCommand{
		KeyOpts:                 ko,
		RegistryOptions:         o.Registry,
		CertPath:                o.Cert,
		CertChainPath:           o.CertChain,
		NoUpload:                o.NoUpload,
		PredicateType:           o.Predicate.PredicateOptions.Type,
		Replace:                 o.Replace,
		TlogUpload:              o.TlogUpload,
		RekorEntryType:          o.RekorEntryType,
		RecordCreationTimestamp: o.RecordCreationTimestamp,
	}

	attestInfo = append(attestInfo, "reference", ociImage)
	attestInfo = append(attestInfo, "predicate type", c.PredicateType)

	ref, err := name.ParseReference(ociImage)
	if err != nil {
		return nil, fmt.Errorf("parsing reference: %w", err)
	}
	digest, ok := ref.(name.Digest)
	if !ok {
		return nil, fmt.Errorf("digest not awailable in oci ref")
	}

	ociremoteOpts, err := cosignauth.CosignRemoteAuthOptsWithKeyChain(ctx, cfg.AuthKeyChain)
	if err != nil {
		return nil, fmt.Errorf("constructing oci client options: %w", err)
	}

	sv, err := sign.SignerFromKeyOpts(ctx, ko, false)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	dd := cremote.NewDupeDetector(sv)

	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	predicateType, err := options.ParsePredicateType(c.PredicateType)
	if err != nil {
		return nil, err
	}

	predicateTypeAnnotation := map[string]string{
		"predicateType": predicateType,
	}
	opts = append(opts, static.WithAnnotations(predicateTypeAnnotation))

	if c.TlogUpload {
		bundle, index, err := uploadToTlog(ctx, sv, c.RekorURL, func(r *rclient.Rekor, b []byte) (*models.LogEntryAnon, error) {
			return cosign.TLogUploadDSSEEnvelope(ctx, r, signedPayload, b)
		})
		if err != nil {
			return nil, err
		}
		opts = append(opts, static.WithBundle(bundle))
		attestInfo = append(attestInfo, "tlog uploaded to", c.RekorURL)
		attestInfo = append(attestInfo, "tlog entry created with index", fmt.Sprintf("%d", *index))
	}

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return nil, err
	}
	se := ociremote.SignedUnknown(digest, ociremoteOpts...)

	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
		mutate.WithRecordCreationTimestamp(c.RecordCreationTimestamp),
	}

	// Attach the attestation to the entity.
	newSE, err := mutate.AttachAttestationToEntity(se, sig, signOpts...)
	if err != nil {
		return nil, err
	}

	// Publish the attestations associated with this entity
	return attestInfo, ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
}

type tlogUploadFn func(*rclient.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(ctx context.Context, sv *csign.SignerVerifier, rekorURL string, upload tlogUploadFn) (*cbundle.RekorBundle, *int64, error) {
	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return nil, nil, err
	}

	rekorClient, err := rekor.NewClient(rekorURL)
	if err != nil {
		return nil, nil, err
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, nil, err
	}
	return cbundle.EntryToBundle(entry), entry.LogIndex, nil
}
