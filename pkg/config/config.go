package config

import (
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	signerKey = "artifacts.signer"

	// SecretSigner is the signer type to use cosign key stored in cluster
	SecretSigner = "cosign"
	// KmsSigner is the signer type to use cosign key stored in a key management system
	KmsSigner = "kms"
	// FulcioSigner is the signer type to use keyless signing
	FulcioSigner = "fulcio"

	kmsURLKey = "kms.kmsref"

	transparencyKey        = "signer.transparency.enabled"
	transparencyURLKey     = "signer.transparency.url"
	defaultTransparencyURL = options.DefaultRekorURL

	workloadIdentityKey = "oci.workload.Identity.enabled"
)

// Config contais the configurable info of argo slsa
type Config struct {
	SignerType string

	KmsURL string

	Transparency    bool
	TransparencyURL string
}

// New constructs the Config type using configData
func New(configData map[string]string) Config {
	config := new(Config)

	signer, ok := configData[signerKey]
	if !ok {
		signer = SecretSigner
	}
	config.SignerType = signer

	kmsRef, ok := configData[kmsURLKey]
	if ok {
		config.KmsURL = kmsRef
	}

	if transparency, ok := configData[transparencyKey]; ok && strings.ToLower(transparency) == "true" {
		config.Transparency = true
	} else {
		config.Transparency = false
	}

	if transparencyURL, ok := configData[transparencyURLKey]; ok && transparencyURL != "" {
		config.TransparencyURL = transparencyURL
	} else {
		config.TransparencyURL = defaultTransparencyURL
	}

	return *config
}

// RuntimeConfig contains informatin about te controller runtime
type RuntimeConfig struct {
	InclusterClient kubernetes.Interface
	Namespace       string
	Workflow        *wfv1alpha1.Workflow
	client.Client
}
