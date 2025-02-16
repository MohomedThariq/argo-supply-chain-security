package config

import "strings"

const (
	signerKey          = "artifacts.signer"
	transparencyKey    = "signer.transparency.enabled"
	transparencyUrlKey = "signer.transparency.url"

	SecretSigner = "cosign"
	KmsSigner    = "kms"
	FulcioSigner = "fulcio"

	defaultTransparencyURL = "https://rekor.sigstore.dev"
)

type Config struct {
	SignerType      string
	Transparency    bool
	TransparencyUrl string
}

func New(configData map[string]string) Config {
	config := new(Config)

	signer, ok := configData[signerKey]
	if !ok {
		signer = SecretSigner
	}
	config.SignerType = signer

	tEnabled := false
	transparency, ok := configData[transparencyKey]
	if ok && strings.ToLower(transparency) == "true" {
		tEnabled = true
	}
	config.Transparency = tEnabled

	transparencyUrl, ok := configData[transparencyUrlKey]
	if !ok {
		transparencyUrl = defaultTransparencyURL
	}
	config.TransparencyUrl = transparencyUrl

	return *config
}
