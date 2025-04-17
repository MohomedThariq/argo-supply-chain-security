package crane

import (
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
)

func GetManifest(keychain authn.Keychain, oci string) ([]byte, error) {
	return crane.Manifest(oci, crane.WithAuthFromKeychain(keychain))
}
