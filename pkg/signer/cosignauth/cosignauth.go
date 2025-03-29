package cosignauth

import (
	"context"
	"fmt"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/auth"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func CosignRemoteAuthOptsWithKeyChain(ctx context.Context, keychain authn.Keychain) ([]remote.Option, error) {
	opts := auth.GetRemoteOptsWithKeychain(ctx, keychain)

	remoteOpts := []remote.Option{remote.WithRemoteOptions(opts...)}
	if len(remoteOpts) == 0 {
		return nil, fmt.Errorf("no auth mechanisms configured")
	}

	return remoteOpts, nil
}
