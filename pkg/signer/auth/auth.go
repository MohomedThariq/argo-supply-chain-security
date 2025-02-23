package auth

import (
	"context"
	"io"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	alibabaacr "github.com/mozillazg/docker-credential-acr-helper/pkg/credhelper"
	cremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func registryClientOpts(ctx context.Context) ([]cremote.Option, error) {
	opts := []remote.Option{
		remote.WithContext(ctx),
	}

	KubeKeyChain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
		authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
		authn.NewKeychainFromHelper(alibabaacr.NewACRHelper().WithLoggerOut(io.Discard)),
		github.Keychain,
	)
	opts = append(opts, remote.WithAuthFromKeychain(KubeKeyChain))

	// TODO: add auth to grt auth from label selector auths from argo-slsa ns & workflow running ns

	pusher, err := remote.NewPusher(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(pusher))
	}
	puller, err := remote.NewPuller(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(puller))
	}

	return []cremote.Option{cremote.WithRemoteOptions(opts...)}, nil
}
