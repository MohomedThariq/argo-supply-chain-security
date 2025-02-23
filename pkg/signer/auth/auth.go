package auth

import (
	"context"
	"fmt"
	"io"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	alibabaacr "github.com/mozillazg/docker-credential-acr-helper/pkg/credhelper"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func RegistryClientOpts(ctx context.Context) ([]ociremote.Option, error) {
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

	return []ociremote.Option{ociremote.WithRemoteOptions(opts...)}, nil
}

func RegistryClientOptsWithK8s(ctx context.Context, client kubernetes.Interface, namespace string, wf *wfv1alpha1.Workflow) ([]ociremote.Option, error) {
	opts := []remote.Option{
		remote.WithContext(ctx),
	}

	if kubeKeyChain, err := k8schain.New(ctx, client,
		k8schain.Options{
			Namespace:          wf.Namespace,
			ServiceAccountName: wf.Spec.ServiceAccountName,
			ImagePullSecrets:   getPullSecrets(ctx, client, wf.Namespace, wf.Spec.ServiceAccountName),
			UseMountSecrets:    true,
		},
	); err == nil {
		opts = append(opts, remote.WithAuthFromKeychain(kubeKeyChain))
	}

	if argoKeychain, err := getAuthFromSecrets(ctx, client, namespace, wf); err == nil {
		opts = append(opts, remote.WithAuthFromKeychain(argoKeychain))
	}

	authKeyChain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
		authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
		authn.NewKeychainFromHelper(alibabaacr.NewACRHelper().WithLoggerOut(io.Discard)),
		github.Keychain,
	)
	opts = append(opts, remote.WithAuthFromKeychain(authKeyChain))

	// TODO: add auth to grt auth from label selector auths from argo-slsa ns & workflow running ns

	if pusher, err := remote.NewPusher(opts...); err == nil {
		opts = append(opts, remote.Reuse(pusher))
	}
	if puller, err := remote.NewPuller(opts...); err == nil {
		opts = append(opts, remote.Reuse(puller))
	}

	remoteOpts := []ociremote.Option{ociremote.WithRemoteOptions(opts...)}
	if len(remoteOpts) == 0 {
		return nil, fmt.Errorf("no authmechanisms configured")
	}

	return remoteOpts, nil
}

const (
	ociSecretSelector = "argo.slsa.io/secret-type=oci"
)

func getAuthFromSecrets(ctx context.Context, client kubernetes.Interface, namespace string, wf *wfv1alpha1.Workflow) (authn.Keychain, error) {
	var secretList []corev1.Secret
	secrets, err := getNamespacedSecrets(ctx, client, namespace, ociSecretSelector)
	if err == nil {
		secretList = append(secretList, secrets...)
	}
	secrets, err = getNamespacedSecrets(ctx, client, wf.Namespace, ociSecretSelector)
	if err == nil {
		secretList = append(secretList, secrets...)
	}

	if len(secretList) == 0 {
		return nil, fmt.Errorf("no secrets with %s label", ociSecretSelector)
	}

	kc, err := k8schain.NewFromPullSecrets(ctx, secretList)
	if err != nil {
		return nil, fmt.Errorf("unable to create keychain from secrets")
	}

	return kc, nil
}

func getNamespacedSecrets(ctx context.Context, client kubernetes.Interface, namespace, labelSelector string) ([]corev1.Secret, error) {
	secrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets in namespace %s: %w", namespace, err)
	}

	return secrets.Items, nil
}

func getPullSecrets(ctx context.Context, client kubernetes.Interface, namespace, serviceAccount string) []string {
	sa, err := client.CoreV1().ServiceAccounts(namespace).Get(ctx, serviceAccount, metav1.GetOptions{})
	if err != nil {
		return nil
	}

	var secrets []string
	for _, secret := range sa.ImagePullSecrets {
		secrets = append(secrets, secret.Name)
	}

	return secrets
}
