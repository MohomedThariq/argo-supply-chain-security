package auth

import (
	"context"
	"fmt"
	"io"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"

	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	alibabaacr "github.com/mozillazg/docker-credential-acr-helper/pkg/credhelper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	dockerHubAuthKey  = authn.DefaultAuthKey
	ociSecretSelector = "argo.slsa.io/secret-type=oci"
)

func GetRemoteOptsWithKeychain(ctx context.Context, keychain authn.Keychain) []remote.Option {
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(keychain),
	}

	if puller, err := remote.NewPuller(opts...); err == nil {
		opts = append(opts, remote.Reuse(puller))
	}

	if pusher, err := remote.NewPusher(opts...); err == nil {
		opts = append(opts, remote.Reuse(pusher))
	}

	return opts
}

func GetAuthnKeychain(ctx context.Context, client kubernetes.Interface, namespace string, wf *wfv1alpha1.Workflow) authn.Keychain {
	keyChains := []authn.Keychain{
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
		authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
		authn.NewKeychainFromHelper(alibabaacr.NewACRHelper().WithLoggerOut(io.Discard)),
	}

	if argoKeychain, err := getAuthFromSecrets(ctx, client, []string{namespace, wf.Namespace}); err == nil {
		keyChains = append(keyChains, argoKeychain)
	}

	return authn.NewMultiKeychain(keyChains...)
}

func getAuthFromK8sServiceAccount(ctx context.Context, client kubernetes.Interface, namespace, serviceAccount string) (authn.Keychain, error) {
	return k8schain.New(ctx, client,
		k8schain.Options{
			Namespace:          namespace,
			ServiceAccountName: serviceAccount,
			ImagePullSecrets:   getPullSecrets(ctx, client, namespace, serviceAccount),
			UseMountSecrets:    true,
		},
	)
}

func getAuthFromSecrets(ctx context.Context, client kubernetes.Interface, namespaces []string) (authn.Keychain, error) {
	var secretList []corev1.Secret
	for _, ns := range namespaces {
		secrets, err := getNamespacedSecrets(ctx, client, ns, ociSecretSelector)
		if err == nil {
			secretList = append(secretList, secrets...)
		}
	}

	if len(secretList) == 0 {
		return nil, fmt.Errorf("no secrets with %s label", ociSecretSelector)
	}

	kc, err := kauth.NewFromPullSecrets(ctx, secretList)
	if err != nil {
		return nil, fmt.Errorf("unable to create keychain from secrets")
	}

	return kc, nil
}

func getNamespacedSecrets(ctx context.Context, client kubernetes.Interface, namespace, labelSelector string) ([]corev1.Secret, error) {
	logger := log.FromContext(ctx)

	secrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		err := fmt.Errorf("failed to list secrets in namespace %s: %w", namespace, err)
		logger.Error(err, "unable to get secrets")
		return nil, err
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
