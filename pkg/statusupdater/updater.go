package statusupdater

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func patchMetadata(ctx context.Context, k8sClient client.Client, r client.Object, key string, value string,
	getMetadata func(client.Object) map[string]string,
	setMetadata func(client.Object, map[string]string)) error {

	original, ok := r.DeepCopyObject().(client.Object)
	if !ok {
		return errors.New("unable to convert object to client.Object")
	}

	metadata := getMetadata(r)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	if existing, exists := metadata[key]; exists && existing == value {
		return nil
	}
	metadata[key] = value
	setMetadata(r, metadata)

	patch := client.MergeFrom(original)
	if err := k8sClient.Patch(ctx, r, patch); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return errors.New("conflict or not found")
		}
		return err
	}
	return nil
}

// PatchAnnotations patches a kubernets resourece annotation
func PatchAnnotations(ctx context.Context, k8sClient client.Client, r client.Object, label string, info string) error {
	return patchMetadata(ctx, k8sClient, r, label, info,
		func(obj client.Object) map[string]string { return obj.GetAnnotations() },
		func(obj client.Object, m map[string]string) { obj.SetAnnotations(m) },
	)
}

// PatchLabels patches a kubernetes resource label
func PatchLabels(ctx context.Context, k8sClient client.Client, r client.Object, label string, info string) error {
	return patchMetadata(ctx, k8sClient, r, label, info,
		func(obj client.Object) map[string]string { return obj.GetLabels() },
		func(obj client.Object, m map[string]string) { obj.SetLabels(m) },
	)
}
