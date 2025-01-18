package annotationUpdater

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func PatchAnnotations(ctx context.Context, k8sClient client.Client, r client.Object, label string, info string) error {
	original, ok := r.DeepCopyObject().(client.Object)
	if !ok {
		return errors.New("unable to convert object to client.Object")
	}

	annotations := r.GetAnnotations()
	annotationInfo, annotationExists := annotations[label]
	if annotationExists && annotationInfo == info {
		return nil
	} else if !annotationExists {
		annotations = make(map[string]string)
	}
	annotations[label] = info
	r.SetAnnotations(annotations)

	patch := client.MergeFrom(original)
	if err := k8sClient.Patch(ctx, r, patch); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return errors.New("conflict or not found")
		}
		return err
	}
	return nil
}
