package annotationUpdater

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const StatusLabel string = "argo.slsa.io/status"

func PatchAnnotations[resource client.Object](ctx context.Context, k8sClient client.Client, r resource, label string, info string) error {
	annotations := r.GetAnnotations()
	annotationInfo, annotationExists := annotations[label]
	if annotationExists && annotationInfo == info {
		return nil
	} else if !annotationExists {
		annotations = make(map[string]string)
	}
	annotations[label] = info
	r.SetAnnotations(annotations)

	patch := []byte(`{"metadata": {"annotations": {"` + label + `": "` + info + `"}}}`)
	if err := k8sClient.Patch(ctx, r, client.RawPatch(types.MergePatchType, patch)); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return errors.New("conflict or not found")
		}
		return err
	}
	return nil
}
