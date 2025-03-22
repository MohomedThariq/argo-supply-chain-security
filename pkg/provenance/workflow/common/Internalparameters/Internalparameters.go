package internalparameters

import (
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
)

func GetInternalParams(wf *wfv1alpha1.Workflow) map[string]any {
	internalParams := make(map[string]any)

	internalParams["labels"] = removeArgoSlsaInfo(wf.GetLabels())
	internalParams["annotations"] = removeArgoSlsaInfo(wf.GetAnnotations())

	return internalParams
}

func removeArgoSlsaInfo(annotations map[string]string) map[string]string {
	for key := range annotations {
		if strings.HasPrefix(key, "argo.slsa.io/") && key != "argo.slsa.io/enable" {
			delete(annotations, key)
		}
	}
	return annotations
}
