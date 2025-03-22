package externalparameters

import wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"

func GetExternalParams(wf *wfv1alpha1.Workflow) map[string]any {
	externalParams := make(map[string]any)

	for _, param := range wf.Spec.Arguments.Parameters {
		externalParams[param.Name] = param.Value
	}
	externalParams["runSpec"] = wf.Spec

	return externalParams
}
