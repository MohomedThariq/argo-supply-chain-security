package resolveddependencies

import (
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	intoto "github.com/in-toto/attestation/go/v1"
)

func GetResolvedDependencies(wf *wfv1alpha1.Workflow) ([]*intoto.ResourceDescriptor, error) {
	return []*intoto.ResourceDescriptor{}, nil
}
