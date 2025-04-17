package v1alpha1

import (
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/common/byproducts"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/common/metadata"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	slsav1prov "github.com/in-toto/attestation/go/predicates/provenance/v1"
)

const (
	Wfv1alpha1BuildID = "https://argo.slsa.io/argo-workflows/workflow/v1alpha1/l2"
)

func ConstrunctWorkflowRunDetails(wf *wfv1alpha1.Workflow) (*slsav1prov.RunDetails, error) {
	bp, err := byproducts.GetByproducts(wf)
	if err != nil {
		return &slsav1prov.RunDetails{}, err
	}

	return &slsav1prov.RunDetails{
		Builder: &slsav1prov.Builder{
			Id: Wfv1alpha1BuildID,
			Version: map[string]string{
				"argo-workflows": "v3",
			},
		},
		Metadata:   metadata.GetMetadata(wf),
		Byproducts: bp,
	}, nil
}
