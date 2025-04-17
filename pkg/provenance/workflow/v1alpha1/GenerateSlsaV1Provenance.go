package v1alpha1

import (
	"google.golang.org/protobuf/encoding/protojson"

	slsav1 "github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/slsa/v1"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	intoto "github.com/in-toto/attestation/go/v1"
)

func GenerateSlsaV1Provenance(wf *wfv1alpha1.Workflow, sub []*intoto.ResourceDescriptor) ([]byte, error) {
	// Generate RunDetails
	runDetails, err := ConstrunctWorkflowRunDetails(wf)
	if err != nil {
		return nil, err
	}

	// Generate BuildDefinition
	buildDefinition, err := ConstrunctWorkflowBuildDefinition(wf)
	if err != nil {
		return nil, err
	}

	// Generate Provenance
	provenance, err := slsav1.GenerateProvenance(buildDefinition, runDetails, sub)
	if err != nil {
		return nil, err
	}

	return protojson.Marshal(&provenance)
}
