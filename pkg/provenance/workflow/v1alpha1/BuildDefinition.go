package v1alpha1

import (
	internalparameters "github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/common/Internalparameters"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/common/buildtype"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/common/externalparameters"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/common/proto"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/common/resolveddependencies"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	slsav1prov "github.com/in-toto/attestation/go/predicates/provenance/v1"
)

func ConstrunctWorkflowBuildDefinition(wf *wfv1alpha1.Workflow) (*slsav1prov.BuildDefinition, error) {
	buildDefinitionType := buildtype.Wfv1alpha1BuildType

	internalParams := internalparameters.GetInternalParams(wf)
	protoInternalParams, err := proto.GetAnyProtoStruct(internalParams)
	if err != nil {
		return &slsav1prov.BuildDefinition{}, err
	}

	externalParams := externalparameters.GetExternalParams(wf)
	protoExternalParams, err := proto.GetAnyProtoStruct(externalParams)
	if err != nil {
		return &slsav1prov.BuildDefinition{}, err
	}

	resolvedDeps, err := resolveddependencies.GetResolvedDependencies(wf)
	if err != nil {
		return &slsav1prov.BuildDefinition{}, err
	}

	return &slsav1prov.BuildDefinition{
		BuildType:            buildDefinitionType,
		ExternalParameters:   protoExternalParams,
		InternalParameters:   protoInternalParams,
		ResolvedDependencies: resolvedDeps,
	}, nil
}
