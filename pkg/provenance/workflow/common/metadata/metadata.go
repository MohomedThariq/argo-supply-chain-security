package metadata

import (
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	slsav1prov "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func GetMetadata(wf *wfv1alpha1.Workflow) *slsav1prov.BuildMetadata {
	var startedOn *timestamppb.Timestamp
	var finishedOn *timestamppb.Timestamp
	wfStartTime := wf.Status.StartedAt
	wfCompletitionTime := wf.Status.FinishedAt

	if !wfStartTime.IsZero() {
		startedOn = timestamppb.New(wfStartTime.Time)
	}

	if !wfCompletitionTime.IsZero() {
		finishedOn = timestamppb.New(wfCompletitionTime.Time)
	}

	return &slsav1prov.BuildMetadata{
		InvocationId: string(wf.GetUID()),
		StartedOn:    startedOn,
		FinishedOn:   finishedOn,
	}
}
