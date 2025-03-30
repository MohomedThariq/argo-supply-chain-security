package v1alpha1

import (
	"testing"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	slsav1prov "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConstrunctWorkflowRunDetails(t *testing.T) {
	time := metav1.Now()

	tests := []struct {
		name     string
		wf       *wfv1alpha1.Workflow
		expected *slsav1prov.RunDetails
	}{
		{
			name: "empty workflow",
			wf:   &wfv1alpha1.Workflow{},
			expected: &slsav1prov.RunDetails{
				Builder: &slsav1prov.Builder{
					Id: Wfv1alpha1BuildID,
					Version: map[string]string{
						"argo-workflows": "v3",
					},
				},
				Metadata:   &slsav1prov.BuildMetadata{},
				Byproducts: []*intoto.ResourceDescriptor{},
			},
		},
		{
			name: "workflow with metadata",
			wf: &wfv1alpha1.Workflow{
				Status: wfv1alpha1.WorkflowStatus{
					StartedAt:  time,
					FinishedAt: time,
				},
				ObjectMeta: metav1.ObjectMeta{
					UID: "test-uid",
				},
			},
			expected: &slsav1prov.RunDetails{
				Builder: &slsav1prov.Builder{
					Id: Wfv1alpha1BuildID,
					Version: map[string]string{
						"argo-workflows": "v3",
					},
				},
				Metadata: &slsav1prov.BuildMetadata{
					InvocationId: string("test-uid"),
					StartedOn:    timestamppb.New(time.Time),
					FinishedOn:   timestamppb.New(time.Time),
				},
				Byproducts: []*intoto.ResourceDescriptor{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConstrunctWorkflowRunDetails(tt.wf)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}
