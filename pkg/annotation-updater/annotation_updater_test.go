package annotationUpdater

import (
	"context"
	"testing"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPatchAnnotations(t *testing.T) {
	tests := []struct {
		name            string
		resource        client.Object
		label           string
		info            string
		expectedError   error
		isPatched       bool
		wantAnnotations map[string]string
	}{
		{
			name: "No existing annotations in Workflow",
			resource: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
				},
			},
			label:         "example.com/key",
			info:          "value",
			expectedError: nil,
			isPatched:     true,
			wantAnnotations: map[string]string{
				"example.com/key": "value",
			},
		},
		{
			name: "No existing annotations in Pod",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
			},
			label:         "example.com/key",
			info:          "value",
			expectedError: nil,
			isPatched:     true,
			wantAnnotations: map[string]string{
				"example.com/key": "value",
			},
		},
		{
			name: "annotation exists with same value in Workflow",
			resource: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
					Annotations: map[string]string{
						"example.com/key": "value",
					},
				},
			},
			label:         "example.com/key",
			info:          "value",
			expectedError: nil,
			isPatched:     true,
			wantAnnotations: map[string]string{
				"example.com/key": "value",
			},
		},
		{
			name: "annotation exists with same value in Pod",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"example.com/key": "value",
					},
				},
			},
			label:         "example.com/key",
			info:          "value",
			expectedError: nil,
			isPatched:     true,
			wantAnnotations: map[string]string{
				"example.com/key": "value",
			},
		},
		{
			name: "annotation exists with different value in Workflow",
			resource: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
					Annotations: map[string]string{
						"example.com/key": "old-value",
					},
				},
			},
			label:         "example.com/key",
			info:          "new-value",
			expectedError: nil,
			isPatched:     true,
			wantAnnotations: map[string]string{
				"example.com/key": "new-value",
			},
		},
		{
			name: "annotation exists with different value in Pod",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"example.com/key": "old-value",
					},
				},
			},
			label:         "example.com/key",
			info:          "new-value",
			expectedError: nil,
			isPatched:     true,
			wantAnnotations: map[string]string{
				"example.com/key": "new-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = wfv1alpha1.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)

			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.resource).Build()

			err := PatchAnnotations(context.Background(), fakeClient, tt.resource, tt.label, tt.info)
			assert.Equal(t, tt.expectedError, err, "Unexpected error for test case: %s", tt.name)

			if tt.isPatched {
				assert.Equal(t, tt.wantAnnotations, tt.resource.GetAnnotations(), "Annotation mismatch for test case: %s", tt.name)
			}
		})
	}
}
