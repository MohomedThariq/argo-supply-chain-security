package workflowpodreconciler

import (
	"context"
	"testing"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestHandlePodReconciliation(t *testing.T) {
	tests := []struct {
		name           string
		podStatus      *podStatus
		expectedError  bool
		expectedStatus string
	}{
		{
			name: "Node in error state should mark as skipped",
			podStatus: &podStatus{
				podName: "test-pod",
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-pod",
					},
				},
				status: wfv1alpha1.NodeError,
			},
			expectedError:  false,
			expectedStatus: reconciliationSkipped,
		},
		{
			name: "Pod not in succeeded state should mark as skipped",
			podStatus: &podStatus{
				podName: "test-pod",
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-pod",
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodFailed,
					},
				},
				status: wfv1alpha1.NodeSucceeded,
			},
			expectedError:  false,
			expectedStatus: reconciliationSkipped,
		},
		{
			name: "Happy path with no artifacts should mark as skipped",
			podStatus: &podStatus{
				podName: "test-pod",
				status:  wfv1alpha1.NodeSucceeded,
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-pod",
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodSucceeded,
					},
				},
			},
			expectedError:  false,
			expectedStatus: reconciliationSkipped,
		},
		{
			name: "Happy path with artifacts but no signing should mark as error",
			podStatus: &podStatus{
				podName: "test-pod",
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-pod",
						Annotations: map[string]string{
							artifactsAnnotation: "artifact1",
						},
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodSucceeded,
					},
				},
				status: wfv1alpha1.NodeSucceeded,
			},
			expectedError:  false,
			expectedStatus: reconciliationError,
		},
		{
			name: "Happy path with artifacts and signing should mark as completed",
			podStatus: &podStatus{
				podName: "test-pod",
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-pod",
						Annotations: map[string]string{
							artifactsAnnotation: "artifact1",
							signedAnnotation:    signingCompleted,
						},
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodSucceeded,
					},
				},
				status: wfv1alpha1.NodeSucceeded,
			},
			expectedError:  false,
			expectedStatus: reconciliationCompleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.podStatus.pod).Build()

			runtimrconfig := config.RuntimeConfig{
				Client: fakeClient,
			}

			err := tt.podStatus.handlePodReconciliation(context.Background(), config.Config{}, runtimrconfig)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify pod status annotation
				updatedPod := &corev1.Pod{}
				err = fakeClient.Get(context.Background(), client.ObjectKey{Name: tt.podStatus.pod.Name}, updatedPod)
				assert.NoError(t, err)

				if status, exists := updatedPod.Annotations[podStatusAnnotation]; exists {
					assert.Equal(t, tt.expectedStatus, status)
				}
			}
		})
	}
}
