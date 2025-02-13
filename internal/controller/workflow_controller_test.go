/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"testing"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconciler_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wfv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme) // Add corev1 to scheme

	// Mock getCurrentNamespace function
	originalGetCurrentNamespace := getCurrentNamespaceFunc
	getCurrentNamespaceFunc = func() (string, error) {
		return "default", nil
	}
	defer func() {
		getCurrentNamespaceFunc = originalGetCurrentNamespace
	}()

	tests := []struct {
		name        string
		workflow    *wfv1alpha1.Workflow
		configMap   *corev1.ConfigMap
		wantErr     bool
		wantRequeue bool
	}{
		{
			name:     "Workflow not found",
			workflow: nil,
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: "default",
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "Workflow with feature enabled",
			workflow: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
					Labels: map[string]string{
						enableLabel: featureEnabled,
					},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: "default",
				},
			},
			wantErr:     false,
			wantRequeue: true,
		},
		{
			name: "Workflow with feature disabled",
			workflow: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
					Labels: map[string]string{
						enableLabel: "false",
					},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: "default",
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "Workflow with status completed",
			workflow: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
					Labels: map[string]string{
						enableLabel:         featureEnabled,
						workflowStatusLabel: reconcileCompleted,
					},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: "default",
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "Workflow with status error",
			workflow: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
					Labels: map[string]string{
						enableLabel:         featureEnabled,
						workflowStatusLabel: reconcileError,
					},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: "default",
				},
			},
			wantErr:     false,
			wantRequeue: false,
		},
		{
			name: "Workflow with missing configmap",
			workflow: &wfv1alpha1.Workflow{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-workflow",
					Namespace: "default",
					Labels: map[string]string{
						enableLabel: featureEnabled,
					},
				},
			},
			configMap:   nil,
			wantErr:     true,
			wantRequeue: false,
		},
		// {
		// 	name: "Workflow with patch label error",
		// 	workflow: &wfv1alpha1.Workflow{
		// 		ObjectMeta: metav1.ObjectMeta{
		// 			Name:      "test-workflow",
		// 			Namespace: "default",
		// 			Labels: map[string]string{
		// 				enableLabel: featureEnabled,
		// 			},
		// 		},
		// 	},
		// 	configMap: &corev1.ConfigMap{
		// 		ObjectMeta: metav1.ObjectMeta{
		// 			Name:      configMapName,
		// 			Namespace: "default",
		// 		},
		// 	},
		// 	wantErr:     true,
		// 	wantRequeue: false,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			r := &Reconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			if tt.workflow != nil {
				_ = fakeClient.Create(context.Background(), tt.workflow)
			}

			if tt.configMap != nil {
				_ = fakeClient.Create(context.Background(), tt.configMap)
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-workflow",
					Namespace: "default",
				},
			}

			result, err := r.Reconcile(context.Background(), req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantRequeue, result.Requeue || result.RequeueAfter > 0)
		})
	}
}
