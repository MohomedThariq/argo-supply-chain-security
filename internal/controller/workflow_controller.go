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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// WorkflowReconciler reconciles a Workflow object
type WorkflowReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Supply chain security annotations & labels const
const (
	enableAnnotation string = "argo.slsa.io/enable"
	statusLabel      string = "argo.slsa.io/status"
)

//+kubebuilder:rbac:groups=argoproj.io,resources=workflows,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list
//+kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list;watch;update;patch

// update current status in workflow
func updateWFStatus(r *WorkflowReconciler, ctx context.Context, wf *wfv1alpha1.Workflow, label string, status string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if wf.Labels == nil {
		wf.Labels = make(map[string]string)
	} else if wf.Labels[label] == status {
		// ignore update if status is same
		return ctrl.Result{}, nil
	}
	wf.Labels[label] = status
	if err := r.Update(ctx, wf); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		logger.Error(err, "unable to update workflow status")
		return ctrl.Result{}, err
	}
	logger.Info("Workflow status updated", "status", status)
	return ctrl.Result{}, nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *WorkflowReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// get workflow resource
	var workflow wfv1alpha1.Workflow
	if err := r.Get(ctx, req.NamespacedName, &workflow); err != nil {
		if apierrors.IsNotFound(err) {
			// ignoring not-found errors, since we can get them on deleted requests.
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to fetch Workflow")
		return ctrl.Result{}, err
	}

	// if workflow is still running requeue
	// FIX_ME: this should not be done. should reconcile while running as well
	if workflow.Status.Phase != "Succeeded" && workflow.Status.Phase != "Failed" {
		return ctrl.Result{Requeue: true}, nil
	}

	// start securing the supply chain if enabled
	isEnabled := workflow.Annotations[enableAnnotation] == "true"
	status, labelIsPresent := workflow.Labels[statusLabel]

	// check if enabled & start securing the supply chain
	if isEnabled {
		if !labelIsPresent {
			return updateWFStatus(r, ctx, &workflow, statusLabel, "in-progress")
		} else if status == "completed" || status == "error" {
			// process is already completed or failed
			return ctrl.Result{}, nil
		}
	} else {
		logger.Info("Not enabled ignoring workflow")
		return ctrl.Result{}, nil
	}

	// get pod names associated with the workflow
	podList := &corev1.PodList{}
	labelSelector := client.MatchingLabels{"workflows.argoproj.io/workflow": workflow.Name}
	if err := r.List(ctx, podList, client.InNamespace(req.Namespace), labelSelector); err != nil {
		logger.Error(err, "unable to list pods for the workflow", "workflow", workflow.Name)
		return ctrl.Result{}, err
	}

	for _, pod := range podList.Items {
		logger.Info("Pod name", "podName", pod.Name)
	}

	// NEXT_STEPS:
	// 		read the logs & get the image namescec
	// 		maintain state on pods in pod level
	// 				argo.slsa.io/status: in-progress
	// 				argo.slsa.io/status: completed
	// 				argo.slsa.io/status: error
	// 				argo.slsa.io/status: no-artifacts-to-sign
	// 		signing the images
	// 		uploading the signatures to the registry
	// 		attestation for the images
	// 		sign and upload the attestation to the registry
	// 		sbom generation for the images
	// 		sign and upload the sbom to the registry

	// set the status to completed
	return updateWFStatus(r, ctx, &workflow, statusLabel, "completed")
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkflowReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wfv1alpha1.Workflow{}).
		Complete(r)
}
