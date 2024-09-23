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
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// WorkflowReconciler reconciles a Workflow object
type WorkflowReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Supply chain security annotaions & labels const
const (
	enableAnnotation = "argo.slsa.io/enable"
	statusLabel      = "argo.slsa.io/status"
)

// +kubebuilder:rbac:groups=argoproj.io,resources=workflows,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Workflow object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.3/pkg/reconcile
func (r *WorkflowReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// Create a logger instance (using zap)
	log.SetLogger(zap.New())
	logger := log.Log.WithName("controller")

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

	// start securing the supply chain if enabled
	isEnabled := workflow.Annotations[enableAnnotation] == "true"
	_, labelIsPresent := workflow.Labels[statusLabel]

	if isEnabled {
		if !labelIsPresent {
			if workflow.Labels == nil {
				workflow.Labels = make(map[string]string)
			}
			workflow.Labels[statusLabel] = "in-progress"
			logger.Info("adding label")
		} else {
			// label already available
			return ctrl.Result{}, nil
		}
	} else {
		logger.Info("Ignoring the workflow")
		return ctrl.Result{}, nil
	}

	// update the resource with status
	if err := r.Update(ctx, &workflow); err != nil {
		if apierrors.IsConflict(err) {
			// The workflow has been updated since we read it.
			// Requeue the workflow to try to reconciliate again.
			return ctrl.Result{Requeue: true}, nil
		}
		if apierrors.IsNotFound(err) {
			// The workflow has been deleted since we read it.
			// Requeue the workflow to try to reconciliate again.
			return ctrl.Result{Requeue: true}, nil
		}
		logger.Error(err, "unable to update workflow")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkflowReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wfv1alpha1.Workflow{}).
		Complete(r)
}
