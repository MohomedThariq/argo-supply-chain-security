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
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Reconciler reconciles a Workflow object
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Supply chain security annotations & labels const
const (
	enableAnnotation string = "argo.slsa.io/enable"
	statusLabel      string = "argo.slsa.io/status"
	configMapName    string = "argo-supply-chain-security-chains-config"
)

//+kubebuilder:rbac:groups=argoproj.io,resources=workflows,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list
//+kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	config, err := r.getConfigMap(ctx, configMapName, req.Namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Error(err, "unable to fetch config map")
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	fmt.Println(config)

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
			if err := r.updateWFStatus(ctx, &workflow, statusLabel, "in-progress"); err != nil {
				if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
					return ctrl.Result{Requeue: true}, nil
				} else {
					logger.Error(err, "unable to update workflow status")
					return ctrl.Result{}, nil
				}
			}
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
	if err := r.updateWFStatus(ctx, &workflow, statusLabel, "completed"); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		} else {
			logger.Error(err, "unable to update workflow status")
		}
	}

	return ctrl.Result{}, nil
}

// update current status in workflow
func (r *Reconciler) updateWFStatus(ctx context.Context, wf *wfv1alpha1.Workflow, label string, status string) error {
	logger := log.FromContext(ctx)

	if wf.Labels == nil {
		wf.Labels = make(map[string]string)
	} else if wf.Labels[label] == status {
		// ignore update if status is same
		return nil
	}
	wf.Labels[label] = status
	if err := r.Update(ctx, wf); err != nil {
		return err
	}
	logger.Info("Workflow status updated", "status", status)
	return nil
}

func (r *Reconciler) getConfigMap(ctx context.Context, name string, namespace string) (map[string]string, error) {
	configMap := &corev1.ConfigMap{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, configMap)
	if err != nil {
		return nil, err
	}
	return configMap.Data, nil
}

func getCurrentNamespace() (string, error) {
	namespaceFile := filepath.Join("/var/run/secrets/kubernetes.io/serviceaccount", "namespace")
	namespace, err := os.ReadFile(namespaceFile)
	if err != nil {
		return "", err
	}
	return string(namespace), nil
}

func checkConfigMapExists(ctx context.Context, name string, namespace string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	_, err = clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("ConfigMap %s/%s not found: %v", namespace, name, err)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	namespace, err := getCurrentNamespace()
	if err != nil {
		panic(err)
	}

	if err = checkConfigMapExists(context.Background(), configMapName, namespace); err != nil {
		panic(err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&wfv1alpha1.Workflow{}).
		Complete(r)
}
