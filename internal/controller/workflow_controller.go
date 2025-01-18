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
	"time"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	annotationUpdater "github.com/MohomedThariq/argo-supply-chain-security/pkg/annotation-updater"
	wfpr "github.com/MohomedThariq/argo-supply-chain-security/pkg/workflow-pod-reconciler"
)

// Reconciler reconciles a Workflow object
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	configMapName string = "argo-slsa-config"

	enableAnnotation string = "argo.slsa.io/enable"
	featureEnabled   string = "true"

	WorkflowStatusAnnotation string = "argo.slsa.io/status"
	reconcileInProgrees      string = "In-Progress"
	reconcileCompleted       string = "Completed"
	reconcileError           string = "Error"
)

//+kubebuilder:rbac:groups=argoproj.io,resources=workflows,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list
//+kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	controllerNamespace, err := getCurrentNamespace()
	if err != nil {
		return ctrl.Result{}, err
	}

	if _, err := r.getConfigMap(ctx, configMapName, controllerNamespace); err != nil {
		return ctrl.Result{}, err
	}

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
	isEnabled := workflow.Annotations[enableAnnotation] == featureEnabled
	status, AnnotationsIsPresent := workflow.Annotations[WorkflowStatusAnnotation]

	// check if enabled & start securing the supply chain
	if isEnabled {
		if AnnotationsIsPresent && (status == reconcileCompleted || status == reconcileError) {
			logger.Info("Workflow reconciled")
			return ctrl.Result{}, nil
		}
		if err := annotationUpdater.PatchAnnotations(ctx, r.Client, &workflow, WorkflowStatusAnnotation, reconcileInProgrees); err != nil {
			if err.Error() == "conflict or not found" {
				return ctrl.Result{Requeue: true}, nil
			} else {
				logger.Error(err, "unable to update workflow status")
			}
		}
	} else {
		logger.Info("Not enabled ignoring workflow", "workflow", workflow.Name)
		return ctrl.Result{}, nil
	}

	// get pod names associated with the workflow
	var pods wfpr.WorkflowPodsStatus
	if err := pods.GetPodInfo(&workflow); err != nil {
		return ctrl.Result{Requeue: true}, nil
	}

	// reconcile the pods
	if err := pods.Reconcile(ctx, r.Client, workflow.Namespace); err != nil {
		if err.Error() == "not all workflow pods have been reconciled" {
			logger.Info("Waiting for tasks to execute", "workflow", workflow.Name)
			return ctrl.Result{RequeueAfter: time.Second * 10}, nil
		} else if err.Error() == "conflict or not found" {
			return ctrl.Result{Requeue: true}, nil
		}
		logger.Error(err, "failed to reconcile pods")
		return ctrl.Result{}, err
	}

	// TODO: attach slsa attestation for the artifacts

	// set the status to completed
	if err := annotationUpdater.PatchAnnotations(ctx, r.Client, &workflow, WorkflowStatusAnnotation, reconcileCompleted); err != nil {
		if err.Error() == "conflict or not found" {
			return ctrl.Result{Requeue: true}, nil
		} else {
			logger.Error(err, "unable to update workflow status")
		}
	}

	logger.Info("Workflow secured successfully", "workflow", workflow.Name)
	return ctrl.Result{}, nil
}

func (r *Reconciler) getConfigMap(ctx context.Context, name string, namespace string) (map[string]string, error) {
	configMap := &corev1.ConfigMap{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, configMap); err != nil {
		return nil, err
	}
	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
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
