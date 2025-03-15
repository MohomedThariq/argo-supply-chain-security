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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	wfpr "github.com/MohomedThariq/argo-supply-chain-security/internal/workflow-pod-reconciler"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/statusupdater"
)

// Reconciler reconciles a Workflow object
type Reconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	InclusterClient kubernetes.Interface
	Namespace       string
}

var (
	serviceAccountInfoPath = "/var/run/secrets/kubernetes.io/serviceaccount"
)

const (
	configMapName string = "argo-slsa-config"

	enableLabel    string = "argo.slsa.io/enable"
	featureEnabled string = "true"

	workflowStatusLabel string = "argo.slsa.io/status"
	reconcileInProgrees string = "In-Progress"
	reconcileCompleted  string = "Completed"
	reconcileError      string = "Error"

	conflictOrNotFoundError = "conflict or not found"
)

//+kubebuilder:rbac:groups=argoproj.io,resources=workflows,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups="",resources=secrets;serviceaccounts,verbs=get;list
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	controllerNamespace, err := getCurrentNamespaceFunc()
	if err != nil {
		return ctrl.Result{}, err
	}

	configData, err := r.getConfigMap(ctx, configMapName, controllerNamespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	cfg := config.New(configData)

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

	rcfg := config.RuntimeConfig{
		Client:          r.Client,
		InclusterClient: r.InclusterClient,
		Namespace:       r.Namespace,
		Workflow:        &workflow,
	}

	// start securing the supply chain if enabled
	isEnabled := workflow.Labels[enableLabel] == featureEnabled
	status, statusIsPresent := workflow.Labels[workflowStatusLabel]

	// check if enabled & start securing the supply chain
	if isEnabled {
		if statusIsPresent && (status == reconcileCompleted || status == reconcileError) {
			logger.Info("Workflow reconciled")
			return ctrl.Result{}, nil
		}
		if result, err := r.updateWorkflowStatus(ctx, &workflow, reconcileInProgrees); err != nil {
			return result, err
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
	if err := pods.Reconcile(ctx, cfg, rcfg); err != nil {
		switch {
		case err.Error() == "not all workflow pods have been reconciled":
			logger.Info("Waiting for tasks to execute", "workflow", workflow.Name)
			return ctrl.Result{RequeueAfter: time.Second * 10}, nil

		case strings.HasPrefix(err.Error(), "error while signing artifacts found in "):
			if result, err := r.updateWorkflowStatus(ctx, &workflow, reconcileError); err != nil {
				return result, err
			}
			logger.Error(err, "artifact signing error detected", "workflow", workflow.Name)
			return ctrl.Result{}, nil

		case err.Error() == conflictOrNotFoundError:
			return ctrl.Result{Requeue: true}, nil

		default:
			logger.Error(err, "failed to reconcile pods")
			return ctrl.Result{}, err
		}
	}

	// if err := pods.AttestArtifacts(ctx, cfg, rcfg, []byte(attest.SampleAtt)); err != nil {
	// 	if result, err := r.updateWorkflowStatus(ctx, &workflow, reconcileError); err != nil {
	// 		return result, err
	// 	}
	// 	logger.Error(err, "artifact attesting error detected", "workflow", workflow.Name)
	// 	return ctrl.Result{}, nil
	// }

	// set the status to completed
	if result, err := r.updateWorkflowStatus(ctx, &workflow, reconcileCompleted); err != nil {
		return result, err
	}

	logger.Info("Workflow secured successfully", "workflow", workflow.Name)
	return ctrl.Result{}, nil
}

func (r *Reconciler) updateWorkflowStatus(ctx context.Context, workflow *wfv1alpha1.Workflow, status string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	if err := statusupdater.PatchLabels(ctx, r.Client, workflow, workflowStatusLabel, status); err != nil {
		if err.Error() == conflictOrNotFoundError {
			return ctrl.Result{Requeue: true}, nil
		}
		logger.Error(err, "unable to update workflow status")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) getConfigMap(ctx context.Context, name string, namespace string) (map[string]string, error) {
	configMap := &corev1.ConfigMap{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, configMap); err != nil {
		return nil, err
	}
	if configMap.Data == nil {
		return nil, errors.New("empty config map")
	}
	return configMap.Data, nil
}

var getCurrentNamespaceFunc = getCurrentNamespace

func getCurrentNamespace() (string, error) {
	namespaceFile := filepath.Join(serviceAccountInfoPath, "namespace")
	namespace, err := os.ReadFile(namespaceFile)
	if err != nil {
		return "", err
	}
	return string(namespace), nil
}

func clientWithInClusterConfig() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return client, err
}

func (r *Reconciler) checkConfigMapExists(ctx context.Context, name string) error {
	_, err := r.InclusterClient.CoreV1().ConfigMaps(r.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("ConfigMap %s/%s not found: %w", r.Namespace, name, err)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	client, err := clientWithInClusterConfig()
	if err != nil {
		panic(err)
	}
	r.InclusterClient = client

	namespace, err := getCurrentNamespaceFunc()
	if err != nil {
		panic(err)
	}
	r.Namespace = namespace

	if err = r.checkConfigMapExists(context.Background(), configMapName); err != nil {
		panic(err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&wfv1alpha1.Workflow{}).
		Complete(r)
}
