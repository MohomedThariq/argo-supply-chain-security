package workflowPodReconciler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/statusUpdater"
)

const (
	podStatusAnnotation      string = "argo.slsa.io/status"
	reconciliationInProgerss string = "In-Progress"
	reconciliationCompleted  string = "Completed"
	reconciliationError      string = "Error"
	reconciliationSkipped    string = "Skipped"

	artifactsAnnotation string = "argo.slsa.io/artifacts"
	artifactsNotFound   string = "No-Artifacts-Found"

	signedAnnotation string = "argo.slsa.io/signed"
	signingCompleted string = "Completed"
	signingError     string = "Error"
	signingSkipped   string = "Skipped"
)

type PodStatus struct {
	PodName        string
	Status         wfv1alpha1.NodePhase
	Node           wfv1alpha1.NodeStatus
	ArtifactsFound bool
	Signed         bool
	Reconciliation bool
}

type WorkflowPodsStatus []PodStatus

func (wfps *WorkflowPodsStatus) GetPodInfo(workflow *wfv1alpha1.Workflow) error {
	if len(workflow.Status.Nodes) == 0 {
		return errors.New("no pods found in the workflow")
	}

	var pods []PodStatus
	for _, node := range workflow.Status.Nodes {
		if node.Type == "Pod" {
			pods = append(pods, PodStatus{
				PodName: formatPodName(workflow.Name, node.TemplateName, node.ID),
				Status:  node.Phase,
				Node:    node,
			})
		}
	}

	if len(pods) == 0 {
		return errors.New("no pods found in the workflow")
	}

	*wfps = pods
	return nil
}

func formatPodName(workflowName, templateName, nodeID string) string {
	return fmt.Sprintf("%s-%s-%s",
		workflowName,
		templateName,
		strings.TrimPrefix(nodeID, workflowName+"-"),
	)
}

func (wfps *WorkflowPodsStatus) Reconcile(ctx context.Context, k8sClient client.Client, namespace string) error {
	for i := range *wfps {
		podStatus := &(*wfps)[i]
		if err := wfps.reconcilePod(ctx, k8sClient, namespace, podStatus); err != nil {
			return err
		}
	}

	return wfps.validateAllPodsReconciled()
}

func (wfps *WorkflowPodsStatus) reconcilePod(
	ctx context.Context, k8sClient client.Client, namespace string, podStatus *PodStatus,
) error {
	if wfps.isSkippedOrOmittedNode(podStatus) {
		// skipeed or omitted nodes will not have a pod associated with them to reconcile
		podStatus.Reconciliation = true
		return nil
	} else if !wfps.inKnownState(podStatus) {
		// in case of an unknown state, cannot proceed with reconciliation
		unknownPodStateError := fmt.Sprint(podStatus.PodName, "is in an unknown node state: ", podStatus.Status)
		return errors.New(unknownPodStateError)
	}

	if podStatus.Status == wfv1alpha1.NodeRunning || podStatus.Status == wfv1alpha1.NodePending {
		return nil
	}

	pod, err := wfps.getPod(ctx, k8sClient, namespace, podStatus.PodName)
	if err != nil {
		return err
	}

	if wfps.isAlreadyReconciled(pod) {
		podStatus.Reconciliation = true
		return nil
	}

	return wfps.handlePodReconciliation(ctx, k8sClient, pod, podStatus)
}

func (wfps *WorkflowPodsStatus) handlePodReconciliation(
	ctx context.Context, k8sClient client.Client, pod *corev1.Pod, podStatus *PodStatus,
) error {
	// in this case pod has exited with a non 0 exit code so need to skip this
	if podStatus.Status == wfv1alpha1.NodeError {
		return wfps.markPodAsSkipped(ctx, k8sClient, pod, podStatus)
	}

	// node completed but if the pod is not in succeeded state, then skip this
	if pod.Status.Phase != corev1.PodSucceeded {
		return wfps.markPodAsSkipped(ctx, k8sClient, pod, podStatus)
	}

	if err := statusUpdater.PatchAnnotations(
		ctx, k8sClient, pod, podStatusAnnotation, reconciliationInProgerss,
	); err != nil {
		return err
	}

	// extract artifact information & update the pod annotations
	if err := wfps.handleArtifactInfo(ctx, k8sClient, pod, podStatus); err != nil {
		return err
	}

	// sign the artifacts if found
	if err := wfps.handleArtifactSigning(ctx, k8sClient, pod, podStatus); err != nil {
		return err
	}

	return wfps.updateFinalStatus(ctx, k8sClient, pod, podStatus)
}

func (wfps *WorkflowPodsStatus) handleArtifactInfo(
	ctx context.Context, k8sClient client.Client, pod *corev1.Pod, podStatus *PodStatus,
) error {
	if _, exists := pod.Annotations[artifactsAnnotation]; !exists {
		status := false
		artifactInfo := artifactsNotFound

		outputs := podStatus.Node.Outputs
		if outputs.HasParameters() {
			for _, param := range outputs.Parameters {
				if hasOCIPrefix := strings.HasPrefix("OCI", param.Name); hasOCIPrefix {
					artifactInfo = param.GetValue()
					status = true
				}
			}
		}

		podStatus.ArtifactsFound = status
		return statusUpdater.PatchAnnotations(ctx, k8sClient, pod, artifactsAnnotation, artifactInfo)
	}

	podStatus.ArtifactsFound = pod.Annotations[artifactsAnnotation] != artifactsNotFound
	return nil
}

func (wfps *WorkflowPodsStatus) handleArtifactSigning(
	ctx context.Context, k8sClient client.Client, pod *corev1.Pod, podStatus *PodStatus,
) error {
	if !podStatus.ArtifactsFound {
		return statusUpdater.PatchAnnotations(ctx, k8sClient, pod, signedAnnotation, signingSkipped)
	}

	if _, exists := pod.Annotations[signedAnnotation]; !exists {
		// TODO: artifact signing also generate SBOMs for supported artifacts
		status := false                // TODO: set to false for now until the logic is implemented
		signingState := signingSkipped // TODO: set to "Skipped" for now until the logic is implemented

		podStatus.Signed = status
		return statusUpdater.PatchAnnotations(ctx, k8sClient, pod, signedAnnotation, signingState)
	}

	podStatus.Signed = pod.Annotations[signedAnnotation] == signingCompleted
	return nil
}

func (wfps *WorkflowPodsStatus) isSkippedOrOmittedNode(podStatus *PodStatus) bool {
	return podStatus.Status == wfv1alpha1.NodeSkipped || podStatus.Status == wfv1alpha1.NodeOmitted
}

func (wfps *WorkflowPodsStatus) inKnownState(podStatus *PodStatus) bool {
	return podStatus.Status == wfv1alpha1.NodeSucceeded ||
		podStatus.Status == wfv1alpha1.NodeFailed ||
		podStatus.Status == wfv1alpha1.NodeError ||
		podStatus.Status == wfv1alpha1.NodePending ||
		podStatus.Status == wfv1alpha1.NodeRunning
}

func (wfps *WorkflowPodsStatus) getPod(
	ctx context.Context, k8sClient client.Client, namespace string, podName string,
) (*corev1.Pod, error) {
	var pod corev1.Pod
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      podName,
	}, &pod)
	return &pod, err
}

func (wfps *WorkflowPodsStatus) isAlreadyReconciled(pod *corev1.Pod) bool {
	status, exists := pod.Annotations[podStatusAnnotation]
	return exists && status != reconciliationInProgerss
}

func (wfps *WorkflowPodsStatus) markPodAsSkipped(
	ctx context.Context, k8sClient client.Client, pod *corev1.Pod, podStatus *PodStatus,
) error {
	podStatus.Reconciliation = true
	return statusUpdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationSkipped)
}

func (wfps *WorkflowPodsStatus) updateFinalStatus(
	ctx context.Context, k8sClient client.Client, pod *corev1.Pod, podStatus *PodStatus,
) error {
	podStatus.Reconciliation = true

	// if no artifacts found signing is skipped
	if !podStatus.ArtifactsFound {
		return statusUpdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationSkipped)
	}

	// when artifacts are found & signed
	if podStatus.Signed {
		return statusUpdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationCompleted)
	}

	// when artifacts are found but not signed
	return statusUpdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationError)
}

func (wfps *WorkflowPodsStatus) validateAllPodsReconciled() error {
	for _, workflowPod := range *wfps {
		if !workflowPod.Reconciliation {
			return errors.New("not all workflow pods have been reconciled")
		}
		if workflowPod.ArtifactsFound && !workflowPod.Signed {
			return errors.New("error while signing artifacts found in " + workflowPod.Node.DisplayName)
		}
	}
	return nil
}
