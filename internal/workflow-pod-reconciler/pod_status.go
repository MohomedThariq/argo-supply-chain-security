package workflowpodreconciler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/statusupdater"
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

// podStatus represents the current state and metadata of a workflow pod
type podStatus struct {
	// podName is the name of the pod
	podName string

	// status represents the current phase of the workflow node
	status wfv1alpha1.NodePhase

	// node contains the complete status information of the workflow node
	node wfv1alpha1.NodeStatus

	// artifactsFound indicates if any OCI artifacts were found in the pod
	artifactsFound bool

	// signed indicates if the artifacts in the pod have been signed
	signed bool

	// reconciliation indicates if the pod has completed its reconciliation process
	reconciliation bool
}

func (podStatus *podStatus) reconcilePod(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig) error {
	if podStatus.isSkippedOrOmittedPod() {
		// skipeed or omitted nodes will not have a pod associated with them to reconcile
		podStatus.reconciliation = true
		return nil
	} else if !podStatus.inKnownState() {
		// in case of an unknown state, cannot proceed with reconciliation
		unknownPodStateError := fmt.Sprint(podStatus.podName, "is in an unknown node state: ", podStatus.status)
		return errors.New(unknownPodStateError)
	}

	if podStatus.status == wfv1alpha1.NodeRunning || podStatus.status == wfv1alpha1.NodePending {
		return nil
	}

	pod, err := getPod(ctx, rcfg, podStatus.podName)
	if err != nil {
		return err
	}

	podStatus.currentRconsiliationStatus(pod)

	if podStatus.reconciliation {
		return nil
	}

	return podStatus.handlePodReconciliation(ctx, cfg, rcfg, pod)
}

func (podStatus *podStatus) handlePodReconciliation(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig, pod *corev1.Pod) error {
	// in this case pod has exited with a non 0 exit code so need to skip this
	if podStatus.status == wfv1alpha1.NodeError {
		return podStatus.markPodAsSkipped(ctx, rcfg.Client, pod)
	}

	// node completed but if the pod is not in succeeded state, then skip this
	if pod.Status.Phase != corev1.PodSucceeded {
		return podStatus.markPodAsSkipped(ctx, rcfg.Client, pod)
	}

	if err := statusupdater.PatchAnnotations(
		ctx, rcfg.Client, pod, podStatusAnnotation, reconciliationInProgerss,
	); err != nil {
		return err
	}

	// extract artifact information & update the pod annotations
	if err := podStatus.handleArtifactInfo(ctx, rcfg.Client, pod); err != nil {
		return err
	}

	// sign the artifacts if found
	if err := podStatus.handleArtifactSigning(ctx, cfg, rcfg, rcfg.Client, pod); err != nil {
		return err
	}

	return podStatus.updateFinalStatus(ctx, rcfg.Client, pod)
}

func (podStatus *podStatus) handleArtifactInfo(ctx context.Context, k8sClient client.Client, pod *corev1.Pod) error {
	if _, exists := pod.Annotations[artifactsAnnotation]; !exists {
		status := false
		artifactInfo := artifactsNotFound

		outputs := podStatus.node.Outputs
		if outputs.HasParameters() {
			for _, param := range outputs.Parameters {
				if hasOCIPrefix := strings.HasPrefix("OCI", param.Name); hasOCIPrefix {
					artifactInfo = param.GetValue()
					status = true
				}
			}
		}

		podStatus.artifactsFound = status
		return statusupdater.PatchAnnotations(ctx, k8sClient, pod, artifactsAnnotation, artifactInfo)
	}

	podStatus.artifactsFound = pod.Annotations[artifactsAnnotation] != artifactsNotFound
	return nil
}

func (podStatus *podStatus) handleArtifactSigning(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig, k8sClient client.Client, pod *corev1.Pod) error {
	logger := log.FromContext(ctx)

	if !podStatus.artifactsFound {
		return statusupdater.PatchAnnotations(ctx, k8sClient, pod, signedAnnotation, signingSkipped)
	}

	if _, exists := pod.Annotations[signedAnnotation]; !exists {
		status := false
		signingState := signingError

		if artifactInfo, exists := pod.Annotations[artifactsAnnotation]; exists {
			if err := signer.SignWithConfigOpts(ctx, artifactInfo, cfg, rcfg); err != nil {
				logger.Error(err, "failed to sign artifact",
					"pod name", pod.Name,
					"aertifact", artifactInfo,
				)
			} else {
				status = true
				signingState = signingCompleted
			}
		}

		// TODO: generate SBOMs for supported artifacts

		podStatus.signed = status
		return statusupdater.PatchAnnotations(ctx, k8sClient, pod, signedAnnotation, signingState)
	}

	podStatus.signed = pod.Annotations[signedAnnotation] == signingCompleted
	return nil
}

func (podStatus *podStatus) isSkippedOrOmittedPod() bool {
	return podStatus.status == wfv1alpha1.NodeSkipped || podStatus.status == wfv1alpha1.NodeOmitted
}

func (podStatus *podStatus) inKnownState() bool {
	return podStatus.status == wfv1alpha1.NodeSucceeded ||
		podStatus.status == wfv1alpha1.NodeFailed ||
		podStatus.status == wfv1alpha1.NodeError ||
		podStatus.status == wfv1alpha1.NodePending ||
		podStatus.status == wfv1alpha1.NodeRunning
}

func getPod(ctx context.Context, rcfg config.RuntimeConfig, podName string) (*corev1.Pod, error) {
	var pod corev1.Pod
	err := rcfg.Client.Get(ctx, client.ObjectKey{
		Namespace: rcfg.Workflow.Namespace,
		Name:      podName,
	}, &pod)
	return &pod, err
}

func (podStatus *podStatus) currentRconsiliationStatus(pod *corev1.Pod) {
	if status, exists := pod.Annotations[podStatusAnnotation]; exists && status != reconciliationInProgerss {
		podStatus.reconciliation = true
	}

	if artifacts, exists := pod.Annotations[artifactsAnnotation]; exists && artifacts != artifactsNotFound {
		podStatus.artifactsFound = true
	}

	if signed, exists := pod.Annotations[signedAnnotation]; exists && signed != signingError {
		podStatus.signed = true
	}

}

func (podStatus *podStatus) markPodAsSkipped(ctx context.Context, k8sClient client.Client, pod *corev1.Pod) error {
	podStatus.reconciliation = true
	return statusupdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationSkipped)
}

func (podStatus *podStatus) updateFinalStatus(
	ctx context.Context, k8sClient client.Client, pod *corev1.Pod,
) error {
	podStatus.reconciliation = true

	// if no artifacts found signing is skipped
	if !podStatus.artifactsFound {
		return statusupdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationSkipped)
	}

	// when artifacts are found & signed
	if podStatus.signed {
		return statusupdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationCompleted)
	}

	// when artifacts are found but not signed
	return statusupdater.PatchAnnotations(ctx, k8sClient, pod, podStatusAnnotation, reconciliationError)
}
