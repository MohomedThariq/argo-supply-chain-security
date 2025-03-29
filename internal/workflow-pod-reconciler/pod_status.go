package workflowpodreconciler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/v1alpha1"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/sbom"
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

	sbomAnnotation string = "argo.slsa.io/sbom"
	sbomCompleted  string = "Attached"
	sbomError      string = "Error"
	sbomSkipped    string = "Skipped"
	sbomType       string = options.PredicateCycloneDX

	provenanceAnnotation string = "argo.slsa.io/provenance"
	provenanceCompleted  string = "Attached"
	provenanceError      string = "Error"
	provenanceSkipped    string = "Skipped"
	provenanceType       string = options.PredicateSLSA1
)

// podStatus represents the current state and metadata of a workflow pod
type podStatus struct {
	podName            string
	pod                *corev1.Pod
	status             wfv1alpha1.NodePhase
	node               wfv1alpha1.NodeStatus
	artifactsFound     bool
	artifactInfo       string
	signed             bool
	sbomAttached       bool
	provenanceAttached bool
	reconciliation     bool
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

	return podStatus.handlePodReconciliation(ctx, cfg, rcfg)
}

func (podStatus *podStatus) handlePodReconciliation(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig) error {
	logger := log.FromContext(ctx)

	// in this case pod has exited with a non 0 exit code so need to skip this
	if podStatus.status == wfv1alpha1.NodeError {
		return podStatus.markPodAsSkipped(ctx, rcfg.Client)
	}

	// node completed but if the pod is not in succeeded state, then skip this
	if podStatus.pod.Status.Phase != corev1.PodSucceeded {
		return podStatus.markPodAsSkipped(ctx, rcfg.Client)
	}

	if err := statusupdater.PatchAnnotations(
		ctx, rcfg.Client, podStatus.pod, podStatusAnnotation, reconciliationInProgerss,
	); err != nil {
		return err
	}

	// extract artifact information & update the pod annotations
	if err := podStatus.handleArtifactInfo(ctx, rcfg.Client); err != nil {
		return err
	}

	// sign the artifacts if found
	if err := podStatus.handleArtifactSigning(ctx, cfg, rcfg.Client); err != nil {
		return err
	}

	// generate sbom for the artifacts found
	if err := podStatus.handleSBOMgeneration(ctx, cfg, rcfg.Client); err != nil {
		logger.Error(err, "failed to generate sbom for some artifact")
	}

	return podStatus.updateFinalStatus(ctx, rcfg.Client, podStatus.pod)
}

func checkOCI(oci string) (ok bool, ociRef, ociDigest string) {
	ref, err := name.ParseReference(oci)
	if err != nil {
		return false, "", ""
	}
	digest, ok := ref.(name.Digest)
	if !ok {
		return false, "", ""
	}

	return true, ref.Name(), digest.DigestStr()
}

func (podStatus *podStatus) handleArtifactInfo(ctx context.Context, k8sClient client.Client) error {
	if _, exists := podStatus.pod.Annotations[artifactsAnnotation]; !exists {
		status := false
		artifactInfo := artifactsNotFound

		outputs := podStatus.node.Outputs
		if outputs.HasParameters() {
			for _, param := range outputs.Parameters {
				if hasOCIPrefix := strings.HasPrefix("OCI", param.Name); hasOCIPrefix {
					artifactInfo = param.GetValue()
					if ok, _, _ := checkOCI(artifactInfo); ok {
						status = true
					} else {
						artifactInfo = artifactsNotFound
						status = false
					}
				}
			}
		}

		podStatus.artifactsFound = status
		podStatus.artifactInfo = artifactInfo
		return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, artifactsAnnotation, artifactInfo)
	}

	podStatus.artifactsFound = podStatus.pod.Annotations[artifactsAnnotation] != artifactsNotFound
	return nil
}

func (podStatus *podStatus) handleArtifactSigning(ctx context.Context, cfg config.Config, k8sClient client.Client) error {
	logger := log.FromContext(ctx)

	if !podStatus.artifactsFound {
		return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, signedAnnotation, signingSkipped)
	}

	if _, exists := podStatus.pod.Annotations[signedAnnotation]; !exists {
		status := false
		signingState := signingError
		artifactInfo := podStatus.artifactInfo

		if err := signer.SignWithConfigOpts(ctx, artifactInfo, cfg); err != nil {
			logger.Error(err, "failed to sign artifact",
				"pod name", podStatus.pod.Name,
				"aertifact", artifactInfo,
			)
		} else {
			logger.Info("artifact signed", "artifact", artifactInfo)
			status = true
			signingState = signingCompleted
		}

		podStatus.signed = status
		return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, signedAnnotation, signingState)
	}

	podStatus.signed = podStatus.pod.Annotations[signedAnnotation] == signingCompleted
	return nil
}

func (podStatus *podStatus) handleSBOMgeneration(ctx context.Context, cfg config.Config, k8sClient client.Client) error {
	logger := log.FromContext(ctx)

	if !podStatus.artifactsFound {
		return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, sbomAnnotation, sbomSkipped)
	}

	if _, exists := podStatus.pod.Annotations[sbomAnnotation]; !exists {
		status := false
		sbomState := sbomError
		artifactInfo := podStatus.artifactInfo

		if err := sbom.GenerateSBOMWithConfigOpts(ctx, artifactInfo, sbomType, cfg); err != nil {
			logger.Error(err, "failed to create sbom for artifact",
				"pod name", podStatus.pod.Name,
				"aertifact", artifactInfo,
			)
		} else {
			status = true
			sbomState = sbomCompleted
		}

		podStatus.sbomAttached = status
		return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, sbomState, sbomCompleted)
	}

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
	podStatus.pod = pod

	if status, exists := pod.Annotations[podStatusAnnotation]; exists && status != reconciliationInProgerss {
		podStatus.reconciliation = true
	}

	if artifacts, exists := pod.Annotations[artifactsAnnotation]; exists && artifacts != artifactsNotFound {
		podStatus.artifactsFound = true
		podStatus.artifactInfo = artifacts
	}

	if signed, exists := pod.Annotations[signedAnnotation]; exists && signed != signingError {
		podStatus.signed = true
	}

	if sbom, exists := pod.Annotations[sbomAnnotation]; exists && sbom != sbomError {
		podStatus.sbomAttached = true
	}

	if provenance, exists := pod.Annotations[provenanceAnnotation]; exists && provenance != provenanceError {
		podStatus.provenanceAttached = true
	}
}

func (podStatus *podStatus) markPodAsSkipped(ctx context.Context, k8sClient client.Client) error {
	podStatus.reconciliation = true
	return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, podStatusAnnotation, reconciliationSkipped)
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

func (podStatus *podStatus) handleProveneceAttachment(ctx context.Context, cfg config.Config, k8sClient client.Client, wf *wfv1alpha1.Workflow, subjects []*intoto.ResourceDescriptor) error {
	logger := log.FromContext(ctx)

	if !podStatus.artifactsFound {
		return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, provenanceAnnotation, provenanceSkipped)
	}

	if _, exists := podStatus.pod.Annotations[podStatusAnnotation]; !exists && podStatus.signed {
		status := false
		provenenceState := sbomError
		artifactInfo := podStatus.artifactInfo

		provenance, err := v1alpha1.GenerateSlsaV1Provenance(wf, subjects)
		if err != nil {
			return fmt.Errorf("error while generating provenance: %w", err)
		}

		if attestInfo, err := signer.AttestWithConfigOpts(ctx, cfg, artifactInfo, provenanceType, provenance); err != nil {
			logger.Error(err, "failed to attach provenence for artifact",
				"pod name", podStatus.pod.Name,
				"aertifact", artifactInfo,
			)
		} else {
			logger.Info("attached slsa provenence", attestInfo...)
			status = true
			provenenceState = provenanceCompleted
		}

		podStatus.sbomAttached = status
		return statusupdater.PatchAnnotations(ctx, k8sClient, podStatus.pod, provenenceState, provenanceCompleted)
	}

	return nil
}
