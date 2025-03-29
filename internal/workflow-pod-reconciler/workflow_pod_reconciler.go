package workflowpodreconciler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	intoto "github.com/in-toto/attestation/go/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/workflow/v1alpha1"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer"
)

// WorkflowPodsStatus represents the current state and metadata of all the workflow pods
type WorkflowPodsStatus []podStatus

// GetPodInfo collects all thformation of workflow pods
func (wfps *WorkflowPodsStatus) GetPodInfo(workflow *wfv1alpha1.Workflow) error {
	if len(workflow.Status.Nodes) == 0 {
		return errors.New("no pods found in the workflow")
	}

	var pods []podStatus
	for _, node := range workflow.Status.Nodes {
		if node.Type == "Pod" {
			pods = append(pods, podStatus{
				podName: formatPodName(workflow.Name, node.TemplateName, node.ID),
				status:  node.Phase,
				node:    node,
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

// Reconcile will process all the workflow pods & secure artifacts created from it
func (wfps *WorkflowPodsStatus) Reconcile(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig) error {
	for i := range *wfps {
		podStatus := &(*wfps)[i]
		if err := podStatus.reconcilePod(ctx, cfg, rcfg); err != nil {
			return err
		}
	}

	return wfps.validateAllPodsReconciled()
}

func (wfps *WorkflowPodsStatus) validateAllPodsReconciled() error {
	for _, workflowPod := range *wfps {
		if !workflowPod.reconciliation {
			return errors.New("not all workflow pods have been reconciled")
		}
		if workflowPod.artifactsFound && !workflowPod.signed {
			return errors.New("error while signing artifacts found in " + workflowPod.node.DisplayName)
		}
	}
	return nil
}

func (wfps *WorkflowPodsStatus) AttestArtifacts(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig) error {
	logger := log.FromContext(ctx)

	subjects := []*intoto.ResourceDescriptor{}
	for _, workflowPod := range *wfps {
		if workflowPod.artifactsFound && workflowPod.signed {
			imageRef, err := name.ParseReference(workflowPod.artifactInfo)
			if err != nil {
				return fmt.Errorf("error parsing reference: %w", err)
			}
			digest, ok := imageRef.(name.Digest)
			if !ok {
				return fmt.Errorf("digest not available in oci ref")
			}
			subjects = append(subjects, &intoto.ResourceDescriptor{
				Name: workflowPod.artifactInfo,
				Digest: map[string]string{
					"sha256": digest.DigestStr(),
				},
			})
		}
	}

	provenance, err := v1alpha1.GenerateSlsaV1Provenance(rcfg.Workflow, subjects)
	if err != nil {
		return fmt.Errorf("error while generating provenance: %w", err)
	}

	for _, workflowPod := range *wfps {
		if workflowPod.artifactsFound && workflowPod.signed {
			attestInfo, err := signer.AttestWithConfigOpts(ctx, cfg, workflowPod.artifactInfo, provenance)
			if err != nil {
				return fmt.Errorf("error wihile attesting: %w", err)
			}
			logger.Info("artifact attested", attestInfo...)
		}
	}
	return nil
}
