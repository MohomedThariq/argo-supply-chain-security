package workflowpodreconciler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
)

const (
	attestsationType = options.PredicateSLSA1
)

// WorkflowPodsStatus represents the current state and metadata of all the workflow pods
type WorkflowStatus struct {
	PodsStatus []*podStatus
}

// GetPodInfo collects all thformation of workflow pods
func (wfps *WorkflowStatus) GetPodInfo(workflow *wfv1alpha1.Workflow) error {
	if len(workflow.Status.Nodes) == 0 {
		return errors.New("no pods found in the workflow")
	}

	var podsStatus []*podStatus
	for _, node := range workflow.Status.Nodes {
		if node.Type == "Pod" {
			podsStatus = append(podsStatus, &podStatus{
				podName: formatPodName(workflow.Name, node.TemplateName, node.ID),
				status:  node.Phase,
				node:    node,
			})
		}
	}

	if len(podsStatus) == 0 {
		return errors.New("no pods found in the workflow")
	}

	wfps.PodsStatus = podsStatus
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
func (wfps *WorkflowStatus) Reconcile(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig) error {
	for _, podStatus := range wfps.PodsStatus {
		if err := podStatus.reconcilePod(ctx, cfg, rcfg); err != nil {
			return err
		}
	}

	return wfps.validateAllPodsReconciled()
}

func (wfps *WorkflowStatus) validateAllPodsReconciled() error {
	for _, workflowPod := range wfps.PodsStatus {
		if !workflowPod.reconciliation {
			return errors.New("not all workflow pods have been reconciled")
		}
		if workflowPod.artifactsFound && !workflowPod.signed {
			return errors.New("error while signing artifacts found in " + workflowPod.node.DisplayName)
		}
	}
	return nil
}

func (wfps *WorkflowStatus) AttestArtifacts(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig) error {
	subjects := []*intoto.ResourceDescriptor{}
	for _, workflowPod := range wfps.PodsStatus {
		if workflowPod.artifactsFound && workflowPod.signed {
			ok, _, digest := checkOCI(workflowPod.artifactInfo)
			if ok {
				subjects = append(subjects, &intoto.ResourceDescriptor{
					Name: workflowPod.artifactInfo,
					Digest: map[string]string{
						"sha256": digest,
					},
				})
			}
		}
	}

	for _, workflowPod := range wfps.PodsStatus {
		if err := workflowPod.handleProveneceAttachment(ctx, cfg, rcfg.Client, rcfg.Workflow, subjects); err != nil {
			return err
		}
	}
	return nil
}
