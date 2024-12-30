package workflowPodReconciler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	annotationUpdater "github.com/MohomedThariq/argo-supply-chain-security/pkg/annotation-updater"
)

const (
	statusLabel              string = annotationUpdater.StatusLabel
	reconciliationInProgerss string = "In-Progress"
	reconciliationCompleted  string = "Completed"
	reconciliationError      string = "Error"
	reconciliationSkipped    string = "Skipped"

	artifactsLabel    string = "argo.slsa.io/artifacts"
	artifactsNotFound string = "No-Artifacts-Found"

	signedLabel      string = "argo.slsa.io/signed"
	signingCompleted string = "Completed"
	signingError     string = "Error"
	signingSkipped   string = "Skipped"
)

type PodStatus struct {
	PodName        string
	Status         wfv1alpha1.NodePhase
	ArtifactsFound bool
	Signed         bool
	Reconciliation bool
}

type WorkflowPodsStatus []PodStatus

func (wfps *WorkflowPodsStatus) GetPodInfo(workflow *wfv1alpha1.Workflow) error {
	for _, node := range workflow.Status.Nodes {
		if node.Type == "Pod" {
			Id := strings.TrimPrefix(node.ID, workflow.Name+"-")
			podName := fmt.Sprintf("%s-%s-%s", workflow.Name, node.TemplateName, Id)
			*wfps = append(*wfps, PodStatus{PodName: podName, Status: node.Phase})
		}
	}

	if len(*wfps) == 0 {
		return errors.New("no pods found in the workflow")
	}

	return nil
}

func (wfps *WorkflowPodsStatus) Reconcile(ctx context.Context, k8sClient client.Client, namespace string) error {
	for i := range *wfps {
		pod := &corev1.Pod{}
		if (*wfps)[i].Status == wfv1alpha1.NodeSkipped || (*wfps)[i].Status == wfv1alpha1.NodeOmitted {
			// in this case there won't be a pod to update status
			(*wfps)[i].Reconciliation = true
		} else if (*wfps)[i].Status == wfv1alpha1.NodeSucceeded || (*wfps)[i].Status == wfv1alpha1.NodeFailed || (*wfps)[i].Status == wfv1alpha1.NodeError {
			if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: (*wfps)[i].PodName}, pod); err != nil {
				return err
			}

			status, statusLabelIsPresent := pod.Annotations[statusLabel]
			artifactsInfo, artifactsLabelIsPresent := pod.Annotations[artifactsLabel]
			signedStatus, signedLabelIsPresent := pod.Annotations[signedLabel]

			if !statusLabelIsPresent || status == reconciliationInProgerss {
				if (*wfps)[i].Status == wfv1alpha1.NodeError {
					// in this case pod has exited with a non 0 exit code so need to skip this
					if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, statusLabel, reconciliationSkipped); err != nil {
						return err
					}
					(*wfps)[i].Reconciliation = true
				} else {
					// when node success or a child node has failed
					if pod.Status.Phase == corev1.PodSucceeded {
						// start reconcilation
						if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, statusLabel, reconciliationInProgerss); err != nil {
							return err
						}

						if !artifactsLabelIsPresent {
							// TODO: logic to read the logs & get the artifat names. maybe also an artifact type
							artifactsInfo = artifactsNotFound
							(*wfps)[i].ArtifactsFound = false

							if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, artifactsLabel, artifactsInfo); err != nil {
								return err
							}
						} else if artifactsInfo != artifactsNotFound {
							(*wfps)[i].ArtifactsFound = true
						}

						if (*wfps)[i].ArtifactsFound {
							if !signedLabelIsPresent {
								// TODO: artifact signing also generate SBOMs for supported artifacts
								signingStatus := signingCompleted
								(*wfps)[i].Signed = true

								if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, signedLabel, signingStatus); err != nil {
									return err
								}
							} else if signedStatus == signingCompleted {
								(*wfps)[i].Signed = true
							}
						} else if !(*wfps)[i].ArtifactsFound {
							if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, signedLabel, signingSkipped); err != nil {
								return err
							}
						}

						if (*wfps)[i].ArtifactsFound {
							if (*wfps)[i].Signed {
								if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, statusLabel, reconciliationCompleted); err != nil {
									return err
								}
							} else {
								if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, statusLabel, reconciliationError); err != nil {
									return err
								}
							}
						} else {
							if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, statusLabel, reconciliationSkipped); err != nil {
								return err
							}
						}
						(*wfps)[i].Reconciliation = true
					} else {
						// node completed but if the pod in in a different state
						if err := annotationUpdater.PatchAnnotations(ctx, k8sClient, pod, statusLabel, reconciliationSkipped); err != nil {
							return err
						}
						(*wfps)[i].Reconciliation = true
					}
				}
			} else {
				// pod reconcilation has already completed
				(*wfps)[i].Reconciliation = true
			}
		}
	}

	for _, workflowPod := range *wfps {
		if !workflowPod.Reconciliation {
			return errors.New("not all workflow pods have been reconciled")
		}
	}

	return nil
}
