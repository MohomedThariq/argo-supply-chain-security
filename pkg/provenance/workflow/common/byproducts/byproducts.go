package byproducts

import (
	"encoding/json"
	"fmt"

	wfv1alpha1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	intoto "github.com/in-toto/attestation/go/v1"
)

const (
	JsonMediaType = "application/json"
)

func GetByproducts(wf *wfv1alpha1.Workflow) ([]*intoto.ResourceDescriptor, error) {
	byproduct := []*intoto.ResourceDescriptor{}
	if wf.Status.Outputs == nil {
		return byproduct, nil
	}

	if wf.Status.Outputs.Artifacts != nil {
		for _, key := range wf.Status.Outputs.Artifacts {
			content, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			bp := &intoto.ResourceDescriptor{
				Name:      fmt.Sprintf("workflow-artifact/%s", key.Name),
				Content:   content,
				MediaType: JsonMediaType,
			}
			byproduct = append(byproduct, bp)
		}
	}

	if wf.Status.Outputs.Parameters != nil {
		for _, key := range wf.Status.Outputs.Parameters {
			content, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			bp := &intoto.ResourceDescriptor{
				Name:      fmt.Sprintf("workflow-parameter/%s", key.Name),
				Content:   content,
				MediaType: JsonMediaType,
			}
			byproduct = append(byproduct, bp)
		}
	}

	return byproduct, nil
}
