package v1

import (
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/provenance/slsa/common"
	slsav1prov "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	slsav1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
)

func GenerateProvenance(bd *slsav1prov.BuildDefinition, rd *slsav1prov.RunDetails, sub []*intoto.ResourceDescriptor) (intoto.Statement, error) {
	predicate := &slsav1prov.Provenance{
		BuildDefinition: bd,
		RunDetails:      rd,
	}

	predicateStruct, err := common.GetProtoStruct(predicate)
	if err != nil {
		return intoto.Statement{}, err
	}

	return intoto.Statement{
		Type:          intoto.StatementTypeUri,
		PredicateType: slsav1.PredicateSLSAProvenance,
		Subject:       sub,
		Predicate:     predicateStruct,
	}, nil
}
