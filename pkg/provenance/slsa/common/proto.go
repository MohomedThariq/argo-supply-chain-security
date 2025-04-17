package common

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func GetProtoStruct(predicate proto.Message) (*structpb.Struct, error) {
	protoStruct := &structpb.Struct{}
	predicateJSON, err := protojson.Marshal(predicate)
	if err != nil {
		return nil, err
	}

	err = protojson.Unmarshal(predicateJSON, protoStruct)
	if err != nil {
		return nil, err
	}

	return protoStruct, nil
}
