package proto

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func GetAnyProtoStruct(data any) (*structpb.Struct, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	protoStruct := &structpb.Struct{}
	err = protojson.Unmarshal(bytes, protoStruct)
	if err != nil {
		return nil, err
	}

	return protoStruct, nil
}
