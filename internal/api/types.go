package api

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/runtime"
)

type reportRequest struct {
	Verb           string           `json:"verb"`
	OperatorObject *runtime.Unknown `json:"operatorObject"`
}

func (r *reportRequest) UnmarshalJSON(b []byte) error {
	type alias reportRequest
	var req alias
	err := json.Unmarshal(b, &req)
	if err != nil {
		return err
	}
	if req.Verb != "" {
		r.OperatorObject = req.OperatorObject
		r.Verb = req.Verb
		return nil
	}

	// operator webhook may send only the runtime.Unknown data
	obj := new(runtime.Unknown)
	err = obj.UnmarshalJSON(b)
	if err != nil {
		return err
	}
	r.OperatorObject = obj
	return nil
}
