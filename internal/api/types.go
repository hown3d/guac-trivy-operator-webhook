package api

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/runtime"
)

type reportRequest struct {
	Verb           string           `json:"verb"`
	OperatorObject *runtime.Unknown `json:"operatorObject"`
}

func (m *reportRequest) UnmarshalJSON(b []byte) error {
	type internalReportRequest struct {
		Verb           string           `json:"verb"`
		OperatorObject *runtime.Unknown `json:"operatorObject"`
	}
	var internalReq internalReportRequest
	err := json.Unmarshal(b, &internalReq)
	if err != nil {
		return err
	}
	if internalReq.Verb != "" {
		m.OperatorObject = internalReq.OperatorObject
		m.Verb = internalReq.Verb
		return nil
	}

	// operator webhook may send only the runtime.Unknown data
	obj := new(runtime.Unknown)
	err = obj.UnmarshalJSON(b)
	if err != nil {
		return err
	}
	m.OperatorObject = obj
	return nil
}
