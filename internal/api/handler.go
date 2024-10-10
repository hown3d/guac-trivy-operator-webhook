package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	aquasecurityv1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime"
)

type webhookMsg struct {
	Verb           string           `json:"verb"`
	OperatorObject *runtime.Unknown `json:"operatorObject"`
}

func (m *webhookMsg) UnmarshalJSON(b []byte) error {
	type webhookMsgInternal struct {
		Verb           string           `json:"verb"`
		OperatorObject *runtime.Unknown `json:"operatorObject"`
	}
	var internalMsg webhookMsgInternal
	err := json.Unmarshal(b, &internalMsg)
	if err != nil {
		return err
	}
	if internalMsg.Verb != "" {
		m.OperatorObject = internalMsg.OperatorObject
		m.Verb = internalMsg.Verb
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

func (s *Server) sbomHandler(w http.ResponseWriter, r *http.Request) error {
	var req webhookMsg
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return err
	}
	var into aquasecurityv1alpha1.SbomReport
	err = runtime.DecodeInto(s.sbomDecoder, req.OperatorObject.Raw, &into)
	if err != nil {
		return err
	}
	log.Printf("received sbom report: %+v", into)

	bom, err := json.Marshal(into.Report.Bom)
	if err != nil {
		return fmt.Errorf("marshaling bom: %w", err)
	}

	doc := &processor.Document{
		Blob:   bom,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector:   string("TODO"),
			Source:      fmt.Sprintf("%s/%s", into.Name, into.Namespace),
			DocumentRef: events.GetDocRef(bom),
		},
	}
	collector.AddChildLogger(zap.S(), doc)
	return s.publisher.Publish(r.Context(), doc)
}
