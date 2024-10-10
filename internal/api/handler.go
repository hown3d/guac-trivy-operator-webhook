package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"guac-trivy-operator-webhook/internal/attestation"
	"guac-trivy-operator-webhook/internal/guac"
	"log"
	"net/http"

	aquasecurityv1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
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

	var processErrs error
	processErrs = errors.Join(processErrs, processBom(r.Context(), into.Name, into.Name, into.Report.Bom, s.publisher))

	clusterName, ok := r.Header["Clustername"]
	if !ok {
		return fmt.Errorf("missing Clustername header")
	}

	processErrs = errors.Join(processErrs, processDeploymentAttestation(r.Context(), into.Name, into.Namespace, clusterName[0], &into.Report.Artifact, &into.Report.Bom, s.publisher))
	return processErrs
}

func processDeploymentAttestation(ctx context.Context, name, namespace, clusterName string, artifact *aquasecurityv1alpha1.Artifact, bom *aquasecurityv1alpha1.BOM, publisher *guac.Publisher) error {
	purl := bom.Metadata.Component.BOMRef
	totoStatement := attestation.Deployment(purl, artifact.Digest, namespace, clusterName)
	marshaledStatement, err := protojson.Marshal(totoStatement)
	if err != nil {
		return fmt.Errorf("marshaling intoto statement: %w", err)
	}

	doc := &processor.Document{
		Blob:   marshaledStatement,
		Type:   processor.DocumentITE6Generic,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   string("TODO"),
			Source:      fmt.Sprintf("%s/%s", namespace, name),
			DocumentRef: events.GetDocRef(marshaledStatement),
		},
	}
	collector.AddChildLogger(zap.S(), doc)
	return publisher.Publish(ctx, doc)
}

func processBom(ctx context.Context, name, namespace string, bom aquasecurityv1alpha1.BOM, publisher *guac.Publisher) error {
	marshaledBom, err := json.Marshal(bom)
	if err != nil {
		return fmt.Errorf("marshaling bom: %w", err)
	}

	doc := &processor.Document{
		Blob:   marshaledBom,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector:   string("TODO"),
			Source:      fmt.Sprintf("%s/%s", namespace, name),
			DocumentRef: events.GetDocRef(marshaledBom),
		},
	}
	collector.AddChildLogger(zap.S(), doc)
	return publisher.Publish(ctx, doc)
}
