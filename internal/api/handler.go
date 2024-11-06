package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aquasecurityv1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	guac_attestation "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	toto_attestationv1 "github.com/in-toto/attestation/go/v1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/CycloneDX/cyclonedx-go"
)

const (
	clusterNameLabelKey = "trivy-operator.cluster.name"
	collectorName       = "trivy-operator"
)

func (s *Server) reportHandler(w http.ResponseWriter, r *http.Request) error {
	var req reportRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return err
	}
	obj, err := runtime.Decode(s.decoder, req.OperatorObject.Raw)
	if err != nil {
		return err
	}

	switch typed := obj.(type) {
	case *aquasecurityv1alpha1.SbomReport:
		err = s.processSbom(r.Context(), typed)
	case *aquasecurityv1alpha1.VulnerabilityReport:
		err = s.processVulnReport(r.Context(), typed)
	default:
		s.logger.Info("recieved unknown report", zap.String("type", fmt.Sprintf("%T", typed)))
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unknown report type: %T", typed)
		return nil
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprint(w, "published report to guac")
	return nil
}

func (s *Server) processVulnReport(ctx context.Context, vulnReport *aquasecurityv1alpha1.VulnerabilityReport) error {
	report := vulnReport.Report
	var publishErrs error
	for _, vuln := range report.Vulnerabilities {
		vulnAtt := vulnAttestation(&vuln, &report.Scanner, &report.UpdateTimestamp.Time)
		data, err := json.Marshal(vulnAtt)
		if err != nil {
			publishErrs = errors.Join(publishErrs, fmt.Errorf("marshaling attestation for vuln %s", vuln.VulnerabilityID))
		}

		doc := &processor.Document{
			Blob:   data,
			Type:   processor.DocumentITE6Vul,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   collectorName,
				Source:      collectorName,
				DocumentRef: docRefFromObj(vulnReport),
			},
		}
		collector.AddChildLogger(s.logger.Sugar(), doc)
		err = s.publisher.Publish(ctx, doc)
		if err != nil {
			publishErrs = errors.Join(publishErrs, fmt.Errorf("publishing doc for vuln %s", vuln.VulnerabilityID))
		}
	}
	return publishErrs
}

func (s *Server) processSbom(ctx context.Context, sbom *aquasecurityv1alpha1.SbomReport) error {
	// guac parses artifacts by the version. Trivy does not include that by default though
	sbom.Report.Bom.Metadata.Component.Version = sbom.Report.Artifact.Digest

	bom, err := json.Marshal(sbom.Report.Bom)
	if err != nil {
		return fmt.Errorf("marshaling bom: %w", err)
	}

	docType := processor.DocumentUnknown
	if sbom.Report.Bom.BOMFormat == cyclonedx.BOMFormat {
		docType = processor.DocumentCycloneDX
	}
	doc := &processor.Document{
		Blob:   bom,
		Type:   docType,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   collectorName,
			Source:      collectorName,
			DocumentRef: docRefFromObj(sbom),
		},
	}
	return s.publisher.Publish(ctx, doc)
}

func vulnAttestation(vuln *aquasecurityv1alpha1.Vulnerability, scanner *aquasecurityv1alpha1.Scanner, scannedOn *time.Time) guac_attestation.VulnerabilityStatement {
	subject := &toto_attestationv1.ResourceDescriptor{
		Uri: vuln.PkgPURL,
	}
	predicate := guac_attestation.VulnerabilityPredicate{
		Scanner: guac_attestation.Scanner{
			Uri:     scanner.Name,
			Version: scanner.Version,
			Result: []guac_attestation.Result{
				{
					VulnerabilityId: vuln.VulnerabilityID,
				},
			},
		},
		Metadata: guac_attestation.Metadata{
			ScannedOn: scannedOn,
		},
	}
	stmt := guac_attestation.VulnerabilityStatement{
		Statement: toto_attestationv1.Statement{
			Type:    toto_attestationv1.StatementTypeUri,
			Subject: []*toto_attestationv1.ResourceDescriptor{subject},
		},
		Predicate: predicate,
	}
	return stmt
}

func docRefFromObj(obj metav1.Object) string {
	labels := obj.GetLabels()
	clusterName, ok := labels[clusterNameLabelKey]
	if !ok {
		return fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
	}
	return fmt.Sprintf("%s/%s/%s", clusterName, obj.GetNamespace(), obj.GetName())
}
