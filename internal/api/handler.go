package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	aquasecurityv1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	guac_attestation "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	toto_attestationv1 "github.com/in-toto/attestation/go/v1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
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
		return s.processSbom(r.Context(), typed)
	case *aquasecurityv1alpha1.VulnerabilityReport:
		return s.processVulnReport(r.Context(), typed)
	default:
		s.logger.Info("recieved unknown report", zap.String("type", fmt.Sprintf("%T", typed)))
	}
	return nil
}

func (s *Server) processVulnReport(ctx context.Context, vulnReport *aquasecurityv1alpha1.VulnerabilityReport) error {
	vulnAtt, err := vulnAttestation(&vulnReport.Report)
	if err != nil {
		return err
	}
	data, err := json.Marshal(vulnAtt)
	if err != nil {
		return err
	}

	doc := &processor.Document{
		Blob:   data,
		Type:   processor.DocumentITE6Vul,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   collectorName,
			Source:      sourceFromObj(vulnReport),
			DocumentRef: events.GetDocRef(data),
		},
	}
	collector.AddChildLogger(s.logger.Sugar(), doc)
	return s.publisher.Publish(ctx, doc)
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
			Source:      sourceFromObj(sbom),
			DocumentRef: events.GetDocRef(bom),
		},
	}
	collector.AddChildLogger(zap.S(), doc)
	return s.publisher.Publish(ctx, doc)
}

func vulnAttestation(report *aquasecurityv1alpha1.VulnerabilityReportData) (*guac_attestation.VulnerabilityStatement, error) {
	artifact := report.Artifact
	digest := artifact.Digest
	digestSplit := strings.Split(digest, ":")
	if len(digestSplit) != 2 {
		return nil, fmt.Errorf("report has invalid artifact.digest: %s", digest)
	}
	subject := &toto_attestationv1.ResourceDescriptor{
		Name: purl(&report.Registry, &artifact).String(),
		Digest: map[string]string{
			digestSplit[0]: digestSplit[1],
		},
	}

	vulnResult := make([]guac_attestation.Result, 0, len(report.Vulnerabilities))
	for _, vuln := range report.Vulnerabilities {
		vulnResult = append(vulnResult, guac_attestation.Result{
			VulnerabilityId: vuln.VulnerabilityID,
		})
	}

	predicate := guac_attestation.VulnerabilityPredicate{
		Scanner: guac_attestation.Scanner{
			Uri:     report.Scanner.Name,
			Version: report.Scanner.Version,
			Result:  vulnResult,
		},
		Metadata: guac_attestation.Metadata{
			ScannedOn: &report.UpdateTimestamp.Time,
		},
	}

	stmt := &guac_attestation.VulnerabilityStatement{
		Statement: toto_attestationv1.Statement{
			Type:    toto_attestationv1.StatementTypeUri,
			Subject: []*toto_attestationv1.ResourceDescriptor{subject},
		},
		Predicate: predicate,
	}
	return stmt, nil
}

func sourceFromObj(obj metav1.Object) string {
	labels := obj.GetLabels()
	clusterName, ok := labels[clusterNameLabelKey]
	if !ok {
		return fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
	}
	return fmt.Sprintf("%s/%s/%s", clusterName, obj.GetNamespace(), obj.GetName())
}

func purl(registry *aquasecurityv1alpha1.Registry, artifact *aquasecurityv1alpha1.Artifact) *packageurl.PackageURL {
	// see https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#oci for spec
	registryServer := registry.Server
	repo := artifact.Repository
	repoSplits := strings.Split(repo, "/")
	// last fragment of repo
	imageName := repoSplits[len(repoSplits)-1]

	qualifiers := []packageurl.Qualifier{
		{
			Key:   "repository_url",
			Value: fmt.Sprintf("%s/%s", registryServer, repo),
		},
	}
	return packageurl.NewPackageURL(packageurl.TypeOCI, "", imageName, artifact.Digest, qualifiers, "")
}
