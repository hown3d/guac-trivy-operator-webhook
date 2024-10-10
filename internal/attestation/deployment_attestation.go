package attestation

import (
	"guac-trivy-operator-webhook/internal/attestation/gen/v0/predicates"
	"strings"
	"time"

	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const deploymentPredicateType = "https://in-toto.io/attestation/deployment/v1"

// based on https://github.com/in-toto/attestation/pull/341
type deploymentPredicate struct {
	// The timestamp indicating what time the attestation was created. Required.
	CreationTime *time.Time `json:"creationTime"`
	// List of evidence used to make a decision. Resources may include attestations or other relevant evidence. Optional
	DecisionDetails decisionDetails   `json:"decisionDetails"`
	Scopes          map[string]string `json:"scopes"`
}

type decisionDetails struct {
	Evidence []*spb.ResourceDescriptor `json:"evidence"`
	Policy   []*spb.ResourceDescriptor `json:"policy"`
}

// based on https://github.com/laurentsimon/attestation/blob/feat/deploy/spec/predicates/deployment.md#kubernetes-pod-scope
const (
	kubernetesServiceAccountScope = "kubernetes.io/pod/service_account/v1"
	kubernetesNamespaceScope      = "kubernetes.io/pod/namespace/"
	kubernetesClusterIdScope      = "kubernetes.io/pod/cluster_id/v1"
	kubernetesClusterNameScope    = "kubernetes.io/pod/cluster_name/v1"
)

func Deployment(purl, digest, namespace, clusterName string) *spb.Statement {
	depPredicate := &predicates.Deployment{
		CreationTime: timestamppb.Now(),
		Scopes: map[string]string{
			kubernetesClusterNameScope: clusterName,
			kubernetesNamespaceScope:   namespace,
		},
	}
	marshaledPredicate, err := intoStructPb(depPredicate)
	if err != nil {
		panic(err)
	}

	algo, hash := digestTuple(digest)
	return &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: deploymentPredicateType,
		Predicate:     marshaledPredicate,
		Subject: []*spb.ResourceDescriptor{
			{
				Name: purl,
				Digest: map[string]string{
					algo: hash,
				},
			},
		},
	}
}

func digestTuple(s string) (algo string, hash string) {
	splits := strings.Split(s, ":")
	if len(splits) < 2 {
		algo = "sha256"
		hash = s
	} else {
		algo = splits[0]
		hash = splits[1]
	}
	return
}

func intoStructPb(msg protoreflect.ProtoMessage) (*structpb.Struct, error) {
	jsonData, err := protojson.Marshal(msg)
	if err != nil {
		return nil, err
	}
	s := new(structpb.Struct)
	err = protojson.Unmarshal(jsonData, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
