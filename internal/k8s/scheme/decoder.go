package scheme

import (
	aquasecurityv1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

func Decoder() runtime.Decoder {
	scheme := runtime.NewScheme()
	scheme.AddKnownTypes(aquasecurityv1alpha1.SchemeGroupVersion,
		&aquasecurityv1alpha1.SbomReport{},
		&aquasecurityv1alpha1.VulnerabilityReport{},
	)
	meta.AddToGroupVersion(scheme, aquasecurityv1alpha1.SchemeGroupVersion)
	return serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder(aquasecurityv1alpha1.SchemeGroupVersion)
}
