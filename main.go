package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	aquasecurityv1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	// address for pubsub connection
	pubsubAddr = flag.String("pubsub-addr", "", "address for pubsub connection")
	// address for blob store
	blobStoreAddr = flag.String("blobstore-addr", "", "address for blob store")
)

func main() {
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	publisher, err := newPublisher(ctx, *blobStoreAddr, *pubsubAddr)
	if err != nil {
		log.Fatal(err)
	}

	s := &server{
		publisher:   publisher,
		sbomDecoder: sbomDecoder(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sbom", errorMiddleware(s.sbomHandler))
	httpServer := &http.Server{
		Addr:    ":9999",
		Handler: mux,
	}
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		log.Println("serving on :9999")
		return httpServer.ListenAndServe()
	})
	g.Go(func() error {
		<-gCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(ctx)
	})
	if err := g.Wait(); err != nil {
		fmt.Printf("exit reason: %s \n", err)
	}
}

type handle func(http.ResponseWriter, *http.Request) error

func errorMiddleware(f handle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err != nil {
			log.Printf("error in sbom handler: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
	}
}

type server struct {
	publisher   *Publisher
	sbomDecoder runtime.Decoder
}

func sbomDecoder() runtime.Decoder {
	scheme := runtime.NewScheme()
	scheme.AddKnownTypes(aquasecurityv1alpha1.SchemeGroupVersion,
		&aquasecurityv1alpha1.SbomReport{},
	)
	meta.AddToGroupVersion(scheme, aquasecurityv1alpha1.SchemeGroupVersion)
	return serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
}

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

func (s *server) sbomHandler(w http.ResponseWriter, r *http.Request) error {
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

// Publisher is used to store SBOMs in blob store and publish events to guac event stream
type Publisher struct {
	blobStore *blob.BlobStore
	pubsub    *emitter.EmitterPubSub
}

func newPublisher(ctx context.Context, blobAddr, pubsubAddr string) (*Publisher, error) {
	// initialize blob store
	blobStore, err := blob.NewBlobStore(ctx, blobAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to blob store: %w", err)
	}

	var pubsub *emitter.EmitterPubSub
	if strings.HasPrefix(pubsubAddr, "nats://") {
		// initialize jetstream
		// TODO: pass in credentials file for NATS secure login
		jetStream := emitter.NewJetStream(pubsubAddr, "", "")
		if err := jetStream.JetStreamInit(ctx); err != nil {
			return nil, fmt.Errorf("jetStream initialization failed with error: %v", err)
		}
		defer jetStream.Close()
	}
	// initialize pubsub
	pubsub = emitter.NewEmitterPubSub(ctx, pubsubAddr)

	return &Publisher{
		blobStore: blobStore,
		pubsub:    pubsub,
	}, nil
}

func (p *Publisher) Publish(ctx context.Context, doc *processor.Document) error {
	return collector.Publish(ctx, doc, p.blobStore, p.pubsub, true)
}

// type Processor struct {
// 	sboms chan []byte
// }
//
// // RetrieveArtifacts implements collector.Collector.
// func (s *Processor) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
// 	blob := <-s.sboms
// 	doc := &processor.Document{
// 		Blob:   blob,
// 		Type:   processor.DocumentUnknown,
// 		Format: processor.FormatUnknown,
// 		SourceInformation: processor.SourceInformation{
// 			Collector:   string("TODO"),
// 			Source:      "TODO",
// 			DocumentRef: events.GetDocRef(blob),
// 		},
// 	}
// 	docChannel <- doc
// 	return nil
// }
//
// // Type implements collector.Collector.
// func (s *Processor) Type() string {
// 	return "TODO"
// }
//
// var _ collector.Collector = (*Processor)(nil)
