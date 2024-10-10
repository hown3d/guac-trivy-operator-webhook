package api

import (
	"context"
	"guac-trivy-operator-webhook/internal/guac"
	"log"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime"
)

type Server struct {
	httpServer  *http.Server
	publisher   *guac.Publisher
	sbomDecoder runtime.Decoder
}

func NewServer(publisher *guac.Publisher, decoder runtime.Decoder) *Server {
	s := &Server{
		publisher:   publisher,
		sbomDecoder: decoder,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sbom", errorMiddleware(s.sbomHandler))
	httpServer := &http.Server{
		Addr:    ":9999",
		Handler: mux,
	}
	s.httpServer = httpServer
	return s
}

// Run blocks
func (s *Server) Run(ctx context.Context) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		log.Println("serving on :9999")
		return s.httpServer.ListenAndServe()
	})
	g.Go(func() error {
		<-gCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	})
	return g.Wait()
}
