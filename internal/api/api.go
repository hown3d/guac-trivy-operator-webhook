package api

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime"
)

type Server struct {
	httpServer *http.Server
	publisher  DocPublisher
	decoder    runtime.Decoder
	logger     *zap.Logger
}

type DocPublisher interface {
	Publish(ctx context.Context, doc *processor.Document) error
}

func NewServer(publisher DocPublisher, decoder runtime.Decoder) *Server {
	s := &Server{
		publisher: publisher,
		decoder:   decoder,
		logger:    zap.L(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /report", errorMiddleware(s.reportHandler))
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
