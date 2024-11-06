package main

import (
	"context"
	"flag"
	"fmt"
	"guac-trivy-operator-webhook/internal/api"
	"guac-trivy-operator-webhook/internal/guac"
	"guac-trivy-operator-webhook/internal/k8s/scheme"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	runtime_zap "sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	// address for pubsub connection
	pubsubAddr = flag.String("pubsub-addr", "", "address for pubsub connection")
	// address for blob store
	blobStoreAddr = flag.String("blobstore-addr", "", "address for blob store")
)

func main() {
	opts := runtime_zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := runtime_zap.NewRaw(runtime_zap.UseFlagOptions(&opts))
	zap.ReplaceGlobals(logger)
	defer logger.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	publisher, err := guac.NewPublisher(ctx, *blobStoreAddr, *pubsubAddr)
	if err != nil {
		log.Fatal(err)
	}

	s := api.NewServer(publisher, scheme.Decoder())
	if err := s.Run(ctx); err != nil {
		fmt.Printf("exit reason: %s \n", err)
		os.Exit(1)
	}
}
