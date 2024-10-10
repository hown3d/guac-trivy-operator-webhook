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
