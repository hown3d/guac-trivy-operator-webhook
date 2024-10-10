package guac

import (
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// Publisher is used to store SBOMs in blob store and publish events to guac event stream
type Publisher struct {
	blobStore *blob.BlobStore
	pubsub    *emitter.EmitterPubSub
}

func NewPublisher(ctx context.Context, blobAddr, pubsubAddr string) (*Publisher, error) {
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