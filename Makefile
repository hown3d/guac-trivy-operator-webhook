IMAGE_REF := ghcr.io/stackitcloud/guac-trivy-operator-webhook
PLATFORM := arm64
	IN_TOTO_ATTESTATION_DIR := $(shell go list -m -f "{{.Dir}}" github.com/in-toto/attestation)

container:
	KO_DOCKER_REPO=$(IMAGE_REF) ko build -L --bare --platform linux/$(PLATFORM) ./

start-in-guac:
	docker run --network guac_frontend -v guac_blobstore:/blobstore -p 9999:9999 --user 0:0 $(IMAGE_REF) -blobstore-addr file:///blobstore?no_tmp_dir=true -pubsub-addr nats://nats:4222 

setup-vendored-protos:
	ln -s $(IN_TOTO_ATTESTATION_DIR)/protos/in_toto_attestation ./internal/attestation/proto/in_toto_attestation
