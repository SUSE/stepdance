#!/bin/sh -x

podman run -d \
	--rm \
	--userns=keep-id \
	-e DOCKER_STEPCA_INIT_DNS_NAMES=localhost,example.com \
	-e DOCKER_STEPCA_INIT_NAME=TestCA \
	-e DOCKER_STEPCA_INIT_PASSWORD=ThisIsDumb \
	-e DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT=true \
	-p 9000:9000 \
	-v /etc/ssl/ca-bundle.pem:/etc/ssl/certs/ca-certificates.crt:ro \
	-v ./test/stepca:/home/step \
	smallstep/step-ca
