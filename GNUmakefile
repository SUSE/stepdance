SRCDIRS = core cert cmd/stepdance web

.PHONY: build dev test all

build:
	go generate web/template.go
	go build ./cmd/stepdance

dev:
	test/setup.sh

test:
	go test -failfast -v ./web

fmt:
	$(foreach d,$(SRCDIRS),go fmt $(d)/*.go;)

all: fmt build dev test
