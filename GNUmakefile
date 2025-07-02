SRCDIRS = cert cmd/stepdance web

.PHONY: build
build:
	go generate web/template.go
	go build ./cmd/stepdance

.PHONY: dev
dev:
	test/setup.sh

.PHONY: test
test:
	go test -failfast -v ./web

.PHONY: fmt
fmt:
	$(foreach d,$(SRCDIRS),go fmt $(d)/*.go;)
