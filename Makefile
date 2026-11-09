VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= warden

.PHONY: build test e2e vet lint ci docker-build

build:
	go build -o bin/warden ./cmd/warden

test:
	go test ./... -race

e2e:
	go test -tags e2e -count=1 ./e2e/...

vet:
	go vet -tags e2e ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found on PATH — see .golangci.yml install instructions"; exit 1; }
	golangci-lint run ./...

ci: vet lint test e2e build

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):dev .
