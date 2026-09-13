.PHONY: build test vet lint ci

build:
	go build -o bin/warden ./cmd/warden

test:
	go test ./... -race

vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found on PATH — see .golangci.yml install instructions"; exit 1; }
	golangci-lint run ./...

ci: vet lint test build
