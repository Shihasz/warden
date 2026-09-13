.PHONY: build test vet lint

build:
	go build -o bin/warden ./cmd/warden

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...
