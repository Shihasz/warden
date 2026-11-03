FROM --platform=$BUILDPLATFORM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src

# Copy only the module manifests first, so the dependency download layer
# is reused until go.mod or go.sum actually change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/warden ./cmd/warden

# distroless/static ships CA certificates (warden makes HTTPS calls to
# OSV, deps.dev, CISA, and GitHub) and a nonroot user, but no shell, no
# package manager, and no libc.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/warden /usr/local/bin/warden
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/warden"]
