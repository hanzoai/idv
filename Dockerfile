# syntax=docker/dockerfile:1
#
# Hanzo IDV — standalone identity-verification service.
#
# Single static Go binary. No CGO, no SQLite, no SDK bundles — the
# service is a thin HTTP shim over the provider/ package. Each
# provider adapter is wired by env at runtime, so the same image
# serves every provider.

FROM golang:1.26.5-alpine AS builder
# go.mod pins the toolchain. The golang base image sets GOTOOLCHAIN=local,
# which turns a `go` directive newer than the image into a hard build
# failure instead of a download.
ENV GOTOOLCHAIN=auto
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o /build/idv \
    ./cmd/idv

# One directory in an empty image: the static binary and the files it reads;
# nothing else is present to run, so nothing else can be run.
FROM alpine:3.22 AS root
RUN apk add --no-cache ca-certificates tzdata

FROM scratch
COPY --from=root /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=root /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /build/idv /app/idv
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/app/idv"]
CMD ["-http", ":8081"]
