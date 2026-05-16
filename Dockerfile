# syntax=docker/dockerfile:1
#
# Hanzo IDV — standalone identity-verification service.
#
# Single static Go binary. No CGO, no SQLite, no SDK bundles — the
# service is a thin HTTP shim over the provider/ package. Each
# provider adapter is wired by env at runtime, so the same image
# serves every provider.

FROM golang:1.26-alpine AS builder
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

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -S hanzo && adduser -S hanzo -G hanzo
WORKDIR /app
COPY --from=builder /build/idv /app/idv
USER hanzo
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8081/healthz || exit 1
ENTRYPOINT ["/app/idv"]
CMD ["-http", ":8081"]
