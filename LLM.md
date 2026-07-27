# hanzoai/idv — Pluggable Identity Verification

Go module: `github.com/hanzoai/idv`

7 IDV providers in a single package. Uniform interface — swap providers without changing caller code.

## Providers

| Provider | Status | Use case |
|----------|--------|----------|
| Jumio | Real impl | Doc + selfie (EU-strong) |
| Onfido | Real impl | Doc + selfie match |
| Plaid | Real impl | Plaid Identity Verification |
| LexisNexis | Real impl | Background + ID verification |
| Intellicheck | Real impl | Doc scan + barcode |
| IDMerit | Scaffold | Doc + SSN verification |
| Berbix | Scaffold | Doc + selfie (low-cost) |

## Usage

```go
import "github.com/hanzoai/idv/provider"

p := provider.NewOnfido(provider.OnfidoConfig{
    BaseURL:  "https://api.us.onfido.com",
    APIToken: os.Getenv("ONFIDO_TOKEN"),
})

resp, err := p.InitiateVerification(ctx, &provider.VerificationRequest{...})
result, err := p.CheckStatus(ctx, resp.VerificationID)
```

## Interface

```go
type Provider interface {
    Name() string
    InitiateVerification(ctx, *VerificationRequest) (*VerificationResponse, error)
    CheckStatus(ctx, verificationID string) (*VerificationStatusResult, error)
    ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error)
}
```

## Service — `cmd/idv`

Standalone binary, one HTTP surface IAM proxies to. Router is
`github.com/zap-proto/zip` (fleet standard); `newApp(provider.Provider)`
builds it, `Listen("http://"+addr)` serves it.

| Method | Path | |
|---|---|---|
| any | `/healthz` | liveness |
| any | `/v1/idv/status` | active provider discovery |
| POST | `/v1/idv/sessions` | initiate a verification |
| GET | `/v1/idv/sessions/{id}` | poll status (`{id}` may contain `/`) |
| POST | `/v1/idv/webhook/{provider}` | webhook ingest |

Wire format predates zip and is pinned byte-for-byte by
`cmd/idv/router_test.go`: JSON responses are `application/json` with a
trailing newline (`json.Encoder`), errors are `text/plain; charset=utf-8`
+ `nosniff` + message + newline (`http.Error`), including the router's own
404/405. `writeJSON` and `plainError` are the only two places that decide
this — do not answer a request any other way.

`/v1/idv/sessions` and the `/v1/idv/sessions/` subtree are distinct routes
(POST-only collection vs. GET-by-id). fiber's non-strict matching collapses
them onto one wildcard, so `sessionByIDHandler` re-splits them on the raw
path. Non-canonical paths the stdlib mux answered with a 307 or 404 now
serve the canonical resource directly — pinned in
`TestNonStrictRoutingAliases`.
