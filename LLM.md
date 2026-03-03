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
