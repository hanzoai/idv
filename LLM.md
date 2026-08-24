# hanzoai/idv — Pluggable Identity Verification

Go module: `hanzo.ai/idv`

7 IDV providers in a single package. Uniform interface — swap providers without changing caller code.

## Providers

Two things decide whether a provider is usable: whether it can read the provider's
verdict, and whether it can prove a webhook came from the provider. A provider that
cannot do the first must not report a decision; one that cannot do the second must
not accept a callback.

| Provider | Verdict | Webhook | Use case |
|----------|---------|---------|----------|
| Jumio | reads it | HMAC `Callback-Sig` | Doc + selfie (EU-strong) |
| Onfido | reads it | HMAC `X-SHA2-Signature` | Doc + selfie match |
| Plaid | reads it via `CheckStatus` | refuses — poll instead | Plaid Identity Verification |
| Intellicheck | starts only; `CheckStatus` refuses | refuses | Doc scan + barcode |
| LexisNexis | not parsed — refuses | refuses (answers synchronously) | Background + ID verification |
| IDMerit | not implemented — refuses | refuses | Doc + SSN verification |
| Berbix | not implemented — refuses | refuses | Doc + selfie (low-cost) |

**Usable end-to-end today: Jumio and Onfido.** Plaid works by polling. The other
four refuse rather than answer, and that is the honest state — LexisNexis and
Intellicheck previously returned `approved` without reading the response (LexisNexis
for any non-4xx reply, and again from `CheckStatus` with no request at all;
Intellicheck for every outcome including a 500 and a rejected document). Anything
gating on those would have admitted an unverified subject, so both now refuse. Wiring
either means parsing its response and mapping it to a status — nothing else.

## Usage

```go
import "hanzo.ai/idv/provider"

// Credentials come from KMS. The API token bills per check and the webhook token
// is what separates a provider's verdict from a stranger's claim, so neither is a
// literal and neither has an env fallback — an absent secret is an error at
// construction, not a provider that runs without one.
p := provider.NewOnfido(provider.OnfidoConfig{
    BaseURL:      "https://api.us.onfido.com",
    APIToken:     mustSecret(ctx, "onfido/api-token"),
    WebhookToken: mustSecret(ctx, "onfido/webhook-token"),
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

## Webhook authenticity

`ParseWebhook` proves the sender before it reads the payload. The two shared
primitives live in `provider/webhook.go`:

- `verifyHMAC(body, secret, signature)` — hex HMAC-SHA256 over the raw body,
  constant-time. An **empty secret is a refusal, not a skip**: an HMAC under a
  known-empty key is computable by anyone, so verifying against one would admit
  forged verdicts from any caller.
- `header(headers, name)` — case-insensitive. `net/http` canonicalizes on the way
  in, so the wire's `X-SHA2-Signature` is keyed `X-Sha2-Signature`; matching the
  vendor's documented spelling exactly finds nothing and every genuine webhook is
  rejected.

`TestProviderWebhookAuth` drives every constructible provider through an unsigned
body, a garbage signature, a valid signature over a *different* body, and an empty
secret. A provider added later inherits the requirement.

Where a provider's signing scheme is not implemented, its webhook refuses and the
verdict is polled through `CheckStatus` instead. That loses a notification, never a
decision.

## Retiring the standalone service

The service (`hanzo-idv`, 2 pods, ns `hanzo`, `ghcr.io/hanzoai/idv`) is superseded by
the same providers imported as a library into the cloud binary, which already has
routing, auth, tenancy and o11y. This module keeps the provider integrations; what
goes away is `cmd/idv`, the second copy of the server around them.

**A route is what puts something in the request path — not a manifest.** The App CR
`infra/k8s/operator/crs/hanzo-idv.yaml` sets `ingress.enabled: false` and explains
why. A `hanzo-idv` **Ingress object for `idv.hanzo.ai` exists in the cluster anyway**
and answers 200 from the public internet: the operator created it before that flag
was set and never pruned it. Deleting files would not have stopped it. Sequence
accordingly, and verify at each step by request, not by manifest:

1. **Now, independent of the fold.** Delete the orphaned `Ingress/hanzo-idv` in ns
   `hanzo`. It contradicts its own CR, and it is what makes an unauthenticated
   identity-verification API reachable from the internet. Confirm with a request to
   `idv.hanzo.ai`, not with a `kubectl get`.
2. Cloud serves `/v1/idv/*` live on `api.hanzo.ai` — reachable through the existing
   priority-1 catch-all, so no `routes.yaml` change. Confirm by request.
3. Point every caller at `api.hanzo.ai/v1/idv/*`. There are none today: a fleet grep
   for `v1/idv` finds no code callers, which is why steps 1 and 2 are safe in either
   order.
4. Provision provider credentials in KMS and select the provider explicitly. Until
   then the deployment runs with `IDV_PROVIDER` empty and every real endpoint answers
   503 — inert, which is why the exposure in step 1 has had no blast radius.
5. Scale `hanzo-idv` to 0 and watch `api.hanzo.ai/v1/idv/*`. Leave the CR in place
   through one full deploy cycle so a rollback is a scale-up.
6. Remove the CR from `infra/k8s/operator/crs/kustomization.yaml`, then delete
   `cmd/idv` here.

Steps 4-6 are gated on cloud serving it live. Nothing above deletes a pod before the
replacement answers.
