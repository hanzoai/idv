// Copyright 2024-2026 Lux Partners Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The property under test: ParseWebhook yields a verdict only for a body the
// provider provably sent. Everything else — no signature, a wrong one, a valid
// one over different bytes, or a provider holding no secret to check against —
// is an error and a nil event.
//
// It is driven from a list of every provider this package constructs plus a
// sweep of the factory registry, so a provider added later is under the property
// without anyone remembering to write a case for it.

// signer produces the headers a genuine webhook from a provider would carry.
// nil means the provider has no signature scheme implemented here, and so must
// refuse every body it is handed.
type signer func(body []byte, secret string) map[string]string

// hmacHeader signs the raw body with secret and presents the hex digest under
// the header name the vendor documents.
func hmacHeader(name string) signer {
	return func(body []byte, secret string) map[string]string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		return map[string]string{name: hex.EncodeToString(mac.Sum(nil))}
	}
}

// The header each vendor sends its digest under. One definition per provider,
// shared by the authenticity table here and the parsing tests next door.
var (
	jumioSigned  = hmacHeader("Callback-Sig")
	onfidoSigned = hmacHeader("X-SHA2-Signature")
)

// webhookProviders is every provider constructible in this package, paired with
// how a genuine webhook from it is authenticated.
var webhookProviders = []struct {
	name string
	new  func(secret string) Provider
	sign signer
}{
	{ProviderJumio, func(s string) Provider { return NewJumio(JumioConfig{APISecret: s}) }, jumioSigned},
	{ProviderOnfido, func(s string) Provider { return NewOnfido(OnfidoConfig{WebhookToken: s}) }, onfidoSigned},
	{ProviderPlaid, func(string) Provider { return NewPlaid(PlaidConfig{}) }, nil},
	{ProviderLexisNexis, func(string) Provider { return NewLexisNexis(LexisNexisConfig{}) }, nil},
	{ProviderIntellicheck, func(string) Provider { return NewIntellicheck(IntellicheckConfig{}) }, nil},
	{ProviderIDMerit, func(string) Provider { return NewIDMerit(IDMeritConfig{}) }, nil},
	{ProviderBerbix, func(string) Provider { return NewBerbix(BerbixConfig{}) }, nil},
}

// forgedApproval is a body that would read as an approved identity under every
// provider's own schema, so a provider that decodes it without checking who
// sent it injects a verdict. Refusal is only meaningful against a payload that
// would otherwise be believed.
var forgedApproval = []byte(`{
	"payload": {"resource_type": "check", "action": "check.completed",
		"object": {"id": "forged", "status": "complete", "result": "clear"}},
	"transactionReference": "forged",
	"status": "DONE",
	"verificationStatus": "APPROVED_VERIFIED",
	"webhook_type": "IDENTITY_VERIFICATION",
	"webhook_code": "VERIFICATION_COMPLETED",
	"identity_verification_id": "forged"
}`)

// refuses asserts ParseWebhook rejected the body: an error that reports a
// failure of authenticity, and no event for a caller to act on.
func refuses(t *testing.T, event *WebhookEvent, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted an unauthenticated webhook: provider=%s id=%s status=%s",
			event.Provider, event.VerificationID, event.Status)
	}
	if event != nil {
		t.Fatalf("returned status=%s alongside error %v", event.Status, err)
	}
	if !errors.Is(err, ErrWebhookUnsigned) && !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("error does not report an authenticity failure: %v", err)
	}
}

func TestProviderWebhookAuth(t *testing.T) {
	const secret = "provider-webhook-secret"

	for _, p := range webhookProviders {
		t.Run(p.name, func(t *testing.T) {
			// (a) Nothing presented. Also covers a nil map, which a
			// handler can hand over as readily as an empty one.
			t.Run("no headers", func(t *testing.T) {
				event, err := p.new(secret).ParseWebhook(forgedApproval, map[string]string{})
				refuses(t, event, err)
			})
			t.Run("nil headers", func(t *testing.T) {
				event, err := p.new(secret).ParseWebhook(forgedApproval, nil)
				refuses(t, event, err)
			})

			// (b) A signature presented under every name any provider
			// here uses, both unparsable and well-formed-but-wrong.
			for _, name := range []string{"Callback-Sig", "X-SHA2-Signature"} {
				for label, sig := range map[string]string{
					"garbage":   "not-a-signature",
					"wrong hex": hex.EncodeToString(make([]byte, sha256.Size)),
				} {
					t.Run("bad signature/"+name+"/"+label, func(t *testing.T) {
						event, err := p.new(secret).ParseWebhook(forgedApproval, map[string]string{name: sig})
						refuses(t, event, err)
					})
				}
			}

			if p.sign == nil {
				// No scheme implemented: the refusal is unconditional,
				// so there is no valid signature to tamper with and no
				// secret whose absence could change the answer.
				return
			}

			// (c) A signature genuinely computed under the right key, but
			// over different bytes. Replaying it onto another body must
			// not carry that body's verdict.
			t.Run("tampered body", func(t *testing.T) {
				other := []byte(`{"transactionReference":"other","identity_verification_id":"other"}`)
				event, err := p.new(secret).ParseWebhook(forgedApproval, p.sign(other, secret))
				refuses(t, event, err)
			})

			// (d) Configured with no secret. The signature below is the
			// one any caller can compute under the empty key, which is
			// exactly why an empty secret cannot verify anything.
			t.Run("empty secret", func(t *testing.T) {
				event, err := p.new("").ParseWebhook(forgedApproval, p.sign(forgedApproval, ""))
				refuses(t, event, err)
			})
		})
	}

	// Every provider reachable through configuration, not just those listed
	// above. GetProvider hands out a Provider built from a config map; with
	// no secrets in that map, none of them may return a verdict.
	for _, name := range ListRegistered() {
		t.Run("registry/"+name, func(t *testing.T) {
			p, err := GetProvider(name, nil)
			if err != nil {
				// A factory that refuses to build exposes no webhook
				// surface at all, which is the same refusal earlier.
				return
			}
			event, err := p.ParseWebhook(forgedApproval, map[string]string{})
			refuses(t, event, err)
			event, err = p.ParseWebhook(forgedApproval, map[string]string{
				"Callback-Sig":     "not-a-signature",
				"X-SHA2-Signature": "not-a-signature",
			})
			refuses(t, event, err)
		})
	}
}

// TestOnfidoWebhookVerified proves the guard admits Onfido's own webhook. A
// refusal that is total — a case-sensitive header lookup, say — would satisfy
// every negative case above and still break the integration.
func TestOnfidoWebhookVerified(t *testing.T) {
	const token = "onfido-webhook-token"
	body := []byte(`{"payload":{"resource_type":"check","action":"check.completed",` +
		`"object":{"id":"check-verified","status":"complete","result":"clear","applicant_id":"app-1"}}}`)

	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	// The wire spells it X-SHA2-Signature; net/http canonicalizes that to
	// X-Sha2-Signature before a handler ever sees it, so the header a real
	// deployment presents is the second spelling. Both must verify, as must
	// the uppercase hex a vendor is free to send.
	for _, tc := range []struct{ label, key, sig string }{
		{"wire spelling", "X-SHA2-Signature", sig},
		{"canonicalized", "X-Sha2-Signature", sig},
		{"lowercase", "x-sha2-signature", sig},
		{"uppercase hex", "X-Sha2-Signature", strings.ToUpper(sig)},
	} {
		t.Run(tc.label, func(t *testing.T) {
			o := NewOnfido(OnfidoConfig{WebhookToken: token})
			event, err := o.ParseWebhook(body, map[string]string{tc.key: tc.sig})
			if err != nil {
				t.Fatalf("rejected a correctly signed webhook: %v", err)
			}
			if event.Provider != ProviderOnfido {
				t.Fatalf("provider = %q, want %q", event.Provider, ProviderOnfido)
			}
			if event.Status != StatusApproved {
				t.Fatalf("status = %q, want %q", event.Status, StatusApproved)
			}
			if event.VerificationID != "check-verified" {
				t.Fatalf("verification id = %q, want %q", event.VerificationID, "check-verified")
			}
			if len(event.Checks) != 1 || event.Checks[0].Type != "check" || event.Checks[0].Status != "clear" {
				t.Fatalf("checks = %+v, want one check/clear", event.Checks)
			}
		})
	}
}

// TestJumioWebhookVerified proves the same for Jumio's Callback-Sig.
func TestJumioWebhookVerified(t *testing.T) {
	const secret = "jumio-api-secret"
	body := []byte(`{"transactionReference":"txn-verified","customerInternalReference":"app-2",` +
		`"status":"DONE","verificationStatus":"APPROVED_VERIFIED",` +
		`"identityVerification":{"similarity":"MATCH","validity":true}}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	for _, tc := range []struct{ label, key, sig string }{
		{"wire spelling", "Callback-Sig", sig},
		{"lowercase", "callback-sig", sig},
		{"uppercase hex", "Callback-Sig", strings.ToUpper(sig)},
	} {
		t.Run(tc.label, func(t *testing.T) {
			j := NewJumio(JumioConfig{APISecret: secret})
			event, err := j.ParseWebhook(body, map[string]string{tc.key: tc.sig})
			if err != nil {
				t.Fatalf("rejected a correctly signed webhook: %v", err)
			}
			if event.Provider != ProviderJumio {
				t.Fatalf("provider = %q, want %q", event.Provider, ProviderJumio)
			}
			if event.Status != StatusApproved {
				t.Fatalf("status = %q, want %q", event.Status, StatusApproved)
			}
			if event.VerificationID != "txn-verified" {
				t.Fatalf("verification id = %q, want %q", event.VerificationID, "txn-verified")
			}
			if event.ApplicationID != "app-2" {
				t.Fatalf("application id = %q, want %q", event.ApplicationID, "app-2")
			}
			if len(event.Checks) != 2 || event.Checks[1].Status != "MATCH" {
				t.Fatalf("checks = %+v, want document + facial_similarity/MATCH", event.Checks)
			}
		})
	}
}

func TestHeaderCaseInsensitive(t *testing.T) {
	for _, tc := range []struct {
		label   string
		headers map[string]string
		name    string
		want    string
	}{
		{"exact", map[string]string{"X-SHA2-Signature": "abc"}, "X-SHA2-Signature", "abc"},
		{"canonicalized by net/http", map[string]string{"X-Sha2-Signature": "abc"}, "X-SHA2-Signature", "abc"},
		{"lowercase", map[string]string{"x-sha2-signature": "abc"}, "X-SHA2-Signature", "abc"},
		{"uppercase", map[string]string{"X-SHA2-SIGNATURE": "abc"}, "X-SHA2-Signature", "abc"},
		{"callback sig canonicalized", map[string]string{"Callback-Sig": "abc"}, "callback-sig", "abc"},
		{"absent", map[string]string{"Other": "abc"}, "X-SHA2-Signature", ""},
		{"present but empty", map[string]string{"X-Sha2-Signature": ""}, "X-SHA2-Signature", ""},
		{"nil map", nil, "X-SHA2-Signature", ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got := header(tc.headers, tc.name); got != tc.want {
				t.Fatalf("header(%v, %q) = %q, want %q", tc.headers, tc.name, got, tc.want)
			}
		})
	}
}
