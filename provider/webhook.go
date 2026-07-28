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
)

// A webhook carries a verdict about a person's identity, and it arrives on an
// endpoint the provider reaches from the public internet. Authenticity is
// therefore the FIRST thing every ParseWebhook establishes: decode only what the
// provider provably sent. The schemes differ per provider (each vendor picked
// one), so the two primitives below are shared and the policy is uniform —
// unproven authenticity is an error, never a verdict.
//
// providerWebhookAuth in webhook_test.go asserts this property for every
// registered provider, so a provider added later inherits the requirement.

// ErrWebhookUnsigned reports a webhook whose authenticity could not be
// established: no signature was presented, or the receiving provider holds no
// secret to check one against. Both are refusals — an unverifiable verdict is
// indistinguishable from a forged one.
var ErrWebhookUnsigned = errors.New("webhook signature absent or unverifiable")

// ErrWebhookSignature reports a webhook whose signature did not match the body.
var ErrWebhookSignature = errors.New("webhook signature mismatch")

// header reads a header case-insensitively.
//
// net/http canonicalizes on the way in (textproto.CanonicalMIMEHeaderKey), so
// the wire's `X-SHA2-Signature` is keyed `X-Sha2-Signature` in the map a handler
// builds from r.Header. Matching the vendor's documented spelling exactly finds
// nothing; the lookup has to be case-insensitive or the signature silently reads
// as absent (which fails closed, but rejects every genuine webhook too).
func header(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok && v != "" {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// verifyHMAC checks a hex-encoded HMAC-SHA256 of the raw body under secret.
//
// An empty secret is a refusal, not a skip: HMAC under a known-empty key is
// computable by anyone, so "verifying" against it would admit forged verdicts
// from any caller. The signature is compared after hex-decoding — the encoding
// is not part of the claim, so a vendor that sends uppercase hex still verifies,
// and the comparison stays constant-time over the raw digest.
func verifyHMAC(body []byte, secret, signature string) error {
	if secret == "" || signature == "" {
		return ErrWebhookUnsigned
	}
	got, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return ErrWebhookSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return ErrWebhookSignature
	}
	return nil
}
