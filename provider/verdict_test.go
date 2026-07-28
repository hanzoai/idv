// Copyright 2024-2026 Lux Partners Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A verdict is the provider's answer, never ours. Two properties enforce that, and
// both are stated per METHOD rather than per provider — an integration can have a
// correct Start and an unimplemented status read, and Intellicheck does.
//
// The providers are pointed at a server that ANSWERS. An unreachable base URL would
// make these assertions pass for the wrong reason — the transport error rather than
// the refusal — leaving a synthesized approval downstream of a return the test never
// reaches. That is how the first version of this file scored a mutant as caught
// while guarding nothing.

// answering returns a server that replies 200 with a body, so every code path runs
// to the point where a verdict would be invented.
func answering(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"whatever the provider actually said"}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// A verification that has just been created cannot already be decided — the subject
// has not acted yet. LexisNexis returned "approved" straight out of
// InitiateVerification for any non-4xx reply, which is a pass the provider never
// gave; a caller gating on it would admit an unverified subject.
func TestInitiateIsNeverApproved(t *testing.T) {
	ctx := context.Background()
	srv := answering(t)
	req := &VerificationRequest{GivenName: "Ada", FamilyName: "Lovelace", Email: "ada@example.test"}

	for name, p := range allProviders(srv.URL) {
		t.Run(name, func(t *testing.T) {
			resp, err := p.InitiateVerification(ctx, req)
			if err != nil {
				return // a refusal is an acceptable answer; a fabricated pass is not
			}
			if resp == nil {
				t.Fatalf("%s returned no error and no response", name)
			}
			if resp.Status == StatusApproved {
				t.Fatalf("%s InitiateVerification returned %q for a verification the subject has not acted on", name, resp.Status)
			}
		})
	}
}

// An integration that does not parse the provider's response cannot report what the
// provider decided, so its status read must refuse. LexisNexis answered "approved"
// with no request at all; Intellicheck issued the request and then ignored the
// response, including its status code, so a 500 and a rejected document both read as
// approved.
func TestUnreadCheckRefuses(t *testing.T) {
	ctx := context.Background()
	srv := answering(t)

	unread := []string{ProviderLexisNexis, ProviderIntellicheck, ProviderIDMerit, ProviderBerbix}
	all := allProviders(srv.URL)
	for _, name := range unread {
		t.Run(name, func(t *testing.T) {
			p, ok := all[name]
			if !ok {
				t.Fatalf("%s is not constructible — the table drifted", name)
			}
			res, err := p.CheckStatus(ctx, "any-id")
			if err == nil {
				t.Fatalf("%s CheckStatus reported %+v without parsing a verdict", name, res)
			}
			if res != nil && res.Status == StatusApproved {
				t.Fatalf("%s CheckStatus synthesized an approval", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("%s refusal does not name the provider, so an operator cannot tell it apart from a network fault: %v", name, err)
			}
		})
	}
}

// allProviders constructs every provider in this package against base. Driving the
// tests from one constructor table means a provider added later inherits both
// properties instead of quietly opting out of them.
func allProviders(base string) map[string]Provider {
	return map[string]Provider{
		ProviderJumio:        NewJumio(JumioConfig{BaseURL: base, APIToken: "t", APISecret: "s"}),
		ProviderOnfido:       NewOnfido(OnfidoConfig{BaseURL: base, APIToken: "t", WebhookToken: "w"}),
		ProviderPlaid:        NewPlaid(PlaidConfig{BaseURL: base, ClientID: "c", Secret: "s"}),
		ProviderLexisNexis:   NewLexisNexis(LexisNexisConfig{BaseURL: base}),
		ProviderIntellicheck: NewIntellicheck(IntellicheckConfig{BaseURL: base}),
		ProviderIDMerit:      NewIDMerit(IDMeritConfig{BaseURL: base}),
		ProviderBerbix:       NewBerbix(BerbixConfig{BaseURL: base}),
	}
}
