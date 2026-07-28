// Copyright 2024-2026 Lux Partners Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// Webhook payloads are signed with hmacHeader from webhook_test.go: the tests
// below cover decoding and status mapping, which they only reach through the
// authenticity guard, so they present the signature a real provider would.

// --- Provider registry ---

func TestGetProviderJumio(t *testing.T) {
	p, err := GetProvider("jumio", map[string]string{
		"api_token":  "tok",
		"api_secret": "sec",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "jumio" {
		t.Fatalf("expected 'jumio', got %q", p.Name())
	}
}

func TestGetProviderOnfido(t *testing.T) {
	p, err := GetProvider("onfido", map[string]string{
		"api_token": "tok",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "onfido" {
		t.Fatalf("expected 'onfido', got %q", p.Name())
	}
}

func TestGetProviderPlaid(t *testing.T) {
	p, err := GetProvider("plaid", map[string]string{
		"client_id": "cid",
		"secret":    "sec",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "plaid" {
		t.Fatalf("expected 'plaid', got %q", p.Name())
	}
}

func TestGetProviderUnknown(t *testing.T) {
	_, err := GetProvider("unknown", nil)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestListRegistered(t *testing.T) {
	names := ListRegistered()
	if len(names) < 3 {
		t.Fatalf("expected at least 3 registered factories, got %d", len(names))
	}
	sort.Strings(names)
	expected := []string{"jumio", "onfido", "plaid"}
	for _, exp := range expected {
		found := false
		for _, n := range names {
			if n == exp {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected %q in registered list", exp)
		}
	}
}

// --- Jumio ---

func TestJumioName(t *testing.T) {
	j := NewJumio(JumioConfig{})
	if j.Name() != "jumio" {
		t.Fatalf("expected 'jumio', got %q", j.Name())
	}
}

func TestJumioDefaultBaseURL(t *testing.T) {
	j := NewJumio(JumioConfig{})
	if j.cfg.BaseURL != JumioSandboxv4 {
		t.Fatalf("expected sandbox URL, got %q", j.cfg.BaseURL)
	}
}

func TestJumioCustomBaseURL(t *testing.T) {
	j := NewJumio(JumioConfig{BaseURL: "https://custom.example.com"})
	if j.cfg.BaseURL != "https://custom.example.com" {
		t.Fatalf("expected custom URL, got %q", j.cfg.BaseURL)
	}
}

func TestJumioInitiateVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/initiate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"transactionReference": "txn-test-001",
			"redirectUrl":          "https://verify.jumio.com/abc",
		})
	}))
	defer server.Close()

	j := NewJumio(JumioConfig{
		BaseURL:   server.URL,
		APIToken:  "test-token",
		APISecret: "test-secret",
	})

	resp, err := j.InitiateVerification(context.Background(), &VerificationRequest{
		ApplicationID: "app-1",
		Email:         "test@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.VerificationID != "txn-test-001" {
		t.Fatalf("expected 'txn-test-001', got %q", resp.VerificationID)
	}
	if resp.Provider != ProviderJumio {
		t.Fatalf("expected 'jumio', got %q", resp.Provider)
	}
	if resp.RedirectURL != "https://verify.jumio.com/abc" {
		t.Fatalf("unexpected redirect URL: %q", resp.RedirectURL)
	}
}

func TestJumioCheckStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transactions/txn-001" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":             "DONE",
			"verificationStatus": "APPROVED_VERIFIED",
		})
	}))
	defer server.Close()

	j := NewJumio(JumioConfig{BaseURL: server.URL})
	result, err := j.CheckStatus(context.Background(), "txn-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
}

func TestJumioParseWebhookApproved(t *testing.T) {
	secret := "test-secret"
	j := NewJumio(JumioConfig{APISecret: secret})
	payload := []byte(`{
		"transactionReference": "txn-001",
		"customerInternalReference": "app-100",
		"status": "DONE",
		"verificationStatus": "APPROVED_VERIFIED",
		"identityVerification": {"similarity": "MATCH", "validity": true}
	}`)

	event, err := j.ParseWebhook(payload, jumioSigned(payload, secret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Status != StatusApproved {
		t.Fatalf("expected approved, got %q", event.Status)
	}
	if event.VerificationID != "txn-001" {
		t.Fatalf("expected 'txn-001', got %q", event.VerificationID)
	}
	if event.ApplicationID != "app-100" {
		t.Fatalf("expected 'app-100', got %q", event.ApplicationID)
	}
	if len(event.Checks) < 2 {
		t.Fatal("expected at least 2 checks")
	}
	if event.Checks[0].Type != "document" || event.Checks[0].Status != "clear" {
		t.Fatalf("expected document/clear, got %s/%s", event.Checks[0].Type, event.Checks[0].Status)
	}
	if event.Checks[1].Type != "facial_similarity" || event.Checks[1].Status != "MATCH" {
		t.Fatalf("expected facial_similarity/MATCH, got %s/%s", event.Checks[1].Type, event.Checks[1].Status)
	}
}

func TestJumioParseWebhookDeclined(t *testing.T) {
	cases := []string{
		"DENIED_FRAUD",
		"DENIED_UNSUPPORTED_ID_TYPE",
		"DENIED_UNSUPPORTED_ID_COUNTRY",
		"ERROR_NOT_READABLE_ID",
		"NO_ID_UPLOADED",
	}

	secret := "decline-secret"
	j := NewJumio(JumioConfig{APISecret: secret})
	for _, vs := range cases {
		t.Run(vs, func(t *testing.T) {
			payload := []byte(fmt.Sprintf(`{
				"transactionReference": "txn-dec",
				"customerInternalReference": "app-dec",
				"status": "FAILED",
				"verificationStatus": %q
			}`, vs))
			event, err := j.ParseWebhook(payload, jumioSigned(payload, secret))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event.Status != StatusDeclined {
				t.Fatalf("expected declined for %s, got %q", vs, event.Status)
			}
		})
	}
}

func TestJumioParseWebhookPending(t *testing.T) {
	secret := "pending-secret"
	j := NewJumio(JumioConfig{APISecret: secret})
	payload := []byte(`{
		"transactionReference": "txn-p",
		"customerInternalReference": "app-p",
		"status": "PENDING",
		"verificationStatus": "UNKNOWN"
	}`)
	event, err := j.ParseWebhook(payload, jumioSigned(payload, secret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Status != StatusPending {
		t.Fatalf("expected pending, got %q", event.Status)
	}
}

func TestJumioParseWebhookInvalidJSON(t *testing.T) {
	secret := "json-secret"
	j := NewJumio(JumioConfig{APISecret: secret})
	body := []byte(`not-json`)
	_, err := j.ParseWebhook(body, jumioSigned(body, secret))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// Signature acceptance and rejection live in webhook_test.go, which asserts them
// over every provider rather than Jumio alone.

// --- Onfido ---

func TestOnfidoName(t *testing.T) {
	o := NewOnfido(OnfidoConfig{})
	if o.Name() != "onfido" {
		t.Fatalf("expected 'onfido', got %q", o.Name())
	}
}

func TestOnfidoDefaultBaseURL(t *testing.T) {
	o := NewOnfido(OnfidoConfig{})
	if o.cfg.BaseURL != OnfidoSandboxAPIv3 {
		t.Fatalf("expected sandbox URL, got %q", o.cfg.BaseURL)
	}
}

func TestOnfidoCheckStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"id":     "check-001",
			"status": "complete",
			"result": "clear",
		})
	}))
	defer server.Close()

	o := NewOnfido(OnfidoConfig{BaseURL: server.URL})
	result, err := o.CheckStatus(context.Background(), "check-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
}

func TestOnfidoParseWebhookClear(t *testing.T) {
	token := "clear-token"
	o := NewOnfido(OnfidoConfig{WebhookToken: token})
	payload := []byte(`{
		"payload": {
			"resource_type": "check",
			"action": "check.completed",
			"object": {
				"id": "check-001",
				"status": "complete",
				"result": "clear",
				"applicant_id": "app-001"
			}
		}
	}`)
	event, err := o.ParseWebhook(payload, onfidoSigned(payload, token))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Status != StatusApproved {
		t.Fatalf("expected approved, got %q", event.Status)
	}
	if event.VerificationID != "check-001" {
		t.Fatalf("expected 'check-001', got %q", event.VerificationID)
	}
}

func TestOnfidoParseWebhookConsider(t *testing.T) {
	token := "consider-token"
	o := NewOnfido(OnfidoConfig{WebhookToken: token})
	payload := []byte(`{
		"payload": {
			"resource_type": "check",
			"action": "check.completed",
			"object": {
				"id": "check-002",
				"status": "complete",
				"result": "consider"
			}
		}
	}`)
	event, err := o.ParseWebhook(payload, onfidoSigned(payload, token))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Status != StatusDeclined {
		t.Fatalf("expected declined, got %q", event.Status)
	}
}

func TestOnfidoParseWebhookInvalidJSON(t *testing.T) {
	token := "json-token"
	o := NewOnfido(OnfidoConfig{WebhookToken: token})
	body := []byte(`{bad`)
	_, err := o.ParseWebhook(body, onfidoSigned(body, token))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- Plaid ---

func TestPlaidName(t *testing.T) {
	p := NewPlaid(PlaidConfig{})
	if p.Name() != "plaid" {
		t.Fatalf("expected 'plaid', got %q", p.Name())
	}
}

func TestPlaidDefaultBaseURL(t *testing.T) {
	p := NewPlaid(PlaidConfig{})
	if p.cfg.BaseURL != PlaidSandbox {
		t.Fatalf("expected sandbox URL, got %q", p.cfg.BaseURL)
	}
}

// TestPlaidCheckStatus covers polling, which is the only path a Plaid verdict
// takes: every status Plaid reports has to map through here.
func TestPlaidCheckStatus(t *testing.T) {
	for _, tc := range []struct {
		reported string
		want     VerificationStatus
	}{
		{"success", StatusApproved},
		{"failed", StatusDeclined},
		{"expired", StatusExpired},
		{"active", StatusPending},
	} {
		t.Run(tc.reported, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status": tc.reported,
					"steps": map[string]string{
						"verify_sms":               tc.reported,
						"documentary_verification": tc.reported,
						"selfie_check":             tc.reported,
						"kyc_check":                tc.reported,
						"risk_check":               tc.reported,
					},
				})
			}))
			defer server.Close()

			p := NewPlaid(PlaidConfig{BaseURL: server.URL, ClientID: "test", Secret: "test"})
			result, err := p.CheckStatus(context.Background(), "idv-001")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Status != tc.want {
				t.Fatalf("status = %q, want %q", result.Status, tc.want)
			}
			if len(result.Checks) != 4 {
				t.Fatalf("expected 4 checks, got %d", len(result.Checks))
			}
		})
	}
}

// TestPlaidWebhookPollInstead states the policy: Plaid pushes a verdict this
// client cannot authenticate, so the refusal names the path that works.
func TestPlaidWebhookPollInstead(t *testing.T) {
	p := NewPlaid(PlaidConfig{ClientID: "cid", Secret: "sec"})
	payload := []byte(`{
		"webhook_type": "IDENTITY_VERIFICATION",
		"webhook_code": "VERIFICATION_COMPLETED",
		"identity_verification_id": "idv-done-001"
	}`)
	event, err := p.ParseWebhook(payload, map[string]string{"Plaid-Verification": "eyJhbGciOiJFUzI1NiJ9.e30.sig"})
	refuses(t, event, err)
	if !strings.Contains(err.Error(), "CheckStatus") {
		t.Fatalf("refusal should point at the path that works, got: %v", err)
	}
}

// --- Status constants ---

func TestStatusConstants(t *testing.T) {
	if StatusPending != "pending" {
		t.Fatalf("StatusPending = %q", StatusPending)
	}
	if StatusApproved != "approved" {
		t.Fatalf("StatusApproved = %q", StatusApproved)
	}
	if StatusDeclined != "declined" {
		t.Fatalf("StatusDeclined = %q", StatusDeclined)
	}
	if StatusExpired != "expired" {
		t.Fatalf("StatusExpired = %q", StatusExpired)
	}
	if StatusError != "error" {
		t.Fatalf("StatusError = %q", StatusError)
	}
}

func TestNewID(t *testing.T) {
	id1 := newID()
	id2 := newID()
	if id1 == id2 {
		t.Fatal("expected unique IDs")
	}
	if len(id1) != 32 {
		t.Fatalf("expected 32-char hex ID, got %d chars", len(id1))
	}
}

// --- Provider registry: additional coverage ---

func TestRegisterFactoryOverwrite(t *testing.T) {
	// Register a custom factory, then overwrite it
	customCalled := false
	RegisterFactory("custom-test-provider", func(config map[string]string) (Provider, error) {
		customCalled = true
		return NewJumio(JumioConfig{BaseURL: config["base_url"]}), nil
	})

	p, err := GetProvider("custom-test-provider", map[string]string{"base_url": "https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !customCalled {
		t.Fatal("custom factory should have been called")
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}

	// Overwrite with a different factory
	overwriteCalled := false
	RegisterFactory("custom-test-provider", func(config map[string]string) (Provider, error) {
		overwriteCalled = true
		return NewOnfido(OnfidoConfig{}), nil
	})

	p2, err := GetProvider("custom-test-provider", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !overwriteCalled {
		t.Fatal("overwritten factory should have been called")
	}
	if p2.Name() != "onfido" {
		t.Fatalf("expected onfido from overwritten factory, got %q", p2.Name())
	}

	// Clean up: re-register nothing to avoid polluting other tests
	// (not strictly necessary since test factories don't conflict with init ones)
}

func TestGetProviderWithNilConfig(t *testing.T) {
	// All init-registered providers should handle nil config gracefully
	for _, name := range []string{"jumio", "onfido", "plaid"} {
		p, err := GetProvider(name, nil)
		if err != nil {
			t.Fatalf("GetProvider(%q, nil): unexpected error: %v", name, err)
		}
		if p.Name() != name {
			t.Fatalf("expected %q, got %q", name, p.Name())
		}
	}
}

func TestGetProviderErrorMessage(t *testing.T) {
	_, err := GetProvider("nonexistent-provider-xyz", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "nonexistent-provider-xyz") {
		t.Fatalf("error should mention provider name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("error should say 'not registered', got: %v", err)
	}
}

func TestRegisterFactoryReturningError(t *testing.T) {
	RegisterFactory("failing-factory", func(config map[string]string) (Provider, error) {
		return nil, fmt.Errorf("config validation failed: missing api_key")
	})

	_, err := GetProvider("failing-factory", nil)
	if err == nil {
		t.Fatal("expected error from failing factory")
	}
	if !strings.Contains(err.Error(), "config validation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Verification request field coverage ---

func TestVerificationRequestFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"transactionReference": "txn-fields-001",
			"redirectUrl":          "https://verify.example.com/test",
		})
	}))
	defer server.Close()

	j := NewJumio(JumioConfig{
		BaseURL:   server.URL,
		APIToken:  "tok",
		APISecret: "sec",
	})

	// Test with all optional fields populated
	resp, err := j.InitiateVerification(context.Background(), &VerificationRequest{
		ApplicationID: "app-full",
		GivenName:     "John",
		FamilyName:    "Doe",
		DateOfBirth:   "1990-01-15",
		Email:         "john@example.com",
		Phone:         "+1-555-0100",
		Country:       "US",
		IPAddress:     "192.168.1.1",
		Street:        []string{"123 Main St", "Apt 4"},
		City:          "San Francisco",
		State:         "CA",
		PostalCode:    "94102",
		TaxID:         "123-45-6789",
		TaxIDType:     "ssn",
		DocumentType:  "passport",
		DocumentID:    "P123456",
		Provider:      "jumio",
		Workflow:      "wf-001",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.VerificationID != "txn-fields-001" {
		t.Fatalf("expected txn-fields-001, got %q", resp.VerificationID)
	}
	if resp.Status != StatusPending {
		t.Fatalf("expected pending, got %q", resp.Status)
	}
}

// --- Jumio edge cases ---

func TestJumioInitiateVerificationHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	j := NewJumio(JumioConfig{BaseURL: server.URL, APIToken: "tok", APISecret: "sec"})
	_, err := j.InitiateVerification(context.Background(), &VerificationRequest{
		ApplicationID: "app-err",
		Email:         "err@example.com",
	})
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestJumioCheckStatusHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	j := NewJumio(JumioConfig{BaseURL: server.URL})
	_, err := j.CheckStatus(context.Background(), "txn-notfound")
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

// --- Onfido edge cases ---

func TestOnfidoInitiateVerification(t *testing.T) {
	// Mock: create applicant then create check
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "checks") {
			json.NewEncoder(w).Encode(map[string]string{
				"id":     "chk-001",
				"status": "in_progress",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]string{
				"id": "applicant-001",
			})
		}
	}))
	defer server.Close()

	o := NewOnfido(OnfidoConfig{BaseURL: server.URL, APIToken: "tok"})
	resp, err := o.InitiateVerification(context.Background(), &VerificationRequest{
		ApplicationID: "app-onfido",
		GivenName:     "Jane",
		FamilyName:    "Doe",
		Email:         "jane@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Provider != ProviderOnfido {
		t.Fatalf("expected onfido, got %q", resp.Provider)
	}
	if resp.Status != StatusPending {
		t.Fatalf("expected pending, got %q", resp.Status)
	}
}

// --- Plaid edge cases ---

func TestPlaidInitiateVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":            "idv-plaid-001",
			"shareable_url": "https://plaid.com/verify/abc",
			"status":        "active",
		})
	}))
	defer server.Close()

	p := NewPlaid(PlaidConfig{BaseURL: server.URL, ClientID: "cid", Secret: "sec"})
	resp, err := p.InitiateVerification(context.Background(), &VerificationRequest{
		ApplicationID: "app-plaid",
		GivenName:     "Bob",
		FamilyName:    "Smith",
		Email:         "bob@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Provider != ProviderPlaid {
		t.Fatalf("expected plaid, got %q", resp.Provider)
	}
}

// --- Provider constant coverage ---

func TestProviderNameConstants(t *testing.T) {
	if ProviderJumio != "jumio" {
		t.Fatalf("ProviderJumio = %q", ProviderJumio)
	}
	if ProviderOnfido != "onfido" {
		t.Fatalf("ProviderOnfido = %q", ProviderOnfido)
	}
	if ProviderPlaid != "plaid" {
		t.Fatalf("ProviderPlaid = %q", ProviderPlaid)
	}
}

func TestListRegisteredContainsAllInit(t *testing.T) {
	names := ListRegistered()
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}

	for _, expected := range []string{ProviderJumio, ProviderOnfido, ProviderPlaid} {
		if !nameSet[expected] {
			t.Errorf("ListRegistered() missing %q", expected)
		}
	}
}
