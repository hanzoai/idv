package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/idv/provider"
)

// fakeProvider answers deterministically so route tests pin the wire
// format, not a provider's behavior.
type fakeProvider struct{ fail bool }

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) InitiateVerification(_ context.Context, req *provider.VerificationRequest) (*provider.VerificationResponse, error) {
	if f.fail {
		return nil, errors.New("upstream boom")
	}
	return &provider.VerificationResponse{
		VerificationID: "ver_1",
		Provider:       "fake",
		Status:         provider.StatusPending,
		RedirectURL:    "https://x/" + req.ApplicationID,
		CreatedAt:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}, nil
}

func (f *fakeProvider) CheckStatus(_ context.Context, id string) (*provider.VerificationStatusResult, error) {
	if f.fail {
		return nil, errors.New("upstream boom")
	}
	return &provider.VerificationStatusResult{
		VerificationID: id, Provider: "fake", Status: provider.StatusApproved,
	}, nil
}

func (f *fakeProvider) ParseWebhook(_ []byte, headers map[string]string) (*provider.WebhookEvent, error) {
	if f.fail {
		return nil, errors.New("bad webhook")
	}
	return &provider.WebhookEvent{
		Provider:       "fake",
		VerificationID: headers["X-Verification-Id"],
		Status:         provider.StatusApproved,
		ReceivedAt:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}, nil
}

const (
	ctJSON  = "application/json"
	ctPlain = "text/plain; charset=utf-8"
)

type routeCase struct {
	name        string
	prov        provider.Provider
	method      string
	path        string
	body        string
	wantStatus  int
	wantCT      string
	wantBody    string
	wantHeaders map[string]string
}

func (rc routeCase) run(t *testing.T) {
	t.Helper()
	req := httptest.NewRequest(rc.method, rc.path, strings.NewReader(rc.body))
	req.Header.Set("X-Verification-Id", "ver_1")
	res, err := newApp(rc.prov).Fiber().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", rc.method, rc.path, err)
	}
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if res.StatusCode != rc.wantStatus {
		t.Errorf("status = %d, want %d", res.StatusCode, rc.wantStatus)
	}
	if ct := res.Header.Get("Content-Type"); ct != rc.wantCT {
		t.Errorf("Content-Type = %q, want %q", ct, rc.wantCT)
	}
	if string(got) != rc.wantBody {
		t.Errorf("body = %q, want %q", got, rc.wantBody)
	}
	for k, v := range rc.wantHeaders {
		if h := res.Header.Get(k); h != v {
			t.Errorf("header %s = %q, want %q", k, h, v)
		}
	}
}

// TestRoutes pins every path/method/status/body the net/http mux served,
// captured from that mux before the port and unchanged by it.
func TestRoutes(t *testing.T) {
	ok := &fakeProvider{}
	bad := &fakeProvider{fail: true}
	nosniff := map[string]string{"X-Content-Type-Options": "nosniff"}

	const (
		bodyHealth   = "{\"status\":\"ok\"}\n"
		bodyStatusOn = "{\"enabled\":true,\"label\":\"fake\",\"provider\":\"fake\"}\n"
		bodyStatusNo = "{\"enabled\":false,\"label\":\"\",\"provider\":\"\"}\n"
		bodySession  = "{\"verification_id\":\"ver_1\",\"provider\":\"fake\",\"status\":\"pending\"," +
			"\"redirect_url\":\"https://x/app1\",\"created_at\":\"2026-01-02T03:04:05Z\"}\n"
		bodyWebhook = "{\"provider\":\"fake\",\"verification_id\":\"ver_1\",\"status\":\"approved\"," +
			"\"received_at\":\"2026-01-02T03:04:05Z\"}\n"
		bodyNotAllowed = "method not allowed\n"
		bodyDisabled   = "IDV disabled\n"
		bodyNotFound   = "404 page not found\n"
	)

	cases := []routeCase{
		// GET /healthz — the mux served it on every method.
		{"healthz/get", ok, "GET", "/healthz", "", 200, ctJSON, bodyHealth, nil},
		{"healthz/post", ok, "POST", "/healthz", "", 200, ctJSON, bodyHealth, nil},
		{"healthz/no-provider", nil, "GET", "/healthz", "", 200, ctJSON, bodyHealth, nil},

		// GET /v1/idv/status — likewise method-agnostic.
		{"status/get", ok, "GET", "/v1/idv/status", "", 200, ctJSON, bodyStatusOn, nil},
		{"status/post", ok, "POST", "/v1/idv/status", "", 200, ctJSON, bodyStatusOn, nil},
		{"status/no-provider", nil, "GET", "/v1/idv/status", "", 200, ctJSON, bodyStatusNo, nil},

		// POST /v1/idv/sessions
		{"sessions/post", ok, "POST", "/v1/idv/sessions",
			`{"application_id":"app1","email":"a@b.c"}`, 200, ctJSON, bodySession, nil},
		{"sessions/truncated-json", ok, "POST", "/v1/idv/sessions", `{`,
			400, ctPlain, "unexpected EOF\n", nosniff},
		{"sessions/provider-error", bad, "POST", "/v1/idv/sessions", `{}`,
			502, ctPlain, "upstream boom\n", nosniff},
		{"sessions/no-provider", nil, "POST", "/v1/idv/sessions", `{}`,
			503, ctPlain, bodyDisabled, nosniff},
		{"sessions/get", ok, "GET", "/v1/idv/sessions", "", 405, ctPlain, bodyNotAllowed, nosniff},
		{"sessions/put", ok, "PUT", "/v1/idv/sessions", "", 405, ctPlain, bodyNotAllowed, nosniff},
		{"sessions/patch", ok, "PATCH", "/v1/idv/sessions", "", 405, ctPlain, bodyNotAllowed, nosniff},
		{"sessions/delete", ok, "DELETE", "/v1/idv/sessions", "", 405, ctPlain, bodyNotAllowed, nosniff},

		// GET /v1/idv/sessions/{id}
		{"byid/get", ok, "GET", "/v1/idv/sessions/ver_9", "", 200, ctJSON,
			"{\"verification_id\":\"ver_9\",\"provider\":\"fake\",\"status\":\"approved\"}\n", nil},
		{"byid/get-slashed-id", ok, "GET", "/v1/idv/sessions/a/b", "", 200, ctJSON,
			"{\"verification_id\":\"a/b\",\"provider\":\"fake\",\"status\":\"approved\"}\n", nil},
		{"byid/empty-id", ok, "GET", "/v1/idv/sessions/", "",
			400, ctPlain, "session id required\n", nosniff},
		{"byid/provider-error", bad, "GET", "/v1/idv/sessions/ver_9", "",
			502, ctPlain, "upstream boom\n", nosniff},
		{"byid/no-provider", nil, "GET", "/v1/idv/sessions/ver_9", "",
			503, ctPlain, bodyDisabled, nosniff},
		{"byid/post", ok, "POST", "/v1/idv/sessions/ver_9", "", 405, ctPlain, bodyNotAllowed, nosniff},
		{"byid/delete", ok, "DELETE", "/v1/idv/sessions/ver_9", "", 405, ctPlain, bodyNotAllowed, nosniff},

		// POST /v1/idv/webhook/{provider}
		{"webhook/post", ok, "POST", "/v1/idv/webhook/jumio", `{"a":1}`, 200, ctJSON, bodyWebhook, nil},
		{"webhook/no-provider-segment", ok, "POST", "/v1/idv/webhook/", `{}`, 200, ctJSON, bodyWebhook, nil},
		{"webhook/parse-error", bad, "POST", "/v1/idv/webhook/jumio", `{}`,
			400, ctPlain, "bad webhook\n", nosniff},
		{"webhook/no-provider", nil, "POST", "/v1/idv/webhook/jumio", `{}`,
			503, ctPlain, bodyDisabled, nosniff},
		{"webhook/get", ok, "GET", "/v1/idv/webhook/jumio", "", 405, ctPlain, bodyNotAllowed, nosniff},

		// Unrouted.
		{"unknown", ok, "GET", "/nope", "", 404, ctPlain, bodyNotFound, nosniff},
		{"root", ok, "GET", "/", "", 404, ctPlain, bodyNotFound, nosniff},
	}

	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestHeadHealthz — the mux answered HEAD; the body is stripped at the wire.
func TestHeadHealthz(t *testing.T) {
	res, err := newApp(&fakeProvider{}).Fiber().Test(httptest.NewRequest(http.MethodHead, "/healthz", nil))
	if err != nil {
		t.Fatalf("HEAD /healthz: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
}

// TestWebhookHeadersReachProvider proves the webhook handler still hands
// the provider its request headers — how every provider authenticates its
// callback (e.g. Jumio's HMAC signature header).
func TestWebhookHeadersReachProvider(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/idv/webhook/jumio", strings.NewReader(`{}`))
	req.Header.Set("X-Verification-Id", "ver_from_header")
	res, err := newApp(&fakeProvider{}).Fiber().Test(req)
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), `"verification_id":"ver_from_header"`) {
		t.Errorf("provider did not receive request headers; body = %s", body)
	}
}

// TestWebhookSignatureVerification drives a real Jumio provider through the
// route with a real HMAC. The signature lives in the Callback-Sig header, so
// this is what proves the header map the router hands the provider still
// carries net/http's canonical key spelling (RED-14 — a silent break here
// would accept forged webhooks or reject every real one).
func TestWebhookSignatureVerification(t *testing.T) {
	const secret = "test-secret"
	payload := `{"transactionReference":"txn-001","customerInternalReference":"app-100",` +
		`"status":"DONE","verificationStatus":"APPROVED_VERIFIED"}`
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	app := newApp(provider.NewJumio(provider.JumioConfig{APISecret: secret}))

	post := func(t *testing.T, header, value string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/idv/webhook/jumio", strings.NewReader(payload))
		if header != "" {
			req.Header.Set(header, value)
		}
		res, err := app.Fiber().Test(req)
		if err != nil {
			t.Fatalf("POST webhook: %v", err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body)
	}

	t.Run("valid", func(t *testing.T) {
		status, body := post(t, "Callback-Sig", sig)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %q)", status, body)
		}
		for _, want := range []string{`"provider":"jumio"`, `"verification_id":"txn-001"`,
			`"application_id":"app-100"`, `"status":"approved"`} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %s; got %s", want, body)
			}
		}
	})
	t.Run("forged", func(t *testing.T) {
		if status, body := post(t, "Callback-Sig", "deadbeef"); status != 400 ||
			body != "webhook signature mismatch\n" {
			t.Errorf("got %d %q, want 400 %q", status, body, "webhook signature mismatch\n")
		}
	})
	t.Run("missing", func(t *testing.T) {
		if status, body := post(t, "", ""); status != 400 ||
			body != "webhook signature absent or unverifiable\n" {
			t.Errorf("got %d %q, want 400 %q", status, body, "webhook signature absent or unverifiable\n")
		}
	})
}

// TestNonStrictRoutingAliases pins the one behavior the framework changes:
// fiber matches non-canonical paths that net/http's mux answered with a 307
// redirect to (or a 404 for) the canonical form. Every alias below now serves
// the same resource the redirect target served — strictly more permissive, and
// no request that previously got a real answer gets a different one.
func TestNonStrictRoutingAliases(t *testing.T) {
	ok := &fakeProvider{}
	for _, c := range []routeCase{
		// mux: 307 -> /v1/idv/webhook/
		{"webhook/no-trailing-slash", ok, "POST", "/v1/idv/webhook", `{}`, 200, ctJSON,
			"{\"provider\":\"fake\",\"verification_id\":\"ver_1\",\"status\":\"approved\"," +
				"\"received_at\":\"2026-01-02T03:04:05Z\"}\n", nil},
		// mux: 404
		{"status/trailing-slash", ok, "GET", "/v1/idv/status/", "", 200, ctJSON,
			"{\"enabled\":true,\"label\":\"fake\",\"provider\":\"fake\"}\n", nil},
		// mux: 307 -> /v1/idv/sessions/x
		{"byid/double-slash", ok, "GET", "/v1/idv/sessions//x", "", 200, ctJSON,
			"{\"verification_id\":\"/x\",\"provider\":\"fake\",\"status\":\"approved\"}\n", nil},
	} {
		t.Run(c.name, c.run)
	}
}
