// Command idv is the standalone Hanzo IDV service binary.
//
// Exposes one HTTP surface (/v1/idv/*) that IAM proxies to for the
// biometric step of the onboarding pipeline. Decomplected from IAM:
// this service knows the providers (Jumio / Onfido / Plaid / …); IAM
// knows the user identity. Neither imports the other's library.
//
// Provider selection via env:
//
//   IDV_PROVIDER=jumio|onfido|plaid|lexisnexis|intellicheck|
//                idmerit|berbix|securegate|onyxplus
//   IDV_BASE_URL=…               (optional region override)
//   IDV_API_TOKEN=…              (required for non-noop)
//   IDV_WEBHOOK_SECRET=…         (for provider webhooks)
//
// Endpoints:
//
//   GET  /v1/idv/status                   active provider discovery
//   POST /v1/idv/sessions                 initiate a verification
//   GET  /v1/idv/sessions/{id}            poll verification status
//   POST /v1/idv/webhook/{provider}       provider webhook ingest
//   GET  /healthz                         liveness
//
// Run:
//
//   IDV_PROVIDER=onfido IDV_API_TOKEN=… idv -http :8081
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hanzoai/idv/provider"
)

func main() {
	addr := flag.String("http", ":8081", "listen address")
	flag.Parse()

	prov, err := loadProviderFromEnv()
	if err != nil {
		log.Fatalf("idv: %v", err)
	}
	if prov != nil {
		log.Printf("idv: provider=%s", prov.Name())
	} else {
		log.Printf("idv: disabled (IDV_PROVIDER unset)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/v1/idv/status", statusHandler(prov))
	mux.HandleFunc("/v1/idv/sessions", sessionsHandler(prov))
	mux.HandleFunc("/v1/idv/sessions/", sessionByIDHandler(prov))
	mux.HandleFunc("/v1/idv/webhook/", webhookHandler(prov))

	log.Printf("idv: listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func loadProviderFromEnv() (provider.Provider, error) {
	name := strings.ToLower(os.Getenv("IDV_PROVIDER"))
	if name == "" || name == "none" || name == "noop" {
		return nil, nil
	}
	baseURL := os.Getenv("IDV_BASE_URL")
	apiToken := os.Getenv("IDV_API_TOKEN")
	webhookSecret := os.Getenv("IDV_WEBHOOK_SECRET")

	// Explicit constructors keep the wire path straight — no
	// registry indirection that hides which provider is wired.
	switch name {
	case provider.ProviderJumio:
		return provider.NewJumio(provider.JumioConfig{
			BaseURL: baseURL, APIToken: apiToken,
		}), nil
	case provider.ProviderOnfido:
		return provider.NewOnfido(provider.OnfidoConfig{
			BaseURL: baseURL, APIToken: apiToken, WebhookToken: webhookSecret,
		}), nil
	case provider.ProviderPlaid:
		return provider.NewPlaid(provider.PlaidConfig{
			BaseURL: baseURL, ClientID: apiToken,
		}), nil
	case provider.ProviderSecuregate:
		return provider.NewSecuregate(provider.SecuregateConfig{
			BaseURL: baseURL, APIToken: apiToken, WebhookSecret: webhookSecret,
		}), nil
	case provider.ProviderOnyxPlus:
		return provider.NewOnyxPlus(provider.OnyxPlusConfig{
			BaseURL: baseURL, APIToken: apiToken, WebhookSecret: webhookSecret,
		}), nil
	}
	// Fall back to the dynamic registry (Securegate + OnyxPlus self-
	// register via init(); custom adapters can do the same).
	return provider.GetProvider(name, map[string]string{
		"base_url":       baseURL,
		"api_token":      apiToken,
		"webhook_secret": webhookSecret,
	})
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

func statusHandler(prov provider.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if prov == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"enabled":  false,
				"provider": "",
				"label":    "",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":  true,
			"provider": prov.Name(),
			"label":    prov.Name(),
		})
	}
}

func sessionsHandler(prov provider.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if prov == nil {
			http.Error(w, "IDV disabled", http.StatusServiceUnavailable)
			return
		}
		var req provider.VerificationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := prov.InitiateVerification(r.Context(), &req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func sessionByIDHandler(prov provider.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if prov == nil {
			http.Error(w, "IDV disabled", http.StatusServiceUnavailable)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/idv/sessions/")
		if id == "" {
			http.Error(w, "session id required", http.StatusBadRequest)
			return
		}
		result, err := prov.CheckStatus(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func webhookHandler(prov provider.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if prov == nil {
			http.Error(w, "IDV disabled", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		headers := map[string]string{}
		for k := range r.Header {
			headers[k] = r.Header.Get(k)
		}
		event, err := prov.ParseWebhook(body, headers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, event)
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "writeJSON: %v\n", err)
	}
}
