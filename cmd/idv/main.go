// Command idv is the standalone Hanzo IDV service binary.
//
// Exposes one HTTP surface (/v1/idv/*) that IAM proxies to for the
// biometric step of the onboarding pipeline. Decomplected from IAM:
// this service knows the providers (Jumio / Onfido / Plaid / …); IAM
// knows the user identity. Neither imports the other's library.
//
// Provider selection via env:
//
//	IDV_PROVIDER=jumio|onfido|plaid|lexisnexis|intellicheck|
//	             idmerit|berbix
//	IDV_BASE_URL=…               (optional region override)
//	IDV_API_TOKEN=…              (required for non-noop)
//	IDV_API_SECRET=…             (Jumio: API auth and callback signature;
//	                              Plaid: client secret)
//	IDV_WEBHOOK_SECRET=…         (Onfido: webhook signature)
//
// Endpoints:
//
//	GET  /v1/idv/status                   active provider discovery
//	POST /v1/idv/sessions                 initiate a verification
//	GET  /v1/idv/sessions/{id}            poll verification status
//	POST /v1/idv/webhook/{provider}       provider webhook ingest
//	GET  /healthz                         liveness
//
// Run:
//
//	IDV_PROVIDER=onfido IDV_API_TOKEN=… idv -http :8081
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/zap-proto/fiber/v3"
	"github.com/zap-proto/zip"

	"hanzo.ai/idv/provider"
)

// sessionsSubtree is the prefix that separates the collection route
// (POST /v1/idv/sessions) from the by-id subtree. See sessionByIDHandler.
const sessionsSubtree = "/v1/idv/sessions/"

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

	log.Printf("idv: listening on %s", *addr)
	log.Fatal(newApp(prov).Listen("http://" + *addr))
}

// newApp builds the zip router. Every path, method, status code and
// response body is the one the net/http mux served before it.
func newApp(prov provider.Provider) *zip.App {
	app := zip.New(zip.Config{
		AppName:               "idv",
		DisableStartupMessage: true,
		ErrorHandler:          plainError,
	})

	// All (not Get): the stdlib mux served these on any method.
	app.All("/healthz", func(c *zip.Ctx) error {
		return writeJSON(c, http.StatusOK, map[string]string{"status": "ok"})
	})

	v1 := app.Group("/v1/idv")
	v1.All("/status", statusHandler(prov))
	v1.Post("/sessions", sessionsHandler(prov))
	v1.Get("/sessions/*", sessionByIDHandler(prov))
	v1.Post("/webhook/*", webhookHandler(prov))
	return app
}

func loadProviderFromEnv() (provider.Provider, error) {
	name := strings.ToLower(os.Getenv("IDV_PROVIDER"))
	if name == "" || name == "none" || name == "noop" {
		return nil, nil
	}
	baseURL := os.Getenv("IDV_BASE_URL")
	apiToken := os.Getenv("IDV_API_TOKEN")
	apiSecret := os.Getenv("IDV_API_SECRET")
	webhookSecret := os.Getenv("IDV_WEBHOOK_SECRET")

	// Explicit constructors keep the wire path straight — no
	// registry indirection that hides which provider is wired.
	//
	// Each provider gets the secret its webhook signature is keyed on,
	// because a provider holding no secret refuses every callback: the
	// guard is only as reachable as the configuration makes it.
	switch name {
	case provider.ProviderJumio:
		return provider.NewJumio(provider.JumioConfig{
			BaseURL: baseURL, APIToken: apiToken, APISecret: apiSecret,
		}), nil
	case provider.ProviderOnfido:
		return provider.NewOnfido(provider.OnfidoConfig{
			BaseURL: baseURL, APIToken: apiToken, WebhookToken: webhookSecret,
		}), nil
	case provider.ProviderPlaid:
		// Plaid verdicts are polled, so the client secret is what
		// authenticates the only path they arrive on.
		return provider.NewPlaid(provider.PlaidConfig{
			BaseURL: baseURL, ClientID: apiToken, Secret: apiSecret,
		}), nil
	}
	// Fall back to the dynamic registry (providers self-register via
	// init(); custom adapters can do the same).
	return provider.GetProvider(name, map[string]string{
		"base_url":       baseURL,
		"api_token":      apiToken,
		"api_secret":     apiSecret,
		"webhook_secret": webhookSecret,
	})
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

func statusHandler(prov provider.Provider) zip.Handler {
	return func(c *zip.Ctx) error {
		if prov == nil {
			return writeJSON(c, http.StatusOK, map[string]any{
				"enabled":  false,
				"provider": "",
				"label":    "",
			})
		}
		return writeJSON(c, http.StatusOK, map[string]any{
			"enabled":  true,
			"provider": prov.Name(),
			"label":    prov.Name(),
		})
	}
}

func sessionsHandler(prov provider.Provider) zip.Handler {
	return func(c *zip.Ctx) error {
		if prov == nil {
			return errDisabled
		}
		var req provider.VerificationRequest
		// Decoder, not Unmarshal: it yields the same error text the
		// stdlib handler returned for a truncated body.
		if err := json.NewDecoder(bytes.NewReader(c.Body())).Decode(&req); err != nil {
			return httpErr(http.StatusBadRequest, err.Error())
		}
		resp, err := prov.InitiateVerification(c.Context(), &req)
		if err != nil {
			return httpErr(http.StatusBadGateway, err.Error())
		}
		return writeJSON(c, http.StatusOK, resp)
	}
}

func sessionByIDHandler(prov provider.Provider) zip.Handler {
	return func(c *zip.Ctx) error {
		// The stdlib mux drew a hard line between the collection route
		// "/v1/idv/sessions" (POST-only) and the "/v1/idv/sessions/"
		// subtree. fiber's non-strict matching collapses both onto this
		// one wildcard route, so the raw path redraws the line: an exact
		// /v1/idv/sessions belongs to the sibling route, which does not
		// answer GET.
		id, under := strings.CutPrefix(c.Path(), sessionsSubtree)
		if !under {
			return errMethodNotAllowed
		}
		if prov == nil {
			return errDisabled
		}
		if id == "" {
			return errSessionIDRequired
		}
		result, err := prov.CheckStatus(c.Context(), id)
		if err != nil {
			return httpErr(http.StatusBadGateway, err.Error())
		}
		return writeJSON(c, http.StatusOK, result)
	}
}

func webhookHandler(prov provider.Provider) zip.Handler {
	return func(c *zip.Ctx) error {
		if prov == nil {
			return errDisabled
		}
		headers := map[string]string{}
		for k, v := range c.Fiber().GetReqHeaders() {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		event, err := prov.ParseWebhook(c.Body(), headers)
		if err != nil {
			return httpErr(http.StatusBadRequest, err.Error())
		}
		return writeJSON(c, http.StatusOK, event)
	}
}

// --------------------------------------------------------------------------
// Wire format — the net/http contract this service shipped, in one place
// --------------------------------------------------------------------------

var (
	errDisabled          = httpErr(http.StatusServiceUnavailable, "IDV disabled")
	errMethodNotAllowed  = httpErr(http.StatusMethodNotAllowed, "method not allowed")
	errSessionIDRequired = httpErr(http.StatusBadRequest, "session id required")
)

func httpErr(status int, msg string) *zip.HTTPError {
	return &zip.HTTPError{Status: status, Msg: msg}
}

// writeJSON mirrors encoding/json's Encoder: "application/json" with no
// charset, and a trailing newline after the value.
func writeJSON(c *zip.Ctx, status int, body any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "writeJSON: %v\n", err)
	}
	c.SetHeader(fiber.HeaderContentType, "application/json")
	return c.Bytes(status, buf.Bytes())
}

// plainError renders every error exactly as net/http's http.Error did:
// text/plain, nosniff, message + "\n" — including the router's own 404
// and 405, whose stdlib wording this service inherited.
func plainError(fc fiber.Ctx, err error) error {
	status, msg := http.StatusInternalServerError, err.Error()
	var he *zip.HTTPError
	var fe *fiber.Error
	switch {
	case errors.Is(err, fiber.ErrNotFound):
		status, msg = http.StatusNotFound, "404 page not found"
	case errors.Is(err, fiber.ErrMethodNotAllowed):
		status, msg = errMethodNotAllowed.Status, errMethodNotAllowed.Msg
	case errors.As(err, &he):
		status, msg = he.Status, he.Msg
	case errors.As(err, &fe):
		status, msg = fe.Code, fe.Message
	}
	fc.Set(fiber.HeaderContentType, "text/plain; charset=utf-8")
	fc.Set("X-Content-Type-Options", "nosniff")
	fc.Status(status)
	return fc.SendString(msg + "\n")
}
