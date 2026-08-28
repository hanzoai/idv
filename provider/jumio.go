// Copyright 2024-2026 Lux Industries Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	JumioAPIv4     = "https://netverify.com/api/v4"
	JumioSandboxv4 = "https://lon.netverify.com/api/v4"
)

// JumioConfig holds Jumio API credentials.
type JumioConfig struct {
	BaseURL   string
	APIToken  string // OAuth2 or API token
	APISecret string // API secret for basic auth
}

// Jumio implements the Provider interface for Jumio Netverify API v4.
type Jumio struct {
	cfg    JumioConfig
	client *http.Client
}

// NewJumio creates a Jumio IDV provider.
func NewJumio(cfg JumioConfig) *Jumio {
	if cfg.BaseURL == "" {
		cfg.BaseURL = JumioSandboxv4
	}
	return &Jumio{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (j *Jumio) Name() string { return ProviderJumio }

// InitiateVerification creates a new Jumio verification transaction via API v4.
func (j *Jumio) InitiateVerification(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	payload := map[string]interface{}{
		"customerInternalReference": req.ApplicationID,
		"userReference":             req.Email,
		"workflowId":                200, // ID + Identity Verification
	}
	if req.Workflow != "" {
		payload["workflowId"] = req.Workflow
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		j.cfg.BaseURL+"/initiate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "LuxCompliance/1.0")
	httpReq.SetBasicAuth(j.cfg.APIToken, j.cfg.APISecret)

	resp, err := j.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("jumio API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jumio API error %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		TransactionReference string `json:"transactionReference"`
		RedirectURL          string `json:"redirectUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("jumio response decode failed: %w", err)
	}

	return &VerificationResponse{
		VerificationID: result.TransactionReference,
		Provider:       ProviderJumio,
		Status:         StatusPending,
		RedirectURL:    result.RedirectURL,
		CreatedAt:      time.Now(),
	}, nil
}

// CheckStatus retrieves the current status of a Jumio transaction.
func (j *Jumio) CheckStatus(ctx context.Context, verificationID string) (*VerificationStatusResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		j.cfg.BaseURL+"/transactions/"+verificationID, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "LuxCompliance/1.0")
	httpReq.SetBasicAuth(j.cfg.APIToken, j.cfg.APISecret)

	resp, err := j.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("jumio status check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jumio status check error %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		Status             string                 `json:"status"`
		VerificationStatus string                 `json:"verificationStatus"`
		Decision           map[string]interface{} `json:"decision,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("jumio status decode failed: %w", err)
	}

	status := mapJumioVerificationStatus(result.VerificationStatus)
	checks := []Check{
		{Type: "document", Status: mapJumioDocStatus(result.Status)},
	}

	return &VerificationStatusResult{
		VerificationID: verificationID,
		Provider:       ProviderJumio,
		Status:         status,
		Checks:         checks,
	}, nil
}

// ParseWebhook parses a Jumio callback.
//
// Jumio signs the raw callback body with the account's API secret and sends the
// digest in Callback-Sig. The signature is checked before the body is read, and
// an account holding no secret cannot check anything — both refuse.
func (j *Jumio) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	if err := verifyHMAC(body, j.cfg.APISecret, header(headers, "Callback-Sig")); err != nil {
		return nil, err
	}

	var payload struct {
		TransactionReference      string                 `json:"transactionReference"`
		CustomerInternalReference string                 `json:"customerInternalReference"`
		Status                    string                 `json:"status"`
		VerificationStatus        string                 `json:"verificationStatus"`
		RejectReason              map[string]interface{} `json:"rejectReason,omitempty"`
		IdentityVerification      map[string]interface{} `json:"identityVerification,omitempty"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("jumio webhook decode: %w", err)
	}

	status := mapJumioVerificationStatus(payload.VerificationStatus)

	checks := []Check{
		{Type: "document", Status: mapJumioDocStatus(payload.Status)},
	}
	if payload.IdentityVerification != nil {
		if sim, ok := payload.IdentityVerification["similarity"].(string); ok {
			checks = append(checks, Check{
				Type:   "facial_similarity",
				Status: sim,
			})
		}
	}

	return &WebhookEvent{
		Provider:       ProviderJumio,
		VerificationID: payload.TransactionReference,
		ApplicationID:  payload.CustomerInternalReference,
		Status:         status,
		Checks:         checks,
		RawPayload:     body,
		ReceivedAt:     time.Now(),
	}, nil
}

func mapJumioVerificationStatus(s string) VerificationStatus {
	switch s {
	case "APPROVED_VERIFIED":
		return StatusApproved
	case "DENIED_FRAUD", "DENIED_UNSUPPORTED_ID_TYPE", "DENIED_UNSUPPORTED_ID_COUNTRY",
		"ERROR_NOT_READABLE_ID", "NO_ID_UPLOADED":
		return StatusDeclined
	default:
		return StatusPending
	}
}

func mapJumioDocStatus(s string) string {
	switch s {
	case "DONE":
		return "clear"
	default:
		return "consider"
	}
}
