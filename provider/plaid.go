// Copyright 2024-2026 Lux Partners Limited. All rights reserved.
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
	PlaidProduction = "https://production.plaid.com"
	PlaidSandbox    = "https://sandbox.plaid.com"
)

// PlaidConfig holds Plaid API credentials.
type PlaidConfig struct {
	BaseURL    string
	ClientID   string
	Secret     string
	WebhookURL string // callback URL for identity verification events
}

// Plaid implements the Provider interface for Plaid Identity Verification.
type Plaid struct {
	cfg    PlaidConfig
	client *http.Client
}

// NewPlaid creates a Plaid Identity IDV provider.
func NewPlaid(cfg PlaidConfig) *Plaid {
	if cfg.BaseURL == "" {
		cfg.BaseURL = PlaidSandbox
	}
	return &Plaid{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (p *Plaid) Name() string { return ProviderPlaid }

// InitiateVerification creates a Plaid Identity Verification session.
func (p *Plaid) InitiateVerification(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	payload := map[string]interface{}{
		"client_id":    p.cfg.ClientID,
		"secret":       p.cfg.Secret,
		"is_shareable": true,
		"template_id":  req.Workflow,
		"gave_consent": true,
		"user": map[string]interface{}{
			"client_user_id": req.ApplicationID,
			"email_address":  req.Email,
			"name": map[string]string{
				"given_name":  req.GivenName,
				"family_name": req.FamilyName,
			},
			"date_of_birth": req.DateOfBirth,
		},
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.cfg.BaseURL+"/identity_verification/create", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("plaid identity verification create: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("plaid API error %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		ID           string `json:"id"`
		ShareableURL string `json:"shareable_url"`
		Status       string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("plaid response decode: %w", err)
	}

	return &VerificationResponse{
		VerificationID: result.ID,
		Provider:       ProviderPlaid,
		Status:         StatusPending,
		RedirectURL:    result.ShareableURL,
		CreatedAt:      time.Now(),
	}, nil
}

// CheckStatus retrieves the current status of a Plaid identity verification.
func (p *Plaid) CheckStatus(ctx context.Context, verificationID string) (*VerificationStatusResult, error) {
	payload := map[string]string{
		"client_id":                p.cfg.ClientID,
		"secret":                   p.cfg.Secret,
		"identity_verification_id": verificationID,
	}
	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.cfg.BaseURL+"/identity_verification/get", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("plaid status check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("plaid status check error %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		Status string `json:"status"`
		Steps  struct {
			VerifySMS               string `json:"verify_sms"`
			DocumentaryVerification string `json:"documentary_verification"`
			SelfieCheck             string `json:"selfie_check"`
			KYCCheck                string `json:"kyc_check"`
			RiskCheck               string `json:"risk_check"`
		} `json:"steps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("plaid status decode: %w", err)
	}

	status := mapPlaidStatus(result.Status)
	checks := []Check{
		{Type: "documentary_verification", Status: result.Steps.DocumentaryVerification},
		{Type: "selfie_check", Status: result.Steps.SelfieCheck},
		{Type: "kyc_check", Status: result.Steps.KYCCheck},
		{Type: "risk_check", Status: result.Steps.RiskCheck},
	}

	return &VerificationStatusResult{
		VerificationID: verificationID,
		Provider:       ProviderPlaid,
		Status:         status,
		Checks:         checks,
	}, nil
}

// ParseWebhook refuses every payload: a Plaid verdict enters through CheckStatus.
//
// Plaid authenticates a webhook with a JWT in Plaid-Verification, whose signing
// key must be fetched from /webhook_verification_key/get by key ID and whose
// body-hash claim must then be matched against the request. None of that is
// implemented here, so a genuine Plaid callback is indistinguishable from a
// forged one and neither is a verdict. Polling is the authenticated path: the
// answer arrives over a connection Plaid's own certificate authenticates, with
// the client credentials proving who is asking.
func (p *Plaid) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	return nil, fmt.Errorf("plaid webhook carries a Plaid-Verification JWT this client cannot check; poll CheckStatus for the verdict: %w", ErrWebhookUnsigned)
}

func mapPlaidStatus(s string) VerificationStatus {
	switch s {
	case "success":
		return StatusApproved
	case "failed":
		return StatusDeclined
	case "expired":
		return StatusExpired
	default:
		return StatusPending
	}
}
