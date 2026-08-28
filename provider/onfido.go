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
	OnfidoAPIv3        = "https://api.onfido.com/v3.6"
	OnfidoSandboxAPIv3 = "https://api.onfido.com/v3.6"
)

// OnfidoConfig holds Onfido API credentials.
type OnfidoConfig struct {
	BaseURL      string
	APIToken     string
	WebhookToken string // for webhook signature verification
}

// Onfido implements the Provider interface for Onfido API v3.6.
type Onfido struct {
	cfg    OnfidoConfig
	client *http.Client
}

// NewOnfido creates an Onfido IDV provider.
func NewOnfido(cfg OnfidoConfig) *Onfido {
	if cfg.BaseURL == "" {
		cfg.BaseURL = OnfidoSandboxAPIv3
	}
	return &Onfido{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (o *Onfido) Name() string { return ProviderOnfido }

// InitiateVerification creates an Onfido applicant and starts a check workflow.
func (o *Onfido) InitiateVerification(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	// Step 1: Create applicant
	applicant := map[string]interface{}{
		"first_name": req.GivenName,
		"last_name":  req.FamilyName,
		"email":      req.Email,
	}
	if req.DateOfBirth != "" {
		applicant["dob"] = req.DateOfBirth
	}

	applicantID, err := o.createApplicant(ctx, applicant)
	if err != nil {
		return nil, err
	}

	// Step 2: Create SDK token for client-side integration
	sdkToken, err := o.createSDKToken(ctx, applicantID)
	if err != nil {
		return nil, err
	}

	// Step 3: Create check (document + facial similarity + optional watchlist)
	checkID, err := o.createCheck(ctx, applicantID, req.Workflow)
	if err != nil {
		return nil, err
	}

	return &VerificationResponse{
		VerificationID: checkID,
		Provider:       ProviderOnfido,
		Status:         StatusPending,
		RedirectURL:    sdkToken, // SDK token for Onfido Web SDK
		CreatedAt:      time.Now(),
	}, nil
}

func (o *Onfido) createApplicant(ctx context.Context, applicant map[string]interface{}) (string, error) {
	body, _ := json.Marshal(applicant)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.cfg.BaseURL+"/applicants", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	o.setHeaders(req)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("onfido create applicant: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("onfido create applicant %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

func (o *Onfido) createSDKToken(ctx context.Context, applicantID string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"applicant_id": applicantID,
		"referrer":     "*://*/*",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.cfg.BaseURL+"/sdk_token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	o.setHeaders(req)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("onfido create SDK token: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Token, nil
}

func (o *Onfido) createCheck(ctx context.Context, applicantID, workflow string) (string, error) {
	reportNames := []string{"document", "facial_similarity_photo"}
	if workflow == "enhanced" {
		reportNames = append(reportNames, "watchlist_enhanced")
	}

	checkReq := map[string]interface{}{
		"applicant_id": applicantID,
		"report_names": reportNames,
	}
	body, _ := json.Marshal(checkReq)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.cfg.BaseURL+"/checks", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	o.setHeaders(req)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("onfido create check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("onfido create check %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

// CheckStatus retrieves the current status of an Onfido check.
func (o *Onfido) CheckStatus(ctx context.Context, verificationID string) (*VerificationStatusResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		o.cfg.BaseURL+"/checks/"+verificationID, nil)
	if err != nil {
		return nil, err
	}
	o.setHeaders(req)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("onfido status check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("onfido status check error %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("onfido status decode failed: %w", err)
	}

	status := mapOnfidoResult(result.Result)
	checks := []Check{
		{Type: "check", Status: result.Result},
	}

	return &VerificationStatusResult{
		VerificationID: verificationID,
		Provider:       ProviderOnfido,
		Status:         status,
		Checks:         checks,
	}, nil
}

// ParseWebhook parses an Onfido webhook notification.
//
// Onfido signs the raw body with the token registered alongside the webhook
// endpoint and sends the digest in X-SHA2-Signature. That signature is what
// makes the payload Onfido's verdict rather than a caller's claim, so it is
// checked before the body is read at all.
func (o *Onfido) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	if err := verifyHMAC(body, o.cfg.WebhookToken, header(headers, "X-SHA2-Signature")); err != nil {
		return nil, err
	}

	var payload struct {
		Payload struct {
			ResourceType string `json:"resource_type"`
			Action       string `json:"action"`
			Object       struct {
				ID          string `json:"id"`
				Status      string `json:"status"`
				Result      string `json:"result"`
				ApplicantID string `json:"applicant_id"`
			} `json:"object"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("onfido webhook decode: %w", err)
	}

	status := mapOnfidoResult(payload.Payload.Object.Result)

	checks := []Check{
		{
			Type:   payload.Payload.ResourceType,
			Status: payload.Payload.Object.Result,
		},
	}

	return &WebhookEvent{
		Provider:       ProviderOnfido,
		VerificationID: payload.Payload.Object.ID,
		Status:         status,
		Checks:         checks,
		RawPayload:     body,
		ReceivedAt:     time.Now(),
	}, nil
}

func (o *Onfido) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Token token="+o.cfg.APIToken)
}

func mapOnfidoResult(result string) VerificationStatus {
	switch result {
	case "clear":
		return StatusApproved
	case "consider":
		return StatusDeclined
	default:
		return StatusPending
	}
}
