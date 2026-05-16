// Copyright 2024-2026 Lux Partners Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

const (
	ProviderSecuregate = "securegate"
	SecuregateAPI      = "https://api.securegate.io"
)

// SecuregateConfig holds Securegate API credentials.
type SecuregateConfig struct {
	BaseURL  string
	APIToken string
	// WebhookSecret signs the inbound webhook payloads; verified in
	// ParseWebhook before the event is trusted.
	WebhookSecret string
}

// Securegate implements the Provider interface.
//
// Scaffolded — wire the real request/response shapes in
// InitiateVerification + CheckStatus + ParseWebhook when integrating
// against Securegate's actual API. The interface here is fixed so
// callers (hanzoai/iam, base, etc.) can pin to it today.
type Securegate struct {
	cfg    SecuregateConfig
	client *http.Client
}

// NewSecuregate creates a Securegate IDV provider.
func NewSecuregate(cfg SecuregateConfig) *Securegate {
	if cfg.BaseURL == "" {
		cfg.BaseURL = SecuregateAPI
	}
	return &Securegate{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Securegate) Name() string { return ProviderSecuregate }

func (s *Securegate) InitiateVerification(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	// TODO: POST ${BaseURL}/v1/sessions with the Securegate-specific
	// applicant + workflow payload. Returns redirect URL + session id.
	return &VerificationResponse{
		VerificationID: newID(),
		Provider:       ProviderSecuregate,
		Status:         StatusPending,
		CreatedAt:      time.Now().UTC(),
	}, nil
}

func (s *Securegate) CheckStatus(ctx context.Context, verificationID string) (*VerificationStatusResult, error) {
	// TODO: GET ${BaseURL}/v1/sessions/{id}.
	return &VerificationStatusResult{
		VerificationID: verificationID,
		Provider:       ProviderSecuregate,
		Status:         StatusPending,
	}, nil
}

func (s *Securegate) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	// TODO: verify the HMAC signature in headers using cfg.WebhookSecret,
	// then decode the Securegate-specific event envelope.
	var raw json.RawMessage = body
	return &WebhookEvent{
		Provider:   ProviderSecuregate,
		RawPayload: raw,
		ReceivedAt: time.Now().UTC(),
	}, nil
}

func init() {
	RegisterFactory(ProviderSecuregate, func(config map[string]string) (Provider, error) {
		return NewSecuregate(SecuregateConfig{
			BaseURL:       config["base_url"],
			APIToken:      config["api_token"],
			WebhookSecret: config["webhook_secret"],
		}), nil
	})
}
