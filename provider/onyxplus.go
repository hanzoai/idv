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
	ProviderOnyxPlus = "onyxplus"
	OnyxPlusAPI      = "https://onyxplus-api.dev.vendor.com"
)

// OnyxPlusConfig holds OnyxPlus API credentials.
type OnyxPlusConfig struct {
	BaseURL       string
	APIToken      string
	WebhookSecret string
}

// OnyxPlus implements the Provider interface.
//
// Scaffolded against the example/id integration shape (see
// `a downstream integration`). Wire the
// real request/response payloads when integrating.
type OnyxPlus struct {
	cfg    OnyxPlusConfig
	client *http.Client
}

func NewOnyxPlus(cfg OnyxPlusConfig) *OnyxPlus {
	if cfg.BaseURL == "" {
		cfg.BaseURL = OnyxPlusAPI
	}
	return &OnyxPlus{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (o *OnyxPlus) Name() string { return ProviderOnyxPlus }

func (o *OnyxPlus) InitiateVerification(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	// TODO: POST ${BaseURL}/v1/onyx/enrollments — returns
	// { enrollment_id, liveness_session_url, passkey_challenge, expires_at }.
	return &VerificationResponse{
		VerificationID: newID(),
		Provider:       ProviderOnyxPlus,
		Status:         StatusPending,
		CreatedAt:      time.Now().UTC(),
	}, nil
}

func (o *OnyxPlus) CheckStatus(ctx context.Context, verificationID string) (*VerificationStatusResult, error) {
	// TODO: GET ${BaseURL}/v1/onyx/enrollments/{verificationID}.
	return &VerificationStatusResult{
		VerificationID: verificationID,
		Provider:       ProviderOnyxPlus,
		Status:         StatusPending,
	}, nil
}

func (o *OnyxPlus) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	// TODO: verify the signature header against cfg.WebhookSecret,
	// then decode the OnyxPlus attestation envelope.
	var raw json.RawMessage = body
	return &WebhookEvent{
		Provider:   ProviderOnyxPlus,
		RawPayload: raw,
		ReceivedAt: time.Now().UTC(),
	}, nil
}

func init() {
	RegisterFactory(ProviderOnyxPlus, func(config map[string]string) (Provider, error) {
		return NewOnyxPlus(OnyxPlusConfig{
			BaseURL:       config["base_url"],
			APIToken:      config["api_token"],
			WebhookSecret: config["webhook_secret"],
		}), nil
	})
}
