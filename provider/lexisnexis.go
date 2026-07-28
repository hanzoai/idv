// Package lexisnexis implements the IDV provider for LexisNexis FlexID.
package provider

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const (
	LexisNexisProdURL    = "https://wsonline.seisint.com/WsIdentity/FlexID"
	LexisNexisSandboxURL = "https://wsonline-uat.seisint.com/WsIdentity/FlexID"
)

type LexisNexisConfig struct {
	BaseURL  string
	Username string
	Password string
}

type LexisNexis struct {
	cfg    LexisNexisConfig
	client *http.Client
}

func NewLexisNexis(cfg LexisNexisConfig) *LexisNexis {
	if cfg.BaseURL == "" {
		cfg.BaseURL = LexisNexisSandboxURL
	}
	return &LexisNexis{cfg: cfg, client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *LexisNexis) Name() string { return ProviderLexisNexis }

// InitiateVerification refuses.
//
// FlexID answers synchronously: the verdict — the comprehensive verification
// index and any watchlist hits — is IN the response body. This integration builds
// and sends the query correctly but has never parsed that body, so it cannot know
// what the provider decided. It previously returned "approved" for any non-4xx
// response, which reports a decision the provider never gave and would pass a
// subject FlexID had actually flagged.
//
// A provider that cannot read a verdict must not report one, so this refuses
// rather than inventing a pass. Implementing it means parsing the FlexID response
// — the comprehensive verification index and the watchlist section — and mapping
// that to a status; the query that produced it is in this file's history.
func (p *LexisNexis) InitiateVerification(ctx context.Context, user *VerificationRequest) (*VerificationResponse, error) {
	return nil, fmt.Errorf("lexisnexis: the FlexID response carries the verdict and is not parsed — no decision can be reported")
}

// CheckStatus refuses, for the same reason InitiateVerification does: there is no
// stored or fetched verdict to report. It previously answered "approved"
// unconditionally, without so much as a request.
func (p *LexisNexis) CheckStatus(ctx context.Context, sessionID string) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("lexisnexis: no verdict is parsed — status cannot be reported")
}

// ParseWebhook refuses every payload: FlexID answers in the response to the
// query, so nothing legitimate arrives here and there is no signature scheme a
// caller's claim could be checked against.
func (p *LexisNexis) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	return nil, fmt.Errorf("lexisnexis answers synchronously and sends no webhook: %w", ErrWebhookUnsigned)
}
