// Package idmerit implements the IDV provider for IDMerit.
package provider

import (
	"context"
	"fmt"
)

type IDMeritConfig struct {
	BaseURL   string
	APIKey    string
	APISecret string
}

type IDMerit struct{ cfg IDMeritConfig }

func NewIDMerit(cfg IDMeritConfig) *IDMerit { return &IDMerit{cfg: cfg} }
func (p *IDMerit) Name() string             { return ProviderIDMerit }
func (p *IDMerit) InitiateVerification(ctx context.Context, user *VerificationRequest) (*VerificationResponse, error) {
	return nil, fmt.Errorf("idmerit: not yet implemented")
}
func (p *IDMerit) CheckStatus(ctx context.Context, sessionID string) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("idmerit: not yet implemented")
}

// ParseWebhook refuses every payload: with no IDMerit callback signature scheme
// implemented here, an arriving payload is a caller's claim, not a verdict.
func (p *IDMerit) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	return nil, fmt.Errorf("idmerit webhook verification is not implemented: %w", ErrWebhookUnsigned)
}
