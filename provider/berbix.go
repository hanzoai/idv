// Package berbix implements the IDV provider for Berbix.
package provider

import (
	"context"
	"fmt"
)

type BerbixConfig struct {
	BaseURL   string
	APIKey    string
	APISecret string
}

type Berbix struct{ cfg BerbixConfig }

func NewBerbix(cfg BerbixConfig) *Berbix { return &Berbix{cfg: cfg} }
func (p *Berbix) Name() string           { return ProviderBerbix }
func (p *Berbix) InitiateVerification(ctx context.Context, user *VerificationRequest) (*VerificationResponse, error) {
	return nil, fmt.Errorf("berbix: not yet implemented")
}
func (p *Berbix) CheckStatus(ctx context.Context, sessionID string) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("berbix: not yet implemented")
}

// ParseWebhook refuses every payload: with no Berbix callback signature scheme
// implemented here, an arriving payload is a caller's claim, not a verdict.
func (p *Berbix) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	return nil, fmt.Errorf("berbix webhook verification is not implemented: %w", ErrWebhookUnsigned)
}
