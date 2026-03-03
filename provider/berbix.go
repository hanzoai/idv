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
func (p *Berbix) Name() string { return "berbix" }
func (p *Berbix) InitiateVerification(ctx context.Context, user VerificationRequest) (*VerificationResponse, error) {
	return nil, fmt.Errorf("berbix: not yet implemented")
}
func (p *Berbix) CheckStatus(ctx context.Context, sessionID string) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("berbix: not yet implemented")
}
func (p *Berbix) ParseWebhook(headers map[string]string, body []byte) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("berbix: not yet implemented")
}
