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
func (p *IDMerit) Name() string { return "idmerit" }
func (p *IDMerit) InitiateVerification(ctx context.Context, user VerificationRequest) (*VerificationResponse, error) {
	return nil, fmt.Errorf("idmerit: not yet implemented")
}
func (p *IDMerit) CheckStatus(ctx context.Context, sessionID string) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("idmerit: not yet implemented")
}
func (p *IDMerit) ParseWebhook(headers map[string]string, body []byte) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("idmerit: not yet implemented")
}
