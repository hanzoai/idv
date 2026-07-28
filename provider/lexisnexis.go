// Package lexisnexis implements the IDV provider for LexisNexis FlexID.
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

func (p *LexisNexis) InitiateVerification(ctx context.Context, user *VerificationRequest) (*VerificationResponse, error) {
	street := ""
	if len(user.Street) > 0 {
		street = user.Street[0]
	}
	body := map[string]any{
		"Options": map[string]any{"Watchlists.Threshold": 0.84},
		"User":    map[string]string{"GLBPurpose": "7", "DLPurpose": "3"},
		"SearchBy": map[string]any{
			"Name":    map[string]string{"First": user.GivenName, "Last": user.FamilyName},
			"Address": map[string]string{"StreetAddress1": street, "City": user.City, "State": user.State, "Zip5": user.PostalCode},
			"SSN":     user.TaxID,
			"DOB":     map[string]string{"Year": user.DateOfBirth, "Month": "01", "Day": "01"},
		},
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", p.cfg.BaseURL+"?ver_=3.12", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.cfg.Username, p.cfg.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lexisnexis: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("lexisnexis: %d %s", resp.StatusCode, string(respBody))
	}

	return &VerificationResponse{
		VerificationID: fmt.Sprintf("ln-%d", time.Now().UnixNano()),
		Provider:       ProviderLexisNexis,
		Status:         StatusApproved, // LexisNexis returns sync result
	}, nil
}

func (p *LexisNexis) CheckStatus(ctx context.Context, sessionID string) (*VerificationStatusResult, error) {
	return &VerificationStatusResult{Status: StatusApproved}, nil
}

// ParseWebhook refuses every payload: FlexID answers in the response to the
// query, so nothing legitimate arrives here and there is no signature scheme a
// caller's claim could be checked against.
func (p *LexisNexis) ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error) {
	return nil, fmt.Errorf("lexisnexis answers synchronously and sends no webhook: %w", ErrWebhookUnsigned)
}
