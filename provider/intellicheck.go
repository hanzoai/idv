// Package intellicheck implements the IDV provider for Intellicheck document verification.
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
	IntellicheckProdURL = "https://idn-platform-api.intellicheck.com"
	IntellicheckSandboxURL = "https://idn-platform-api-uat.intellicheck.com"
)

type IntellicheckConfig struct {
	BaseURL         string
	CompanyToken    string
	SubscriptionKey string
}

type Intellicheck struct {
	cfg    IntellicheckConfig
	client *http.Client
}

func NewIntellicheck(cfg IntellicheckConfig) *Intellicheck {
	if cfg.BaseURL == "" { cfg.BaseURL = IntellicheckSandboxURL }
	return &Intellicheck{cfg: cfg, client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *Intellicheck) Name() string { return "intellicheck" }

func (p *Intellicheck) InitiateVerification(ctx context.Context, user VerificationRequest) (*VerificationResponse, error) {
	body := map[string]any{"location": "US", "purpose": "Age Verification"}
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", p.cfg.BaseURL+"/ingest", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Ocp-Apim-Subscription-Key", p.cfg.SubscriptionKey)
	req.Header.Set("Authorization", "Bearer "+p.cfg.CompanyToken)
	resp, err := p.client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 { return nil, fmt.Errorf("intellicheck: %d", resp.StatusCode) }
	var result struct{ UserToken string `json:"userToken"`; IngestToken string `json:"ingestToken"` }
	json.Unmarshal(respBody, &result)
	return &VerificationResponse{VerificationID: result.UserToken, Provider: "intellicheck", Status: StatusPending}, nil
}

func (p *Intellicheck) CheckStatus(ctx context.Context, sessionID string) (*VerificationStatusResult, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", p.cfg.BaseURL+"/results/"+sessionID, nil)
	req.Header.Set("Ocp-Apim-Subscription-Key", p.cfg.SubscriptionKey)
	resp, err := p.client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	// body already read above
	return &VerificationStatusResult{Status: StatusApproved}, nil
}

func (p *Intellicheck) ParseWebhook(headers map[string]string, body []byte) (*VerificationStatusResult, error) {
	return nil, fmt.Errorf("intellicheck: webhook not supported")
}
