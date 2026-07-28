// Copyright 2024-2026 Lux Partners Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

// Package idv provides identity verification integration with Jumio, Onfido,
// and Plaid Identity. It extends the hanzoai/iam IDV pattern with multi-provider
// support, webhook routing, and status tracking.
package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// VerificationStatus is the outcome of an identity verification check.
type VerificationStatus string

const (
	StatusPending  VerificationStatus = "pending"
	StatusApproved VerificationStatus = "approved"
	StatusDeclined VerificationStatus = "declined"
	StatusExpired  VerificationStatus = "expired"
	StatusError    VerificationStatus = "error"
)

// Provider names.
const (
	ProviderJumio        = "jumio"
	ProviderOnfido       = "onfido"
	ProviderPlaid        = "plaid"
	ProviderLexisNexis   = "lexisnexis"
	ProviderIntellicheck = "intellicheck"
	ProviderIDMerit      = "idmerit"
	ProviderBerbix       = "berbix"
)

// VerificationRequest initiates an identity verification check.
type VerificationRequest struct {
	ApplicationID string `json:"application_id"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	DateOfBirth   string `json:"date_of_birth,omitempty"`
	Email         string `json:"email"`
	Phone         string `json:"phone,omitempty"`
	Country       string `json:"country,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`

	// Address fields
	Street     []string `json:"street,omitempty"`
	City       string   `json:"city,omitempty"`
	State      string   `json:"state,omitempty"`
	PostalCode string   `json:"postal_code,omitempty"`

	// Tax identification
	TaxID     string `json:"tax_id,omitempty"`
	TaxIDType string `json:"tax_id_type,omitempty"` // ssn, itin, ein

	// Document verification (for sync ID card checks via IAM)
	DocumentType string `json:"document_type,omitempty"` // passport, drivers_license, id_card
	DocumentID   string `json:"document_id,omitempty"`   // document number

	// Provider-specific overrides
	Provider string `json:"provider,omitempty"` // jumio, onfido, plaid
	Workflow string `json:"workflow,omitempty"` // provider-specific workflow ID
}

// VerificationResponse is returned after initiating a check.
type VerificationResponse struct {
	VerificationID string             `json:"verification_id"`
	Provider       string             `json:"provider"`
	Status         VerificationStatus `json:"status"`
	RedirectURL    string             `json:"redirect_url,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
}

// VerificationStatusResult is returned when checking a verification's status.
type VerificationStatusResult struct {
	VerificationID string             `json:"verification_id"`
	Provider       string             `json:"provider"`
	Status         VerificationStatus `json:"status"`
	RiskScore      float64            `json:"risk_score,omitempty"`
	Checks         []Check            `json:"checks,omitempty"`
	CompletedAt    *time.Time         `json:"completed_at,omitempty"`
}

// WebhookEvent represents a parsed webhook from an IDV provider.
type WebhookEvent struct {
	Provider       string             `json:"provider"`
	VerificationID string             `json:"verification_id"`
	ApplicationID  string             `json:"application_id,omitempty"`
	Status         VerificationStatus `json:"status"`
	RiskScore      float64            `json:"risk_score,omitempty"`
	Checks         []Check            `json:"checks,omitempty"`
	RawPayload     json.RawMessage    `json:"raw_payload,omitempty"`
	ReceivedAt     time.Time          `json:"received_at"`
}

// Check is a single verification check (document, selfie, PEP/sanctions, etc.)
type Check struct {
	Type   string `json:"type"`   // document, facial_similarity, watchlist, address
	Status string `json:"status"` // clear, consider, rejected
	Detail string `json:"detail,omitempty"`
}

// Provider is the interface each IDV integration must implement.
type Provider interface {
	Name() string
	InitiateVerification(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error)
	CheckStatus(ctx context.Context, verificationID string) (*VerificationStatusResult, error)
	ParseWebhook(body []byte, headers map[string]string) (*WebhookEvent, error)
}

// The implementations. Stating conformance here makes ParseWebhook's contract —
// including the authenticity requirement webhook_test.go asserts over this same
// set — a compile-time obligation rather than a convention.
var (
	_ Provider = (*Jumio)(nil)
	_ Provider = (*Onfido)(nil)
	_ Provider = (*Plaid)(nil)
	_ Provider = (*LexisNexis)(nil)
	_ Provider = (*Intellicheck)(nil)
	_ Provider = (*IDMerit)(nil)
	_ Provider = (*Berbix)(nil)
)

// providerFactory creates a provider from a config map.
type providerFactory func(config map[string]string) (Provider, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]providerFactory{}
)

// RegisterFactory registers a provider factory by name.
func RegisterFactory(name string, factory providerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// GetProvider creates a provider by name using the given config.
func GetProvider(name string, config map[string]string) (Provider, error) {
	registryMu.RLock()
	factory, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("IDV provider %q not registered", name)
	}
	return factory(config)
}

// ListRegistered returns the names of all registered provider factories.
func ListRegistered() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Providers are registered by importing their sub-packages:
//
//   import _ "github.com/hanzoai/idv/provider/jumio"
//   import _ "github.com/hanzoai/idv/provider/onfido"
//
// Each sub-package calls RegisterFactory in its init().
