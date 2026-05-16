// Copyright 2024-2026 Lux Partners Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package provider

// Auto-registration for the providers that ship their constructors
// in this package. Each entry maps the provider's canonical name to
// a factory that pulls config out of the generic string map (so
// callers can wire all providers with the same `cfg` shape).
//
// New providers either:
//   1. Add an init() block in their own file (see onyxplus.go /
//      securegate.go), or
//   2. Add a case here.

func init() {
	RegisterFactory(ProviderJumio, func(c map[string]string) (Provider, error) {
		return NewJumio(JumioConfig{
			BaseURL:   c["base_url"],
			APIToken:  c["api_token"],
			APISecret: c["api_secret"],
		}), nil
	})
	RegisterFactory(ProviderOnfido, func(c map[string]string) (Provider, error) {
		return NewOnfido(OnfidoConfig{
			BaseURL:      c["base_url"],
			APIToken:     c["api_token"],
			WebhookToken: c["webhook_secret"],
		}), nil
	})
	RegisterFactory(ProviderPlaid, func(c map[string]string) (Provider, error) {
		return NewPlaid(PlaidConfig{
			BaseURL:    c["base_url"],
			ClientID:   c["client_id"],
			Secret:     c["api_token"],
			WebhookURL: c["webhook_url"],
		}), nil
	})
}
