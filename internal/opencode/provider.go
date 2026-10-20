package opencode

import (
	"context"
	"encoding/json"
	"net/http"
)

// Provider is one entry from GET /api/provider (Provider.Info). Fields vary by
// version, so the full payload is kept in Raw and common fields are lifted.
type Provider struct {
	ID   string          `json:"id"`
	Name string          `json:"name,omitempty"`
	Raw  json.RawMessage `json:"-"`
}

func (p *Provider) UnmarshalJSON(b []byte) error {
	type alias Provider
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*p = Provider(a)
	p.Raw = append(p.Raw[:0], b...)
	return nil
}

// Model is one entry from GET /api/model (Model.Info).
type Model struct {
	ID         string          `json:"id"`
	Name       string          `json:"name,omitempty"`
	ProviderID string          `json:"providerID,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

func (m *Model) UnmarshalJSON(b []byte) error {
	type alias Model
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*m = Model(a)
	m.Raw = append(m.Raw[:0], b...)
	return nil
}

// Providers lists available providers (GET /api/provider).
func (c *Client) Providers(ctx context.Context) ([]Provider, error) {
	var out []Provider
	err := c.doAPI(ctx, http.MethodGet, "/provider", nil, &out)
	return out, err
}

// Models lists available models (GET /api/model).
func (c *Client) Models(ctx context.Context) ([]Model, error) {
	var out []Model
	err := c.doAPI(ctx, http.MethodGet, "/model", nil, &out)
	return out, err
}

// Config returns opencode's effective config (GET /api/config) as raw JSON.
func (c *Client) Config(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.doAPI(ctx, http.MethodGet, "/config", nil, &out)
	return out, err
}

// Agents lists configured agents (GET /api/agent).
func (c *Client) Agents(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.doAPI(ctx, http.MethodGet, "/agent", nil, &out)
	return out, err
}

// CreateCredential stores a provider credential (POST /api/credential), the
// server-side part of a /connect flow. input is the version-specific
// Credential.CreateInput payload.
func (c *Client) CreateCredential(ctx context.Context, input any) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.doAPI(ctx, http.MethodPost, "/credential", input, &out)
	return out, err
}
