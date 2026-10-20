// Package opencode is a Go client for the opencode server
// (https://opencode.ai/docs/server). hydra spawns or attaches to an
// `opencode serve` process and drives it over this HTTP + SSE API instead of
// shelling out to `opencode run`.
package opencode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a running opencode server.
type Client struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBasicAuth sets the HTTP basic-auth credentials the server expects when
// OPENCODE_SERVER_PASSWORD is set. Username defaults to "opencode".
func WithBasicAuth(user, pass string) Option {
	return func(c *Client) {
		if user == "" {
			user = "opencode"
		}
		c.username, c.password = user, pass
	}
}

// WithHTTPClient overrides the underlying *http.Client (e.g. for tests).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// New returns a Client for the given base URL (e.g. "http://127.0.0.1:4096").
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 0}, // no global timeout; SSE is long-lived
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// BaseURL returns the server base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// newRequest builds a request with auth and JSON body applied.
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	return req, nil
}

// doJSON performs the request and decodes a JSON response into out (if non-nil).
// Non-2xx responses become an *APIError carrying the status and body.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return nil
}

// APIError is a non-2xx response from the server.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	b := strings.TrimSpace(e.Body)
	if len(b) > 300 {
		b = b[:300] + "…"
	}
	return fmt.Sprintf("opencode %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, b)
}

// apiPrefix is the opencode v2 HTTP API mount point. All endpoints live under
// it; the bare paths (e.g. /session) serve the web UI, not the API.
const apiPrefix = "/api"

// doAPI calls an API endpoint (prefixing apiPrefix) and, when the response is
// the standard {"data": ...} envelope, decodes the inner value into out.
func (c *Client) doAPI(ctx context.Context, method, path string, body, out any) error {
	if out == nil {
		return c.doJSON(ctx, method, apiPrefix+path, body, nil)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := c.doJSON(ctx, method, apiPrefix+path, body, &env); err != nil {
		return err
	}
	if len(env.Data) == 0 {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// ServerInfo is returned by GET /api/info.
type ServerInfo struct {
	Version string   `json:"version"`
	PID     int      `json:"pid"`
	URLs    []string `json:"urls"`
}

// Info returns server info (GET /api/info). A successful response means the
// server is up; there is no separate health flag in v2.
func (c *Client) Info(ctx context.Context) (ServerInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var si ServerInfo
	// /api/info returns ServerInfo directly (no data envelope).
	err := c.doJSON(ctx, http.MethodGet, apiPrefix+"/info", nil, &si)
	return si, err
}
