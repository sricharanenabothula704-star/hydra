package opencode

import (
	"context"
	"encoding/json"
	"net/http"
)

// Session is an opencode conversation/session (Session.Info). Shapes carry more
// fields across versions; the full payload is kept in Raw.
type Session struct {
	ID       string          `json:"id"`
	ParentID string          `json:"parentID,omitempty"`
	Title    string          `json:"title,omitempty"`
	Raw      json.RawMessage `json:"-"`
}

func (s *Session) UnmarshalJSON(b []byte) error {
	type alias Session
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*s = Session(a)
	s.Raw = append(s.Raw[:0], b...)
	return nil
}

// CreateSessionInput is the body for POST /api/session.
type CreateSessionInput struct {
	Title    string `json:"title,omitempty"`
	ParentID string `json:"parentID,omitempty"`
	Agent    string `json:"agent,omitempty"`
	Model    string `json:"model,omitempty"` // "provider/model"
}

// CreateSession creates a new session (POST /api/session). The response is the
// {data: Session.Info} envelope.
func (c *Client) CreateSession(ctx context.Context, in CreateSessionInput) (Session, error) {
	var s Session
	err := c.doAPI(ctx, http.MethodPost, "/session", in, &s)
	return s, err
}

// ListSessions lists sessions (GET /api/session). The SessionsResponse envelope
// carries the list under "data".
func (c *Client) ListSessions(ctx context.Context) ([]Session, error) {
	var out []Session
	err := c.doAPI(ctx, http.MethodGet, "/session", nil, &out)
	return out, err
}

// PromptInput is the body for POST /api/session/{id}/prompt.
type PromptInput struct {
	Text     string         `json:"text"`
	ID       string         `json:"id,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Prompt sends a text prompt to a session (POST /api/session/{id}/prompt). The
// model streams its reply over the /api/event SSE stream; this returns once the
// user message is accepted (the {data: Session.Inbox.User} envelope as raw JSON).
func (c *Client) Prompt(ctx context.Context, sessionID string, in PromptInput) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.doAPI(ctx, http.MethodPost, "/session/"+sessionID+"/prompt", in, &out)
	return out, err
}

// CommandInput runs a named opencode command (e.g. Hydra's hunt/verify/report)
// in a session (POST /api/session/{id}/command).
type CommandInput struct {
	Name string `json:"name"`
	Text string `json:"text,omitempty"`
}

// RunCommand executes a named command in a session.
func (c *Client) RunCommand(ctx context.Context, sessionID string, in CommandInput) error {
	return c.doAPI(ctx, http.MethodPost, "/session/"+sessionID+"/command", in, nil)
}

// SetModel sets the active model for a session (POST /api/session/{id}/model).
func (c *Client) SetModel(ctx context.Context, sessionID, model string) error {
	return c.doAPI(ctx, http.MethodPost, "/session/"+sessionID+"/model",
		map[string]string{"model": model}, nil)
}
