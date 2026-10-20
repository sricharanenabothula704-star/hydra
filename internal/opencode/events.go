package opencode

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Event is a single server-sent event from GET /event. The server sends JSON
// payloads; Type is lifted from the payload's "type" field when present.
type Event struct {
	Type string          // e.g. "server.connected", "message.part.updated"
	Data json.RawMessage // the full JSON payload
}

// Events opens the SSE stream at /api/event and delivers events on the returned
// channel until ctx is cancelled or the stream ends. The channel is closed on
// termination; any terminal error is sent on the error channel (buffered 1).
//
// Each SSE frame carries an "event:" name and a "data:" JSON payload
// (V2EventEncoded). Event.Type is taken from the SSE event name, falling back
// to a "type" field inside the data payload.
func (c *Client) Events(ctx context.Context) (<-chan Event, <-chan error, error) {
	req, err := c.newRequest(ctx, http.MethodGet, apiPrefix+"/event", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil, &APIError{Method: "GET", Path: apiPrefix + "/event", Status: resp.StatusCode}
	}

	events := make(chan Event)
	errc := make(chan error, 1)

	go func() {
		defer resp.Body.Close()
		defer close(events)

		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20) // allow large SSE frames
		var dataLines []string
		var eventName string

		flush := func() {
			if len(dataLines) == 0 {
				eventName = ""
				return
			}
			payload := strings.Join(dataLines, "\n")
			dataLines = dataLines[:0]
			raw := json.RawMessage(payload)
			ev := Event{Type: eventName, Data: raw}
			eventName = ""
			if ev.Type == "" { // fall back to a "type" field in the payload
				var probe struct {
					Type string `json:"type"`
				}
				if json.Unmarshal(raw, &probe) == nil {
					ev.Type = probe.Type
				}
			}
			select {
			case events <- ev:
			case <-ctx.Done():
			}
		}

		for sc.Scan() {
			if ctx.Err() != nil {
				return
			}
			line := sc.Text()
			switch {
			case line == "": // event boundary
				flush()
			case strings.HasPrefix(line, ":"): // comment/keepalive
				continue
			case strings.HasPrefix(line, "event:"):
				eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			default:
				// Ignore other SSE fields (id:, retry:).
			}
		}
		flush()
		if err := sc.Err(); err != nil && ctx.Err() == nil {
			errc <- err
		}
	}()

	return events, errc, nil
}
