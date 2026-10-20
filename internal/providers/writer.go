package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const schemaURL = "https://opencode.ai/config.json"

// Configured is a provider to write into opencode.json.
type Configured struct {
	ID        string            // provider id / config key
	Name      string            // display name
	NPM       string            // ai-sdk package (default @ai-sdk/openai-compatible)
	BaseURL   string            // OpenAI-compatible base URL
	APIKeyRef string            // e.g. "{env:NVIDIA_API_KEY}"; empty for local
	Models    map[string]string // model id -> display name (may be empty)
}

// ConfigPath returns the hydra-owned project config file inside the repo.
func ConfigPath(repoRoot string) string {
	return filepath.Join(repoRoot, "opencode.json")
}

// readTopLevel loads opencode.json as an ordered-insensitive map of raw values.
// A missing file yields an empty map. A file that is not valid JSON is an error
// (we refuse to clobber hand-edited/JSONC configs).
func readTopLevel(path string) (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]json.RawMessage{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("%s is not plain JSON (refusing to overwrite; remove comments or fix it first): %w", path, err)
	}
	return top, nil
}

// writeTopLevel serializes the top-level map deterministically (sorted keys,
// 2-space indent) and writes it atomically. Values pass through untouched, so
// keys hydra does not manage (agent, mcp, command, …) are preserved verbatim.
func writeTopLevel(path string, top map[string]json.RawMessage) error {
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, k := range keys {
		kb, _ := json.Marshal(k)
		// Re-indent each value with a one-level offset for readability.
		var v bytes.Buffer
		if err := json.Indent(&v, top[k], "  ", "  "); err != nil {
			v.Reset()
			v.Write(top[k])
		}
		fmt.Fprintf(&buf, "  %s: %s", kb, v.String())
		if i < len(keys)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("}\n")

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// providerEntry builds the JSON object for one provider.
func (c Configured) providerEntry() (json.RawMessage, error) {
	npm := c.NPM
	if npm == "" {
		npm = defaultNPM
	}
	opts := map[string]any{}
	if c.BaseURL != "" {
		opts["baseURL"] = c.BaseURL
	}
	if c.APIKeyRef != "" {
		opts["apiKey"] = c.APIKeyRef
	}
	entry := map[string]any{"npm": npm}
	if c.Name != "" {
		entry["name"] = c.Name
	}
	if len(opts) > 0 {
		entry["options"] = opts
	}
	models := map[string]any{}
	for id, name := range c.Models {
		if name != "" {
			models[id] = map[string]any{"name": name}
		} else {
			models[id] = map[string]any{}
		}
	}
	if len(models) > 0 {
		entry["models"] = models
	}
	return json.Marshal(entry)
}

// Configure merges the provider into the repo's opencode.json, preserving all
// other top-level keys. Only the "provider" key (and, if setDefaultModel is
// non-empty, "model") is touched.
func Configure(repoRoot string, c Configured, setDefaultModel string) error {
	if c.ID == "" {
		return fmt.Errorf("provider id is required")
	}
	path := ConfigPath(repoRoot)
	top, err := readTopLevel(path)
	if err != nil {
		return err
	}

	// Ensure $schema for editor validation (only when creating fresh).
	if _, ok := top["$schema"]; !ok {
		sb, _ := json.Marshal(schemaURL)
		top["$schema"] = sb
	}

	// Merge into the provider sub-map.
	providers := map[string]json.RawMessage{}
	if raw, ok := top["provider"]; ok {
		if err := json.Unmarshal(raw, &providers); err != nil {
			return fmt.Errorf("existing \"provider\" is not an object: %w", err)
		}
	}
	entry, err := c.providerEntry()
	if err != nil {
		return err
	}
	providers[c.ID] = entry
	pb, err := json.Marshal(providers)
	if err != nil {
		return err
	}
	top["provider"] = pb

	if setDefaultModel != "" {
		mb, _ := json.Marshal(setDefaultModel)
		top["model"] = mb
	}

	return writeTopLevel(path, top)
}

// Remove deletes a provider entry from the repo's opencode.json. It is a no-op
// if the file or entry is absent.
func Remove(repoRoot, id string) error {
	path := ConfigPath(repoRoot)
	top, err := readTopLevel(path)
	if err != nil {
		return err
	}
	raw, ok := top["provider"]
	if !ok {
		return nil
	}
	providers := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &providers); err != nil {
		return fmt.Errorf("existing \"provider\" is not an object: %w", err)
	}
	if _, ok := providers[id]; !ok {
		return nil
	}
	delete(providers, id)
	pb, _ := json.Marshal(providers)
	top["provider"] = pb
	return writeTopLevel(path, top)
}

// ListConfigured returns the provider ids present in the repo's opencode.json
// and the configured default model (if any).
func ListConfigured(repoRoot string) (ids []string, model string, err error) {
	top, err := readTopLevel(ConfigPath(repoRoot))
	if err != nil {
		return nil, "", err
	}
	if raw, ok := top["provider"]; ok {
		providers := map[string]json.RawMessage{}
		if err := json.Unmarshal(raw, &providers); err == nil {
			for k := range providers {
				ids = append(ids, k)
			}
			sort.Strings(ids)
		}
	}
	if raw, ok := top["model"]; ok {
		_ = json.Unmarshal(raw, &model)
	}
	return ids, model, nil
}
