package providers

import (
	"encoding/json"
	"os"
	"testing"
)

// seed writes an opencode.json resembling the user's real one: agents, mcp and
// an existing provider that must all survive provider edits.
func seed(t *testing.T, dir string) {
	t.Helper()
	cfg := `{
  "$schema": "https://opencode.ai/config.json",
  "model": "opencode/space-bunny-free",
  "agent": { "hunter": { "mode": "primary" }, "build": { "permission": { "edit": "allow", "bash": "allow" } } },
  "mcp": { "bugbounty": { "enabled": true, "environment": { "SAFE_MODE": "true", "ALLOWED_TARGETS": "" } } },
  "command": { "hunt": { "template": "run scope_check first" } },
  "provider": { "bynara": { "npm": "@ai-sdk/openai-compatible", "options": { "baseURL": "https://bynara/v1" } } }
}`
	if err := os.WriteFile(ConfigPath(dir), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
}

// parse reloads opencode.json as a generic map.
func parse(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not valid JSON: %v\n%s", err, b)
	}
	return m
}

func TestConfigurePreservesOtherKeys(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir)

	err := Configure(dir, Configured{
		ID: "nvidia", Name: "NVIDIA NIM",
		BaseURL: "https://integrate.api.nvidia.com/v1", APIKeyRef: "{env:NVIDIA_API_KEY}",
		Models: map[string]string{"moonshotai/kimi-k2": "Kimi K2"},
	}, "nvidia/moonshotai/kimi-k2")
	if err != nil {
		t.Fatal(err)
	}

	m := parse(t, dir)

	// Untouched keys must survive verbatim.
	if _, ok := m["agent"]; !ok {
		t.Error("agent key was dropped")
	}
	mcp, ok := m["mcp"].(map[string]any)
	if !ok {
		t.Fatal("mcp key lost or wrong type")
	}
	bb := mcp["bugbounty"].(map[string]any)["environment"].(map[string]any)
	if bb["SAFE_MODE"] != "true" || bb["ALLOWED_TARGETS"] != "" {
		t.Errorf("mcp SAFE_MODE/ALLOWED_TARGETS altered: %v", bb)
	}
	if _, ok := m["command"]; !ok {
		t.Error("command key was dropped")
	}

	// Provider merged, existing provider kept, model updated.
	prov := m["provider"].(map[string]any)
	if _, ok := prov["bynara"]; !ok {
		t.Error("existing provider bynara was dropped")
	}
	nv, ok := prov["nvidia"].(map[string]any)
	if !ok {
		t.Fatal("nvidia provider not written")
	}
	if nv["npm"] != "@ai-sdk/openai-compatible" {
		t.Errorf("nvidia npm wrong: %v", nv["npm"])
	}
	opts := nv["options"].(map[string]any)
	if opts["apiKey"] != "{env:NVIDIA_API_KEY}" {
		t.Errorf("apiKey ref wrong: %v", opts["apiKey"])
	}
	if m["model"] != "nvidia/moonshotai/kimi-k2" {
		t.Errorf("model not updated: %v", m["model"])
	}
}

func TestConfigureCreatesFreshFile(t *testing.T) {
	dir := t.TempDir()
	if err := Configure(dir, Configured{ID: "groq", Name: "Groq", BaseURL: "https://api.groq.com/openai/v1", APIKeyRef: "{env:GROQ_API_KEY}"}, ""); err != nil {
		t.Fatal(err)
	}
	m := parse(t, dir)
	if m["$schema"] != schemaURL {
		t.Errorf("schema not set on fresh file: %v", m["$schema"])
	}
	if _, ok := m["provider"].(map[string]any)["groq"]; !ok {
		t.Error("groq not written to fresh file")
	}
}

func TestRemoveProvider(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir)
	if err := Remove(dir, "bynara"); err != nil {
		t.Fatal(err)
	}
	prov := parse(t, dir)["provider"].(map[string]any)
	if _, ok := prov["bynara"]; ok {
		t.Error("bynara not removed")
	}
	// Other keys still present.
	if _, ok := parse(t, dir)["agent"]; !ok {
		t.Error("agent dropped during remove")
	}
}

func TestConfigureRefusesInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(ConfigPath(dir), []byte("{ // a comment\n }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Configure(dir, Configured{ID: "groq"}, ""); err == nil {
		t.Fatal("expected refusal to overwrite non-plain-JSON file")
	}
}
