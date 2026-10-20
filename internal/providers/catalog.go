// Package providers manages the AI model providers hydra can connect to. It
// keeps a catalog of OpenAI-compatible providers and writes provider entries
// into a hydra-owned project opencode.json (merged by opencode with the user's
// global config — the global files are never modified).
package providers

import "strings"

// Entry describes a known provider in the catalog.
type Entry struct {
	ID        string // opencode provider id (config key)
	Name      string // display name
	BaseURL   string // OpenAI-compatible base URL (empty => user must supply)
	EnvKey    string // conventional API-key env var; "" for local/no-auth
	NPM       string // ai-sdk package; default @ai-sdk/openai-compatible
	Local     bool   // true for localhost providers (no API key)
	Preloaded bool   // opencode already ships this provider
	Note      string
}

const defaultNPM = "@ai-sdk/openai-compatible"

// npmOrDefault returns the entry's NPM package or the default.
func (e Entry) npm() string {
	if e.NPM != "" {
		return e.NPM
	}
	return defaultNPM
}

// Catalog is the built-in provider catalog. Base URLs are the providers'
// published OpenAI-compatible endpoints; verify against each provider's docs if
// one changes.
var Catalog = []Entry{
	{ID: "openrouter", Name: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1", EnvKey: "OPENROUTER_API_KEY", Preloaded: true, Note: "Hundreds of models incl. free tiers"},
	{ID: "nvidia", Name: "NVIDIA NIM", BaseURL: "https://integrate.api.nvidia.com/v1", EnvKey: "NVIDIA_API_KEY", Note: "build.nvidia.com hosted models"},
	{ID: "groq", Name: "Groq", BaseURL: "https://api.groq.com/openai/v1", EnvKey: "GROQ_API_KEY", Note: "Very fast inference"},
	{ID: "together", Name: "Together AI", BaseURL: "https://api.together.xyz/v1", EnvKey: "TOGETHER_API_KEY"},
	{ID: "google-aistudio", Name: "Google AI Studio", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai/", EnvKey: "GEMINI_API_KEY", Note: "Gemini via OpenAI-compatible shim"},
	{ID: "cerebras", Name: "Cerebras", BaseURL: "https://api.cerebras.ai/v1", EnvKey: "CEREBRAS_API_KEY"},
	{ID: "deepseek", Name: "DeepSeek", BaseURL: "https://api.deepseek.com/v1", EnvKey: "DEEPSEEK_API_KEY"},
	{ID: "mistral", Name: "Mistral", BaseURL: "https://api.mistral.ai/v1", EnvKey: "MISTRAL_API_KEY"},
	{ID: "fireworks", Name: "Fireworks", BaseURL: "https://api.fireworks.ai/inference/v1", EnvKey: "FIREWORKS_API_KEY"},
	{ID: "hyperbolic", Name: "Hyperbolic", BaseURL: "https://api.hyperbolic.xyz/v1", EnvKey: "HYPERBOLIC_API_KEY"},
	{ID: "xai", Name: "xAI (Grok)", BaseURL: "https://api.x.ai/v1", EnvKey: "XAI_API_KEY"},
	{ID: "ollama", Name: "Ollama (local)", BaseURL: "http://localhost:11434/v1", Local: true, Note: "Local models; no API key"},
	{ID: "lmstudio", Name: "LM Studio (local)", BaseURL: "http://localhost:1234/v1", Local: true, Note: "Local models; no API key"},
	{ID: "vllm", Name: "vLLM (local)", BaseURL: "http://localhost:8000/v1", Local: true, Note: "Local OpenAI-compatible server"},
}

// Lookup returns the catalog entry for id (case-insensitive), if present.
func Lookup(id string) (Entry, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, e := range Catalog {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// DefaultEnvKey returns the conventional env-var name for a provider's API key,
// generating one (HYDRA_<ID>_KEY) when the catalog has none.
func DefaultEnvKey(id string) string {
	if e, ok := Lookup(id); ok && e.EnvKey != "" {
		return e.EnvKey
	}
	up := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(id))
	return "HYDRA_" + up + "_KEY"
}
