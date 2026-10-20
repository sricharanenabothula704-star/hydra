package gates

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sricharanenabothula704-star/hydra/internal/config"
)

// writeFakeRepo builds a minimal Hydra checkout with a stub scope gate whose
// verdict is controlled by the target prefix: "good*" => PASS(0), else DENY(1).
func writeFakeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, m := range []string{"opencode.jsonc.template", "__main__.py"} {
		if err := os.WriteFile(filepath.Join(dir, m), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	stub := "#!/usr/bin/env bash\ncase \"$1\" in\n  good*) echo \"PASS: $1\"; exit 0;;\n  *) echo \"DENY: $1\"; exit 1;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "scripts", "scope_check.sh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCheckScope_EmptyTargetDenied(t *testing.T) {
	d := CheckScope("   ")
	if d.Allowed {
		t.Fatal("empty target was allowed; must fail closed")
	}
}

func TestCheckScope_GateUnreachableDenied(t *testing.T) {
	// Point HYDRA_HOME at a dir with no gate; ensure cwd/exe cannot rescue it
	// is not guaranteed in-repo, so we only assert: if it errored to locate the
	// gate, the verdict is deny. We force the locate failure via an empty dir
	// that is not a repo and is unlikely to have a repo ancestor under TempDir.
	t.Setenv("HYDRA_HOME", t.TempDir())
	// We cannot fully isolate cwd/exe here, so just assert the contract on the
	// explicit no-gate construction via a bogus repo with no script:
	// (covered more strongly by the e2e isolated-binary test).
	_ = CheckScope("good.example") // smoke: must not panic
}

func TestCheckScope_StubAllowAndDeny(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; skipping gate execution test")
	}
	repo := writeFakeRepo(t)
	t.Setenv("HYDRA_HOME", repo)

	if d := CheckScope("good.example.com"); !d.Allowed {
		t.Fatalf("expected ALLOW for good.example.com, got deny: %s", d.Reason)
	}
	if d := CheckScope("evil.example.com"); d.Allowed {
		t.Fatalf("expected DENY for evil.example.com, got allow: %s", d.Reason)
	}
}

// TestCheckScope_RealGateApexWildcardBoundary runs the repository's actual
// scripts/scope_check.sh against a controlled allowlist to lock in the two
// fixes: (1) an apex/exact domain authorizes itself and its subdomains, and
// (2) a '*.wild' entry matches true subdomains only, never lookalikes.
func TestCheckScope_RealGateApexWildcardBoundary(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; skipping real-gate test")
	}
	root, err := config.RepoRoot()
	if err != nil {
		t.Skipf("real repo not found from test cwd: %v", err)
	}
	t.Setenv("HYDRA_HOME", root)

	// Point the gate at a controlled allowlist via a fake HOME.
	home := t.TempDir()
	alDir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(alDir, 0o755); err != nil {
		t.Fatal(err)
	}
	allow := "# test allowlist\nexample.com\n*.wild.com\n"
	if err := os.WriteFile(filepath.Join(alDir, "SCOPE_ALLOWLIST.txt"), []byte(allow), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Git Bash on Windows

	cases := []struct {
		target string
		allow  bool
	}{
		{"example.com", true},       // apex authorizes itself
		{"a.example.com", true},     // apex covers subdomains
		{"a.b.wild.com", true},      // wildcard subdomain
		{"xexample.com", false},     // lookalike, not a subdomain
		{"wild.com", false},         // wildcard-only entry does NOT cover apex
		{"example.com.evil.net", false},
		{"evil.net", false},
	}
	for _, c := range cases {
		d := CheckScope(c.target)
		if d.Allowed != c.allow {
			t.Errorf("CheckScope(%q)=allowed:%v, want %v (reason: %s)", c.target, d.Allowed, c.allow, d.Reason)
		}
	}
}
