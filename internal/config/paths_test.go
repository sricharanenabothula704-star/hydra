package config

import (
	"os"
	"path/filepath"
	"testing"
)

// makeFakeRepo creates a dir containing the given marker files.
func makeFakeRepo(t *testing.T, present []string) string {
	t.Helper()
	dir := t.TempDir()
	for _, m := range present {
		p := filepath.Join(dir, m)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRepoRoot_HydraHomeWithAllMarkers(t *testing.T) {
	repo := makeFakeRepo(t, markers)
	t.Setenv("HYDRA_HOME", repo)
	got, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot error: %v", err)
	}
	// Resolve symlinks for stable comparison on macOS temp dirs.
	wantR, _ := filepath.EvalSymlinks(repo)
	gotR, _ := filepath.EvalSymlinks(got)
	if gotR != wantR {
		t.Fatalf("RepoRoot = %q, want %q", gotR, wantR)
	}
}

func TestRepoRoot_IncompleteHydraHomeIsRejected(t *testing.T) {
	// Only one of the three markers present: must NOT be accepted as the repo.
	incomplete := makeFakeRepo(t, []string{"scripts/scope_check.sh"})
	t.Setenv("HYDRA_HOME", incomplete)
	got, err := RepoRoot()
	// It may still succeed by finding the real repo via cwd/exe fallback, but it
	// must never return the incomplete directory.
	if err == nil && got == incomplete {
		t.Fatalf("RepoRoot accepted incomplete dir %q as repo", incomplete)
	}
}

func TestIsRepo(t *testing.T) {
	full := makeFakeRepo(t, markers)
	if !isRepo(full) {
		t.Errorf("isRepo(full)=false, want true")
	}
	partial := makeFakeRepo(t, markers[:1])
	if isRepo(partial) {
		t.Errorf("isRepo(partial)=true, want false")
	}
	if isRepo(t.TempDir()) {
		t.Errorf("isRepo(empty)=true, want false")
	}
}
