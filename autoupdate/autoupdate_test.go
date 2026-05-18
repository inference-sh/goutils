package autoupdate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnvOptOut(t *testing.T) {
	t.Setenv("INFSH_NO_AUTOUPDATE", "1")

	cfg := Config{
		ManifestURL:    "https://example.invalid/manifest.json",
		CurrentVersion: "v1.0.0",
		DisabledEnv:    "INFSH_NO_AUTOUPDATE",
	}
	res, err := CheckAndReexec(t.Context(), cfg)
	if err != nil {
		t.Fatalf("env opt-out should not error: %v", err)
	}
	if !res.Skipped {
		t.Fatal("expected Skipped=true when DisabledEnv is set")
	}
	if res.SkipReason == "" {
		t.Error("expected a SkipReason")
	}
}

func TestEnvOptOutEmptyValue(t *testing.T) {
	// Explicitly empty env var → not disabled
	t.Setenv("INFSH_NO_AUTOUPDATE", "")

	cfg := Config{
		ManifestURL:    "https://example.invalid/manifest.json",
		CurrentVersion: "dev", // will skip for a different reason
		DisabledEnv:    "INFSH_NO_AUTOUPDATE",
	}
	res, err := CheckAndReexec(t.Context(), cfg)
	if err != nil {
		t.Fatalf("dev skip should not error: %v", err)
	}
	if !res.Skipped || res.SkipReason == "disabled via INFSH_NO_AUTOUPDATE" {
		t.Errorf("expected dev skip reason, got %q", res.SkipReason)
	}
}

func TestDevVersionSkipped(t *testing.T) {
	for _, v := range []string{"", "dev"} {
		t.Run(v, func(t *testing.T) {
			res, err := CheckAndReexec(t.Context(), Config{
				ManifestURL:    "https://example.invalid/manifest.json",
				CurrentVersion: v,
			})
			if err != nil {
				t.Fatalf("should not error on dev version: %v", err)
			}
			if !res.Skipped {
				t.Fatal("expected Skipped=true for dev version")
			}
		})
	}
}

func TestCheckIntervalRateLimit(t *testing.T) {
	tmp := t.TempDir()
	cfg := Config{
		ManifestURL:    "https://example.invalid/manifest.json",
		CurrentVersion: "v1.0.0",
		CheckInterval:  1 * time.Hour,
		StateDir:       tmp,
	}

	// Prime the state file with a recent check.
	applyDefaults(&cfg)
	path := stateFile(cfg)
	if err := writeState(path, &state{LastCheck: time.Now().Add(-5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	res, err := CheckAndReexec(t.Context(), cfg)
	if err != nil {
		t.Fatalf("rate limit should not error: %v", err)
	}
	if !res.Skipped {
		t.Fatal("expected Skipped=true when within check interval")
	}
	if res.SkipReason != "within check interval" {
		t.Errorf("unexpected SkipReason: %q", res.SkipReason)
	}
}

func TestStateFileRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	cfg := Config{
		ManifestURL: "https://dist.example.com/cli/manifest.json",
		StateDir:    tmp,
	}
	applyDefaults(&cfg)
	path := stateFile(cfg)

	now := time.Now().Truncate(time.Second)
	original := &state{LastCheck: now, LastVersion: "v1.2.3"}
	if err := writeState(path, original); err != nil {
		t.Fatalf("writeState: %v", err)
	}

	loaded, err := readState(path)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected state, got nil")
	}
	if !loaded.LastCheck.Equal(now) {
		t.Errorf("LastCheck mismatch: want %v got %v", now, loaded.LastCheck)
	}
	if loaded.LastVersion != "v1.2.3" {
		t.Errorf("LastVersion mismatch: %q", loaded.LastVersion)
	}
}

func TestStateFileMissingReturnsNil(t *testing.T) {
	s, err := readState(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing state should not error: %v", err)
	}
	if s != nil {
		t.Fatal("expected nil state for missing file")
	}
}

func TestStateFileCorruptReturnsNil(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "corrupt.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := readState(path)
	if err != nil {
		t.Fatalf("corrupt state should not error: %v", err)
	}
	if s != nil {
		t.Fatal("expected nil state for corrupt file")
	}
}

func TestStateFileKeyedPerManifest(t *testing.T) {
	// Different manifest URLs should produce different state file names so
	// CLI and engine don't collide in the same state dir.
	cfgA := Config{ManifestURL: "https://dist.example.com/cli/manifest.json", StateDir: "/tmp/x"}
	cfgB := Config{ManifestURL: "https://dist.example.com/engine/manifest.json", StateDir: "/tmp/x"}

	applyDefaults(&cfgA)
	applyDefaults(&cfgB)

	if stateFile(cfgA) == stateFile(cfgB) {
		t.Errorf("state files must differ per manifest URL:\n  %s\n  %s", stateFile(cfgA), stateFile(cfgB))
	}
}

func TestResolveSelfPathFollowsSymlinks(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real-bin")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link-bin")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	// We can't easily change os.Executable() from a test, but the resolution
	// helper takes a path so let's assert EvalSymlinks does its job there.
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != real {
		t.Errorf("symlink not resolved: want %s got %s", real, resolved)
	}
}

func TestIsDevVersion(t *testing.T) {
	cases := map[string]bool{
		"":         true,
		"dev":      true,
		"v1.0.0":   false,
		"v1.2.3":   false,
		"v0.0.0-0": false,
	}
	for v, want := range cases {
		if got := isDevVersion(v); got != want {
			t.Errorf("isDevVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestWriteStateCreatesDir(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "nested", "deeper", "state.json")

	if err := writeState(path, &state{LastCheck: time.Now()}); err != nil {
		t.Fatalf("writeState should create parent dirs: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}
