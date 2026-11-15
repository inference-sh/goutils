package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testManifest = `{"product":"cli","version":"v1.2.0","builds":{"linux-amd64":{"url":"https://dist.inference.sh/cli/v1.2.0/x.tar.gz","binaryName":"x.tar.gz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`

func keygenForTest(t *testing.T) (priv, pub string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if err := run([]string{"keygen"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`"([A-Za-z0-9+/=]{44})", // added`).FindStringSubmatch(errOut.String())
	if m == nil {
		t.Fatalf("no Go key line in %q", errOut.String())
	}
	if strings.Contains(errOut.String(), strings.TrimSpace(out.String())) {
		t.Fatal("private key printed on stderr")
	}
	return strings.TrimSpace(out.String()), m[1]
}

func TestKeygenSignVerify(t *testing.T) {
	priv, pub := keygenForTest(t)
	_, otherPub := keygenForTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(testManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELEASE_MANIFEST_SIGNING_KEY", priv)

	var out bytes.Buffer
	if err := run([]string{"sign", path}, &out, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"pubkey"}, &out, &out); err != nil || strings.TrimSpace(out.String()) != pub {
		t.Fatalf("pubkey = %q, %v; want %q", out.String(), err, pub)
	}
	if err := run([]string{"verify", "-keys", otherPub + "," + pub, "-product", "cli", path}, &out, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := run([]string{"verify", "-keys", pub, "-product", "engine", path}, &out, &out); err == nil {
		t.Fatal("verify accepted the wrong product")
	}
	if err := run([]string{"verify", "-keys", otherPub, "-product", "cli", path}, &out, &out); err == nil {
		t.Fatal("verify accepted the wrong key")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(testManifest, "v1.2.0", "v1.2.1", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "-keys", pub, "-product", "cli", path}, &out, &out); err == nil {
		t.Fatal("verify accepted a tampered manifest")
	}
}

func TestSignRotationWritesALinePerKey(t *testing.T) {
	a, pa := keygenForTest(t)
	b, pb := keygenForTest(t)
	path := filepath.Join(t.TempDir(), "manifest.json")
	os.WriteFile(path, []byte(testManifest), 0o644)
	t.Setenv("RELEASE_MANIFEST_SIGNING_KEY", a+"\n"+b)
	var out bytes.Buffer
	if err := run([]string{"sign", path}, &out, &out); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(path + ".sig")
	if n := strings.Count(string(sig), "\n"); n != 2 {
		t.Fatalf("%d lines, want 2", n)
	}
	for _, pub := range []string{pa, pb} {
		if err := run([]string{"verify", "-keys", pub, "-product", "cli", path}, &out, &out); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignRefuses(t *testing.T) {
	priv, _ := keygenForTest(t)
	cases := map[string]string{
		"no product": strings.Replace(testManifest, `"product":"cli",`, "", 1),
		"no sha256":  regexp.MustCompile(`"sha256":"a+"`).ReplaceAllString(testManifest, `"sha256":""`),
		"not json":   "<html>",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			os.WriteFile(path, []byte(body), 0o644)
			t.Setenv("RELEASE_MANIFEST_SIGNING_KEY", priv)
			var out bytes.Buffer
			if err := run([]string{"sign", path}, &out, &out); err == nil {
				t.Fatal("signed")
			}
			if _, err := os.Stat(path + ".sig"); err == nil {
				t.Fatal("wrote a signature")
			}
		})
	}
	t.Run("no key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifest.json")
		os.WriteFile(path, []byte(testManifest), 0o644)
		t.Setenv("RELEASE_MANIFEST_SIGNING_KEY", "")
		var out bytes.Buffer
		if err := run([]string{"sign", path}, &out, &out); err == nil {
			t.Fatal("signed without a key")
		}
	})
	t.Run("malformed key is not echoed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifest.json")
		os.WriteFile(path, []byte(testManifest), 0o644)
		t.Setenv("RELEASE_MANIFEST_SIGNING_KEY", "c2VjcmV0LXZhbHVl")
		var out bytes.Buffer
		err := run([]string{"sign", path}, &out, &out)
		if err == nil || strings.Contains(err.Error(), "c2VjcmV0LXZhbHVl") {
			t.Fatalf("err = %v", err)
		}
	})
}
