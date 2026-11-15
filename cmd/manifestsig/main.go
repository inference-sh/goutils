// Command manifestsig makes and checks the ed25519 signatures on release
// manifests that goutils/updater verifies.
//
//	manifestsig keygen
//	    Prints a new private key on stdout and, on stderr, the public key as
//	    the Go line to add to a binary's trusted keys. Pipe stdout straight
//	    into the secret store so the private key is never written to disk
//	    (bash; one key for every product, in each repo's release environment):
//
//	    go run github.com/inference-sh/goutils/cmd/manifestsig keygen \
//	      | tee >(gh secret set RELEASE_MANIFEST_SIGNING_KEY --repo inference-sh/cli --env release) \
//	      | gh secret set RELEASE_MANIFEST_SIGNING_KEY --repo inference-sh/engine --env release
//
//	manifestsig sign [-key-env NAME] [-o FILE] manifest.json
//	    Signs manifest.json with the private key(s) in $NAME (default
//	    RELEASE_MANIFEST_SIGNING_KEY; several keys separated by whitespace sign
//	    once each, for rotation) and writes manifest.json.sig.
//
//	manifestsig pubkey [-key-env NAME]
//	    Prints the public key of each private key in $NAME, one per line.
//
//	manifestsig verify -keys K1,K2 [-product P] manifest.json [manifest.json.sig]
//	    Exits non-zero unless the signature verifies under one of the keys
//	    and the manifest names product P.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/inference-sh/goutils/updater"
)

const defaultKeyEnv = "RELEASE_MANIFEST_SIGNING_KEY"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "manifestsig:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: manifestsig keygen | sign | pubkey | verify (see go doc github.com/inference-sh/goutils/cmd/manifestsig)")
	}
	switch args[0] {
	case "keygen":
		return keygen(stdout, stderr)
	case "sign":
		return sign(args[1:], stdout)
	case "pubkey":
		return pubkey(args[1:], stdout)
	case "verify":
		return verify(args[1:], stdout)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func keygen(stdout, stderr io.Writer) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, b64(priv.Seed()))
	fmt.Fprintf(stderr, "Private key written to stdout: store it only as the GitHub Actions secret %s.\n", defaultKeyEnv)
	fmt.Fprintf(stderr, "Public key, for the trusted key list in each binary:\n\n\t%q, // added %s\n\n", updater.EncodePublicKey(pub), time.Now().UTC().Format("2006-01-02"))
	return nil
}

// privateKeys reads the whitespace-separated private keys in env var name.
func privateKeys(name string) ([]ed25519.PrivateKey, error) {
	raw := os.Getenv(name)
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil, fmt.Errorf("$%s is empty", name)
	}
	keys := make([]ed25519.PrivateKey, 0, len(fields))
	for i, f := range fields {
		k, err := updater.ParsePrivateKey(f)
		if err != nil {
			// The error never quotes the value: this runs in CI logs.
			return nil, fmt.Errorf("$%s key %d: %w", name, i+1, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func sign(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyEnv := fs.String("key-env", defaultKeyEnv, "environment variable holding the private key(s)")
	out := fs.String("o", "", "signature file (default <manifest>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: manifestsig sign [-key-env NAME] [-o FILE] manifest.json")
	}
	path := fs.Arg(0)
	if *out == "" {
		*out = path + ".sig"
	}
	keys, err := privateKeys(*keyEnv)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	product, err := checkSignable(manifest)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var sig strings.Builder
	pubs := make([]ed25519.PublicKey, 0, len(keys))
	for _, k := range keys {
		sig.WriteString(updater.SignManifest(k, manifest))
		pubs = append(pubs, k.Public().(ed25519.PublicKey))
	}
	if err := updater.VerifyManifest(manifest, []byte(sig.String()), pubs, product); err != nil {
		return fmt.Errorf("self-check: %w", err)
	}
	if err := os.WriteFile(*out, []byte(sig.String()), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s -> %s with %d key(s)\n", path, *out, len(keys))
	return nil
}

func pubkey(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	keyEnv := fs.String("key-env", defaultKeyEnv, "environment variable holding the private key(s)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := privateKeys(*keyEnv)
	if err != nil {
		return err
	}
	for _, k := range keys {
		fmt.Fprintln(stdout, updater.EncodePublicKey(k.Public().(ed25519.PublicKey)))
	}
	return nil
}

func verify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	keysFlag := fs.String("keys", "", "comma-separated base64 public keys")
	product := fs.String("product", "", "product the manifest must name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 || *keysFlag == "" {
		return errors.New("usage: manifestsig verify -keys K1,K2 [-product P] manifest.json [manifest.json.sig]")
	}
	var pubs []ed25519.PublicKey
	for _, s := range strings.Split(*keysFlag, ",") {
		k, err := updater.ParsePublicKey(s)
		if err != nil {
			return err
		}
		pubs = append(pubs, k)
	}
	path := fs.Arg(0)
	sigPath := path + ".sig"
	if fs.NArg() == 2 {
		sigPath = fs.Arg(1)
	}
	manifest, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	if err := updater.VerifyManifest(manifest, sig, pubs, *product); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: signature OK\n", path)
	return nil
}

// checkSignable refuses a manifest a binary would refuse once signed, so the
// release fails here instead of every update check failing later.
func checkSignable(manifest []byte) (product string, err error) {
	var m updater.LightManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return "", fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if m.Product == "" {
		return "", errors.New(`manifest has no "product" (the dist directory it is published under, e.g. "cli")`)
	}
	if len(m.Builds) == 0 {
		return "", errors.New("manifest has no builds")
	}
	for platform, b := range m.Builds {
		if b.SHA256 == "" {
			return "", fmt.Errorf("build %s has no sha256", platform)
		}
	}
	return m.Product, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
