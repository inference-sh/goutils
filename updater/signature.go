package updater

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Release manifests are signed keyless with Sigstore. The release workflow
// asks GitHub Actions for an OIDC token, Fulcio turns it into a short-lived
// certificate naming the workflow (repository, workflow file, ref), the
// manifest's exact bytes are signed with it, and the signature is logged in
// Rekor. The bundle (certificate, signature, log entry) is published next to
// the manifest at <manifest URL>.sigstore.json, the name cosign and GitHub
// artifact attestations use.
//
// Nothing is pinned by key. A binary pins who may sign each product's
// channels (Products) and trusts Sigstore's public-good roots, which it
// keeps current through TUF (see trustroot.go). There is no private key to
// keep or rotate.
//
// The bundle covers the manifest's exact bytes, so readers that ignore it
// (install.sh, npm, Scoop, binaries already in the field) see the manifest
// unchanged.

// OIDCIssuer is the issuer GitHub Actions tokens carry. Fulcio records it in
// the certificate, and only certificates from it are accepted.
const OIDCIssuer = "https://token.actions.githubusercontent.com"

// BundleSuffix is appended to a manifest URL's path to find its bundle.
const BundleSuffix = ".sigstore.json"

// VersionSegment in a Channel path stands for the manifest's own version.
const VersionSegment = "{version}"

// Signer is the GitHub Actions workflow whose certificates may sign a
// channel's manifests.
type Signer struct {
	// Repository is "owner/name".
	Repository string
	// Workflow is the workflow file's path in the repository.
	Workflow string
	// Refs are the git refs the workflow may run from: the ref of the event
	// that started the run (refs/heads/main for a push to main). The
	// release tag is created during the run, so it is never this ref.
	Refs []string
}

// Identity is the certificate subject (SAN URI) a run of the workflow from
// ref gets: https://github.com/<repo>/<workflow>@<ref>.
func (s Signer) Identity(ref string) string {
	return "https://github.com/" + s.Repository + "/" + s.Workflow + "@" + ref
}

// sanRegexp matches the identity of every allowed ref, and nothing else.
func (s Signer) sanRegexp() string {
	alts := make([]string, len(s.Refs))
	for i, ref := range s.Refs {
		alts[i] = regexp.QuoteMeta(s.Identity(ref))
	}
	return "^(?:" + strings.Join(alts, "|") + ")$"
}

// Channel is one release line of a product: who signs it, where its
// manifests are served, and what its versions look like. A signed manifest
// names its channel ("channel": "stable"); it verifies only if that
// channel's signer made it, it is served at one of that channel's paths,
// and its version matches the channel's pattern. So a manifest signed for
// one channel is refused at another channel's URL, and a dev-signed canary
// can never pass as stable.
type Channel struct {
	Name   string
	Signer Signer
	// Paths are where the channel's manifests are served, relative to the
	// product's dist directory. VersionSegment matches one path segment,
	// which must equal the manifest's version.
	Paths []string
	// Version is a regexp the manifest's version must match.
	Version string
}

// Product is a released binary whose manifests are signed.
type Product struct {
	// Name is the product's dist directory ("cli" for
	// https://dist.inference.sh/cli/manifest.json). A signed manifest names
	// it in its "product" field, so a bundle valid for one product's
	// manifest can't install another product (both are signed by
	// workflows of the same organisation, and binfetch installs the first
	// file in whatever archive the manifest names).
	Name     string
	Channels []Channel
	// Required is the rollout switch for this product (see the
	// *SignatureRequired constants).
	Required bool
}

// The rollout switch, one per product.
//
// false (phase 1): a manifest with no bundle is accepted, and Warnf reports
// it. A manifest with a bundle must verify: a bad signature, another
// signer, the wrong product or channel, or a picked build with no sha256 is
// refused.
//
// true (phase 2): a manifest with no bundle is refused too (ErrUnsigned).
//
// Flip a product's constant once every manifest its released binaries can
// be pointed at has a bundle that verifies, and the binaries that verify
// have been out long enough that most installs run them. For the engine
// that includes channels/canary.json and every <version>/manifest.json a
// pin, rollback or `engine update vX` can name.
const (
	CLISignatureRequired    = false
	EngineSignatureRequired = false
)

const (
	stableVersion = `^v[0-9]+\.[0-9]+\.[0-9]+$`
	canaryVersion = `^v[0-9]+\.[0-9]+\.[0-9]+-canary\.[0-9]+$`
)

// Products maps a dist directory to who signs each of its channels. A
// manifest URL whose first path segment is not here is not checked (a test
// server, a manifest on another host's layout).
//
// Stable is released by CI on a push to main; the engine's canary by CI on a
// push to dev.
var Products = map[string]Product{
	"cli": {
		Name: "cli",
		Channels: []Channel{{
			Name:    "stable",
			Signer:  Signer{Repository: "inference-sh/cli", Workflow: ".github/workflows/release.yml", Refs: []string{"refs/heads/main"}},
			Paths:   []string{"manifest.json", VersionSegment + "/manifest.json"},
			Version: stableVersion,
		}},
		Required: CLISignatureRequired,
	},
	"engine": {
		Name: "engine",
		Channels: []Channel{{
			Name:    "stable",
			Signer:  Signer{Repository: "inference-sh/engine", Workflow: ".github/workflows/release.yml", Refs: []string{"refs/heads/main"}},
			Paths:   []string{"manifest.json", VersionSegment + "/manifest.json"},
			Version: stableVersion,
		}, {
			Name:    "canary",
			Signer:  Signer{Repository: "inference-sh/engine", Workflow: ".github/workflows/release.yml", Refs: []string{"refs/heads/dev"}},
			Paths:   []string{"channels/canary.json", VersionSegment + "/manifest.json"},
			Version: canaryVersion,
		}},
		Required: EngineSignatureRequired,
	},
}

// Warnf reports an accepted unsigned manifest. Binaries may redirect it.
var Warnf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

var (
	// ErrUnsigned is returned when a product requires signatures and its
	// manifest has no bundle.
	ErrUnsigned = errors.New("release manifest is not signed")
	// ErrBadSignature is returned when a bundle does not verify, was made by
	// another signer, or the manifest it covers is for another product,
	// channel, path or version.
	ErrBadSignature = errors.New("release manifest signature does not verify")
)

// BundleURL is where the bundle for manifestURL lives: the same URL with
// BundleSuffix appended to its path (a query string stays after it).
func BundleURL(manifestURL string) (string, error) {
	u, err := url.Parse(manifestURL)
	if err != nil {
		return "", fmt.Errorf("parse manifest URL: %w", err)
	}
	u.Path += BundleSuffix
	u.RawPath = ""
	return u.String(), nil
}

// ProductFromURL is the dist directory of manifestURL: the first segment of
// its path when the path has more than one
// ("https://dist.inference.sh/engine/channels/canary.json" is "engine"),
// otherwise "".
func ProductFromURL(manifestURL string) string {
	product, _ := splitURL(manifestURL)
	return product
}

// DistPathFromURL is manifestURL's path below its product's dist directory
// ("channels/canary.json" for the URL above).
func DistPathFromURL(manifestURL string) string {
	_, rest := splitURL(manifestURL)
	return rest
}

func splitURL(manifestURL string) (product, rest string) {
	u, err := url.Parse(manifestURL)
	if err != nil {
		return "", ""
	}
	parts := strings.SplitN(strings.Trim(u.Path, "/"), "/", 2)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// matchPath reports whether distPath is one of pattern's paths. version is
// the value VersionSegment must take; "" matches any one segment.
func matchPath(pattern, distPath, version string) bool {
	pp, dp := strings.Split(pattern, "/"), strings.Split(distPath, "/")
	if len(pp) != len(dp) {
		return false
	}
	for i := range pp {
		if pp[i] == VersionSegment {
			if dp[i] == "" || (version != "" && dp[i] != version) {
				return false
			}
			continue
		}
		if pp[i] != dp[i] {
			return false
		}
	}
	return true
}

func (c Channel) servedAt(distPath, version string) bool {
	for _, p := range c.Paths {
		if matchPath(p, distPath, version) {
			return true
		}
	}
	return false
}

// verifierOptions are the checks a public-good bundle must pass: the
// certificate was logged in a CT log, the signature is in Rekor, and the
// certificate was valid at the time Rekor recorded. Tests replace them
// (their virtual CA issues no SCTs).
var verifierOptions = []verify.VerifierOption{
	verify.WithSignedCertificateTimestamps(1),
	verify.WithTransparencyLog(1),
	verify.WithObserverTimestamps(1),
}

// parseBundle decodes a bundle. Tests replace it to hand in entities signed
// by a virtual Sigstore.
var parseBundle = func(data []byte) (verify.SignedEntity, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &b, nil
}

// VerifyManifest checks that bundleJSON is a Sigstore bundle over the exact
// bytes of manifest, served at distPath below p's dist directory: made by
// the signer of a channel of p served at distPath, and the manifest names p,
// that channel, and a version the channel allows (the one in distPath, if
// the path holds one). It returns the certificate identity that signed.
func VerifyManifest(manifest, bundleJSON []byte, p Product, distPath string) (string, error) {
	tm, err := trustedMaterial()
	if err != nil {
		return "", fmt.Errorf("sigstore trust root: %w", err)
	}
	entity, err := parseBundle(bundleJSON)
	if err != nil {
		return "", fmt.Errorf("%w: parse bundle: %v", ErrBadSignature, err)
	}
	return verifyEntity(tm, entity, manifest, p, distPath)
}

func verifyEntity(tm root.TrustedMaterial, entity verify.SignedEntity, manifest []byte, p Product, distPath string) (string, error) {
	v, err := verify.NewVerifier(tm, verifierOptions...)
	if err != nil {
		return "", err
	}

	// The signature first, against the signer of each channel served at
	// this path: nothing the manifest says is trusted before it verifies.
	var (
		ch      *Channel
		san     string
		lastErr = fmt.Errorf("no channel of %s is served at %q", p.Name, distPath)
	)
	for i := range p.Channels {
		c := &p.Channels[i]
		if !c.servedAt(distPath, "") {
			continue
		}
		if len(c.Signer.Refs) == 0 || c.Signer.Repository == "" || c.Signer.Workflow == "" {
			lastErr = fmt.Errorf("channel %s has no signer", c.Name)
			continue
		}
		id, err := verify.NewShortCertificateIdentity(OIDCIssuer, "", "", c.Signer.sanRegexp())
		if err != nil {
			return "", err
		}
		res, err := v.Verify(entity, verify.NewPolicy(
			verify.WithArtifact(bytes.NewReader(manifest)),
			verify.WithCertificateIdentity(id),
		))
		if err != nil {
			lastErr = err
			continue
		}
		ch = c
		if res.Signature != nil && res.Signature.Certificate != nil {
			san = res.Signature.Certificate.SubjectAlternativeName
		}
		break
	}
	if ch == nil {
		return "", fmt.Errorf("%w: %v", ErrBadSignature, lastErr)
	}

	var signed struct {
		Product string `json:"product"`
		Channel string `json:"channel"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &signed); err != nil {
		return "", fmt.Errorf("parse signed manifest: %w", err)
	}
	if signed.Product != p.Name {
		return "", fmt.Errorf("%w: manifest is for product %q, want %q", ErrBadSignature, signed.Product, p.Name)
	}
	if signed.Channel != ch.Name {
		return "", fmt.Errorf("%w: manifest is for channel %q, signed by the %s channel's signer", ErrBadSignature, signed.Channel, ch.Name)
	}
	if ok, _ := regexp.MatchString(ch.Version, signed.Version); !ok {
		return "", fmt.Errorf("%w: version %q is not a %s version", ErrBadSignature, signed.Version, ch.Name)
	}
	if !ch.servedAt(distPath, signed.Version) {
		return "", fmt.Errorf("%w: a %s manifest for %s is not served at %q", ErrBadSignature, ch.Name, signed.Version, distPath)
	}
	return san, nil
}

// VerifyManifestFiles is VerifyManifest for files on disk, for a release's
// self-check: the binary just built verifies the manifest just signed, for
// each dist path it is about to be published at.
func VerifyManifestFiles(manifestPath, bundlePath, product string, distPaths ...string) (string, error) {
	p, ok := Products[product]
	if !ok {
		return "", fmt.Errorf("unknown product %q", product)
	}
	if len(distPaths) == 0 {
		return "", errors.New("no dist path to verify the manifest at")
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(bundlePath)
	if err != nil {
		return "", err
	}
	var san string
	for _, dp := range distPaths {
		if san, err = VerifyManifest(manifest, b, p, dp); err != nil {
			return "", fmt.Errorf("at %s: %w", dp, err)
		}
	}
	// The same check CheckVersion makes of the build it picks, for every
	// build: the signature covers a binary only through its digest.
	var m LightManifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}
	if len(m.Builds) == 0 {
		return "", errors.New("manifest has no builds")
	}
	for key, build := range m.Builds {
		if build.SHA256 == "" {
			return "", fmt.Errorf("%w: build %s has no sha256", ErrBadSignature, key)
		}
	}
	return san, nil
}

// SelfCheckCommand is the hidden argument a released binary takes to run
// SelfCheck:
//
//	<binary> __verify-release-manifest <product> <manifest> <bundle> <dist path>...
//
// A release runs the binary it just built this way before publishing, with
// every path below the product's dist directory the manifest is about to be
// uploaded to, so a manifest the shipped binaries would refuse there is
// never published.
const SelfCheckCommand = "__verify-release-manifest"

// SelfCheck is VerifyManifestFiles for the binary being released: the
// manifest must also name binaryVersion, the version compiled into it.
func SelfCheck(product, manifestPath, bundlePath, binaryVersion string, distPaths ...string) (string, error) {
	san, err := VerifyManifestFiles(manifestPath, bundlePath, product, distPaths...)
	if err != nil {
		return "", err
	}
	var m LightManifest
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}
	if m.Version != binaryVersion {
		return "", fmt.Errorf("manifest is for %s, this binary is %s", m.Version, binaryVersion)
	}
	return san, nil
}

// RunSelfCheck handles os.Args when os.Args[1] is SelfCheckCommand: it runs
// SelfCheck, reports on stderr/stdout and returns the exit code. ok is false
// for any other argv, which the caller then handles as usual.
func RunSelfCheck(args []string, binaryVersion string) (code int, ok bool) {
	if len(args) < 2 || args[1] != SelfCheckCommand {
		return 0, false
	}
	if len(args) < 6 {
		fmt.Fprintf(os.Stderr, "usage: %s %s <product> <manifest.json> <bundle> <dist path>...\n", args[0], SelfCheckCommand)
		return 2, true
	}
	san, err := SelfCheck(args[2], args[3], args[4], binaryVersion, args[5:]...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release manifest self-check failed: %v\n", err)
		return 1, true
	}
	fmt.Printf("release manifest verified: product %s, version %s, at %s, signed by %s\n", args[2], binaryVersion, strings.Join(args[5:], " "), san)
	return 0, true
}
