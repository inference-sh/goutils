package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// LightManifest represents the update manifest structure
type LightManifest struct {
	// Product is the dist directory the manifest belongs to ("cli",
	// "engine"); a signed manifest must name the one it was fetched from.
	Product     string                   `json:"product,omitempty"`
	Version     string                   `json:"version"`
	ReleaseDate time.Time                `json:"releaseDate"`
	Builds      map[string]ManifestBuild `json:"builds"`
	// Aliases is an optional list of symlink names to create alongside the
	// installed binary (e.g. ["infsh"] for the inferencesh CLI). The installer
	// and the autoupdate flow both consume this so a single source of truth
	// drives alias creation. Unix only — ignored on Windows.
	Aliases []string `json:"aliases,omitempty"`
}

// ManifestBuild represents a single build in the manifest
type ManifestBuild struct {
	URL        string `json:"url"`
	BinaryName string `json:"binaryName"`
	SHA256     string `json:"sha256"`
}

// UpdateInfo represents the update check result
type UpdateInfo struct {
	CurrentVersion   string    `json:"currentVersion"`
	AvailableVersion string    `json:"availableVersion"`
	ReleaseDate      time.Time `json:"releaseDate"`
	DownloadURL      string    `json:"downloadUrl"`
	SHA256           string    `json:"sha256"`
	UpdateAvailable  bool      `json:"updateAvailable"`
	Aliases          []string  `json:"aliases,omitempty"`
	// Signed is true when the manifest's signature was verified.
	Signed bool `json:"signed,omitempty"`
}

// IsNewerVersion returns true if available is a higher semver than current.
// Both inputs are normalized to have a "v" prefix before comparison.
func IsNewerVersion(available, current string) bool {
	if !strings.HasPrefix(available, "v") {
		available = "v" + available
	}
	if !strings.HasPrefix(current, "v") {
		current = "v" + current
	}
	return semver.Compare(available, current) > 0
}

// manifestClient bounds the manifest fetch: it runs before every command, so a
// hung connection must not hang the CLI.
var manifestClient = &http.Client{Timeout: 10 * time.Second}

const (
	maxManifestSize  = 1 << 20
	maxSignatureSize = 16 << 10
)

// fetch GETs url. found is false on a 404; any other non-200 is an error.
func fetch(url string, limit int64) (body []byte, found bool, err error) {
	resp, err := manifestClient.Get(url)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		return nil, false, fmt.Errorf("%s: larger than %d bytes", url, limit)
	}
	return body, true, nil
}

// verifyFetched applies the signature policy (see RequireSignature) to a
// manifest fetched from manifestURL. signed reports whether a signature was
// verified.
func verifyFetched(manifestURL string, manifest []byte) (signed bool, err error) {
	keys := currentKeys()
	if len(keys) == 0 {
		if RequireSignature {
			return false, fmt.Errorf("%w: this binary has no trusted release keys", ErrUnsigned)
		}
		return false, nil
	}
	sigURL, err := SignatureURL(manifestURL)
	if err != nil {
		return false, err
	}
	sig, found, err := fetch(sigURL, maxSignatureSize)
	if err != nil {
		return false, fmt.Errorf("failed to get manifest signature: %w", err)
	}
	if !found {
		if RequireSignature {
			return false, fmt.Errorf("%w: no %s", ErrUnsigned, sigURL)
		}
		Warnf("release manifest %s is not signed; accepting it until signatures are required", manifestURL)
		return false, nil
	}
	if err := VerifyManifest(manifest, sig, keys, ProductFromURL(manifestURL)); err != nil {
		return false, fmt.Errorf("%s: %w", manifestURL, err)
	}
	return true, nil
}

// CheckVersion checks if there's a new version available compared to the
// provided version. The manifest's signature is checked as RequireSignature
// and SetTrustedKeys say.
func CheckVersion(manifestUrl string, platform string, arch string, currentVersion string) (*UpdateInfo, error) {
	manifestContent, found, err := fetch(manifestUrl, maxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("failed to get manifest: %s: 404 Not Found", manifestUrl)
	}

	signed, err := verifyFetched(manifestUrl, manifestContent)
	if err != nil {
		return nil, err
	}

	var manifest LightManifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// Get the build for current platform
	key := fmt.Sprintf("%s-%s", platform, arch)
	build, ok := manifest.Builds[key]
	if !ok {
		return nil, fmt.Errorf("no build available for platform: %s", key)
	}
	// The signature covers the binary only through its digest; without
	// one, binfetch would install whatever the URL serves.
	if signed && build.SHA256 == "" {
		return nil, fmt.Errorf("%s: %w: build %s has no sha256", manifestUrl, ErrBadSignature, key)
	}

	updateAvailable := IsNewerVersion(manifest.Version, currentVersion)

	return &UpdateInfo{
		CurrentVersion:   currentVersion,
		AvailableVersion: manifest.Version,
		ReleaseDate:      manifest.ReleaseDate,
		DownloadURL:      build.URL,
		SHA256:           build.SHA256,
		UpdateAvailable:  updateAvailable,
		Aliases:          manifest.Aliases,
		Signed:           signed,
	}, nil
}

// PrintUpdateInfo checks for updates and prints version info with update instructions.
// productName is the display name (e.g. "inference.sh"), updateCmd is the update instruction
// (e.g. "run `infsh-engine update` or `curl -fsSL https://engine.inference.sh | sh`").
func PrintUpdateInfo(manifestUrl, platform, arch, currentVersion, productName, updateCmd string) {
	bold := "\033[1m"
	dim := "\033[2m"
	yellow := "\033[33m"
	reset := "\033[0m"

	updateInfo, err := CheckVersion(manifestUrl, platform, arch, currentVersion)
	if err != nil {
		fmt.Printf("%s%s%s %s%s%s\n\n",
			bold, productName, reset,
			dim, currentVersion, reset,
		)
		return
	}

	if updateInfo.UpdateAvailable {
		fmt.Printf("%s%s%s %s%s%s -> %s%s (%s)%s\n\n",
			bold, productName, reset,
			dim, currentVersion, reset,
			yellow, updateInfo.AvailableVersion, updateCmd, reset,
		)
	} else {
		fmt.Printf("%s%s%s %s%s%s\n\n",
			bold, productName, reset,
			dim, currentVersion, reset,
		)
	}
}
