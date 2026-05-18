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

// CheckVersion checks if there's a new version available compared to the provided version
func CheckVersion(manifestUrl string, platform string, arch string, currentVersion string) (*UpdateInfo, error) {
	resp, err := http.Get(manifestUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}
	defer resp.Body.Close()

	manifestContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
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

	updateAvailable := IsNewerVersion(manifest.Version, currentVersion)

	return &UpdateInfo{
		CurrentVersion:   currentVersion,
		AvailableVersion: manifest.Version,
		ReleaseDate:      manifest.ReleaseDate,
		DownloadURL:      build.URL,
		SHA256:           build.SHA256,
		UpdateAvailable:  updateAvailable,
		Aliases:          manifest.Aliases,
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
