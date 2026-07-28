package contentsafety

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/inference-sh/goutils/logging"
)

// gitleaksConfigURL is the remote config location; overridden in tests.
var gitleaksConfigURL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

// gitleaksConfig represents the top-level TOML structure.
type gitleaksConfig struct {
	Rules []gitleaksRule `toml:"rules"`
}

type gitleaksRule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	Keywords    []string `toml:"keywords"`
}

// livePatterns holds dynamically loaded patterns from gitleaks.
var (
	livePatterns     []*regexp.Regexp
	livePatternsOnce sync.Once
	livePatternsMu   sync.RWMutex
)

// LiveRedactionPatterns returns the combined set of hardcoded + gitleaks patterns.
// Gitleaks patterns are fetched once at first call (lazy init on first scan).
func LiveRedactionPatterns() []*regexp.Regexp {
	livePatternsOnce.Do(func() {
		// gitleaks patterns disabled — they're too aggressive for user content
		// (matched sports text, URL params, etc.) and broke JSON when used in
		// redactOutput. hardcoded patterns only until we have a proper allowlist.
		// fetched := fetchGitleaksPatterns()
		livePatternsMu.Lock()
		livePatterns = redactionPatterns()
		livePatternsMu.Unlock()
		logging.Info("api").Msg("gitleaks: disabled, using hardcoded patterns only")
	})
	livePatternsMu.RLock()
	defer livePatternsMu.RUnlock()
	return livePatterns
}

// fetchGitleaksPatterns downloads the gitleaks TOML config, parses it,
// and compiles Go-compatible regexes. Incompatible patterns are skipped.
func fetchGitleaksPatterns() []*regexp.Regexp {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(gitleaksConfigURL)
	if err != nil {
		logging.Warn("api").Msgf("gitleaks: fetch failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logging.Warn("api").Msgf("gitleaks: fetch returned %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	if err != nil {
		logging.Warn("api").Msgf("gitleaks: read failed: %v", err)
		return nil
	}

	var config gitleaksConfig
	if err := toml.Unmarshal(body, &config); err != nil {
		logging.Warn("api").Msgf("gitleaks: parse failed: %v", err)
		return nil
	}

	var patterns []*regexp.Regexp
	skipped := 0
	for _, rule := range config.Rules {
		if rule.Regex == "" {
			continue
		}

		// Rewrite Go-incompatible features
		cleaned := fixGitleaksRegex(rule.Regex)

		compiled, err := regexp.Compile(cleaned)
		if err != nil {
			skipped++
			continue
		}
		patterns = append(patterns, compiled)
	}

	if skipped > 0 {
		logging.Debug("api").Msgf("gitleaks: skipped %d incompatible patterns", skipped)
	}

	return patterns
}

// fixGitleaksRegex rewrites gitleaks regex features that Go RE2 doesn't support.
// Main issue: (?-i:...) inline flag toggle — we strip the flag wrapper.
func fixGitleaksRegex(pattern string) string {
	// Replace (?-i:...) with (?:...) — loses the case-sensitivity toggle
	// but keeps the grouping. This is a safe approximation since our scanner
	// is looking for credential patterns where case sensitivity is secondary.
	for {
		idx := strings.Index(pattern, "(?-")
		if idx < 0 {
			break
		}
		// Find the colon after the flags
		colon := strings.Index(pattern[idx:], ":")
		if colon < 0 {
			break
		}
		// Replace "(?-flags:" with "(?:"
		pattern = pattern[:idx] + "(?:" + pattern[idx+colon+1:]
	}

	// Replace (?s:...) inline dotall with (?:...)
	pattern = strings.ReplaceAll(pattern, "(?s:", "(?:")

	// Some patterns use \x60 for backtick — Go supports this, but verify
	// the overall pattern compiles by letting the caller handle errors.

	return pattern
}

// ReloadGitleaksPatterns forces a re-fetch of gitleaks patterns.
// Useful for scheduled refresh without restart.
func ReloadGitleaksPatterns() (int, error) {
	fetched := fetchGitleaksPatterns()
	if fetched == nil {
		return 0, fmt.Errorf("failed to fetch gitleaks patterns")
	}
	livePatternsMu.Lock()
	livePatterns = append(redactionPatterns(), fetched...)
	livePatternsMu.Unlock()
	return len(fetched), nil
}
