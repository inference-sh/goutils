package contentsafety

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetGitleaksState(t *testing.T) {
	t.Helper()
	livePatternsOnce = sync.Once{}
	livePatterns = nil
}

func TestFixGitleaksRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "strips case-insensitive toggle",
			input: `(?-i:sk-[a-zA-Z0-9]{20})`,
			want:  `(?:sk-[a-zA-Z0-9]{20})`,
		},
		{
			name:  "strips dotall flag",
			input: `(?s:.*secret.*)`,
			want:  `(?:.*secret.*)`,
		},
		{
			name:  "multiple incompatible toggles",
			input: `(?-i:foo)(?-i:bar)`,
			want:  `(?:foo)(?:bar)`,
		},
		{
			name:  "no change when already compatible",
			input: `sk-[a-zA-Z0-9]{20}`,
			want:  `sk-[a-zA-Z0-9]{20}`,
		},
		{
			name:  "leaves malformed toggle prefix unchanged",
			input: `(?-broken`,
			want:  `(?-broken`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, fixGitleaksRegex(tt.input))
		})
	}
}

func TestFetchGitleaksPatterns_CompilesValidRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[[rules]]
id = "valid-rule"
regex = '''unique-gitleaks-test-token-[0-9]{6}'''

[[rules]]
id = "incompatible-rule"
regex = '''(?-i:password\s*=\s*\S+)'''

[[rules]]
id = "invalid-rule"
regex = '''(?P<unclosed'''

[[rules]]
id = "empty-rule"
regex = ""
`)
	}))
	t.Cleanup(srv.Close)

	origURL := gitleaksConfigURL
	gitleaksConfigURL = srv.URL
	t.Cleanup(func() { gitleaksConfigURL = origURL })

	patterns := fetchGitleaksPatterns()
	require.Len(t, patterns, 2, "valid and fixed incompatible rules should compile")

	matched := patterns[0].FindString("leaked unique-gitleaks-test-token-123456")
	assert.Equal(t, "unique-gitleaks-test-token-123456", matched)

	matched = patterns[1].FindString("password=supersecret")
	assert.Equal(t, "password=supersecret", matched)
}

func TestFetchGitleaksPatterns_HTTPFailures(t *testing.T) {
	t.Run("non-200 response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		origURL := gitleaksConfigURL
		gitleaksConfigURL = srv.URL
		t.Cleanup(func() { gitleaksConfigURL = origURL })

		assert.Nil(t, fetchGitleaksPatterns())
	})

	t.Run("invalid TOML", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `not valid toml [[[`)
		}))
		t.Cleanup(srv.Close)

		origURL := gitleaksConfigURL
		gitleaksConfigURL = srv.URL
		t.Cleanup(func() { gitleaksConfigURL = origURL })

		assert.Nil(t, fetchGitleaksPatterns())
	})

	t.Run("connection refused", func(t *testing.T) {
		origURL := gitleaksConfigURL
		gitleaksConfigURL = "http://127.0.0.1:1"
		t.Cleanup(func() { gitleaksConfigURL = origURL })

		assert.Nil(t, fetchGitleaksPatterns())
	})
}

func TestLiveRedactionPatterns_FallbackOnFetchFailure(t *testing.T) {
	resetGitleaksState(t)

	origURL := gitleaksConfigURL
	gitleaksConfigURL = "http://127.0.0.1:1"
	t.Cleanup(func() { gitleaksConfigURL = origURL })

	patterns := LiveRedactionPatterns()
	assert.Equal(t, redactionPatterns(), patterns)
}

func TestLiveRedactionPatterns_GitleaksDisabled(t *testing.T) {
	resetGitleaksState(t)

	// gitleaks fetch is disabled — should only return hardcoded patterns
	patterns := LiveRedactionPatterns()
	require.Equal(t, len(patterns), len(redactionPatterns()))
}

func TestReloadGitleaksPatterns(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `[[rules]]
id = "refresh-rule"
regex = '''refresh-gitleaks-token-[0-9]{4}'''
`)
		}))
		t.Cleanup(srv.Close)

		origURL := gitleaksConfigURL
		gitleaksConfigURL = srv.URL
		t.Cleanup(func() { gitleaksConfigURL = origURL })

		count, err := ReloadGitleaksPatterns()
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		content := "leak refresh-gitleaks-token-9876 end"
		assert.Equal(t, "leak [REDACTED] end", Redact(content))
	})

	t.Run("fetch failure", func(t *testing.T) {
		origURL := gitleaksConfigURL
		gitleaksConfigURL = "http://127.0.0.1:1"
		t.Cleanup(func() { gitleaksConfigURL = origURL })

		count, err := ReloadGitleaksPatterns()
		assert.Error(t, err)
		assert.Equal(t, 0, count)
		assert.Contains(t, err.Error(), "failed to fetch gitleaks patterns")
	})
}
