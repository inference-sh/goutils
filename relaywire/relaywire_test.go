package relaywire

import "testing"

// The codes are on the wire between belt and the relay: a change is a
// protocol change, so they are pinned here.
func TestCloseCodes(t *testing.T) {
	for _, tc := range []struct {
		code CloseCode
		want int
		name string
	}{
		{CloseStreamRevoked, 4403, "stream revoked"},
		{CloseStreamRefused, 4502, "stream refused"},
		{CloseCode(4000), 4000, "close code 4000"},
	} {
		if tc.code.Int() != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, tc.code.Int(), tc.want)
		}
		if tc.code.String() != tc.name {
			t.Errorf("%d: %q, want %q", tc.want, tc.code.String(), tc.name)
		}
		if tc.want < 4000 || tc.want > 4999 {
			t.Errorf("%d is outside the application range", tc.want)
		}
	}
}
