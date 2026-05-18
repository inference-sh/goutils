package logo

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/term"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var trailingAnsi = regexp.MustCompile(`(\x1b\[[0-9;]*m)+$`)

func joinSideBySide(left, right string, gap int) string {
	lLines := strings.Split(left, "\n")
	rLines := strings.Split(right, "\n")

	// Find max visual width of left side (ignoring trailing spaces)
	maxW := 0
	for _, l := range lLines {
		w := len(strings.TrimRight(ansiRe.ReplaceAllString(l, ""), " "))
		if w > maxW {
			maxW = w
		}
	}

	// Pad to same number of lines
	for len(lLines) < len(rLines) {
		lLines = append(lLines, "")
	}
	for len(rLines) < len(lLines) {
		rLines = append(rLines, "")
	}

	target := maxW + gap
	var out []string
	for i := range lLines {
		stripped := ansiRe.ReplaceAllString(lLines[i], "")
		visible := len(strings.TrimRight(stripped, " "))
		padN := target - visible
		if padN < 0 {
			padN = 0
		}
		// Strip trailing ANSI codes, trim spaces, re-append codes
		trail := trailingAnsi.FindString(lLines[i])
		core := strings.TrimRight(trailingAnsi.ReplaceAllString(lLines[i], ""), " ")
		out = append(out, core+strings.Repeat(" ", padN)+trail+rLines[i])
	}
	return strings.Join(out, "\n")
}

func gradientLines(lines []string) string {
	n := len(lines)
	reset := "\033[0m"
	result := make([]string, n)
	for i, line := range lines {
		// Top = white (255), bottom = dark gray (80)
		gray := 80 + (255-80)*i/(n-1)
		color := fmt.Sprintf("\033[38;2;%d;%d;%dm", gray, gray, gray)
		result[i] = color + line + reset
	}
	return strings.Join(result, "\n")
}

func emblemShape() string {
	reset := "\033[0m"
	purple := "\033[38;2;255;86;157m" // #FF569D (Pink - Outline)
	green := "\033[38;2;0;208;138m"   // #00D08A (Green)
	cyan := "\033[38;2;84;21;255m"    // #5415FF (Purple)
	yellow := "\033[38;2;255;241;76m" // #FFF14C (Yellow)

	return fmt.Sprintf(strings.Join([]string{
		`      %s__%s`,
		`     %s/ %s/%s\%s`,
		`    %s/ %s/  %s\%s`,
		`   %s/ %s/ %s/\ %s\%s`,
		`  %s/ %s/ %s/%s\ %s\ %s\%s`,
		` %s/ %s/_%s/%s__%s\ %s\ %s\%s`,
		`%s/%s________\ %s\ %s\%s`,
		`%s\___________%s\%s/%s`,
	}, "\n"),
		purple, reset,
		purple, yellow, purple, reset,
		purple, yellow, purple, reset,
		purple, yellow, green, purple, reset,
		purple, yellow, green, cyan, green, purple, reset,
		purple, yellow, green, yellow, cyan, green, purple, reset,
		purple, cyan, green, purple, reset,
		purple, green, purple, reset,
	)
}

func PrintLogo() {
	// Check terminal width and use compact logo if narrow
	width, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err == nil && width < 100 {
		fmt.Fprintln(os.Stderr, GetEmblem())
		return
	}

	wordmark := gradientLines([]string{
		`                                                                          `,
		` __            ____                                                      __`,
		`/\_\    ____  /  __\ ____  _____  ____   ____    ____   ____       ____ /\ \____`,
		`\/\ \  / __ \/\  __\/ __ \/\  __\/ __ \ / __ \  / ___\ / __ \     /  __\\ \  __ \`,
		` \ \ \/\ \/\ \ \ \//\  __/\ \ \//\  __//\ \/\ \/\ \__//\  __/  __/\__   \\ \ \ \ \`,
		`  \ \_\ \_\ \_\ \_\\ \____\\ \_\\ \____\ \_\ \_\ \____\ \____\/\_\/\____/ \ \_\ \_\`,
		`   \/_/\/_/\/_/\/_/ \/____/ \/_/ \/____/\/_/\/_/\/____/\/____/\/_/\/___/   \/_/\/_/`,
		``,
	})

	fmt.Fprintln(os.Stderr, joinSideBySide(emblemShape(), wordmark, 0))
}

func PrintBeltLogo() {
	// Check terminal width and use compact logo if narrow
	width, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err == nil && width < 100 {
		fmt.Fprintln(os.Stderr, GetEmblem())
		return
	}

	wordmark := gradientLines([]string{
		`                                            `,
		`  __               __    __                __`,
		` /\ \____    ____ /\ \  /\ \__       ____ /\ \____`,
		` \ \  __ \  / __ \\ \ \ \ \  _\     /  __\\ \  __ \`,
		`  \ \ \_\ \/\  __/ \ \ \_\ \ \_  __/\__   \\ \ \ \ \`,
		`   \ \_____\ \____\ \ \__\\ \__\/\_\/\____/ \ \_\ \_\`,
		`    \/_____/\/____/  \/__/ \/__/\/_/\/___/   \/_/\/_/`,
		``,
	})

	fmt.Fprintln(os.Stderr, joinSideBySide(emblemShape(), wordmark, 0))
}

func GetEmblem() string {
	bold := "\033[1m"
	reset := "\033[0m"
	return emblemShape() + "\n\n " + bold + "inference.sh" + reset + "\n"
}

func PrintVersion(version string) {
	dim := "\033[2m"
	reset := "\033[0m"

	fmt.Fprintf(os.Stderr, "%s%s%s\n\n", dim, version, reset)
}
