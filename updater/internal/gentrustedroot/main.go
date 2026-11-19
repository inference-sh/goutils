// Command gentrustedroot writes Sigstore's current public-good
// trusted_root.json, fetched through TUF from the root.json sigstore-go
// embeds, to the file named by its argument. It refreshes the snapshot the
// updater falls back to when TUF can't be reached.
package main

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gentrustedroot <out.json>")
		os.Exit(2)
	}
	c, err := tuf.New(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, err := c.GetTarget("trusted_root.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := root.NewTrustedRootFromJSON(b); err != nil {
		fmt.Fprintln(os.Stderr, "fetched trusted root does not parse:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
