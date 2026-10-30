package piidetect_test

import (
	"context"
	"fmt"

	"github.com/jchigg2000-git/piidetect"
)

// A reporting tool that wants its own dates left alone drops DOB: an
// unlabelled MM/DD/YYYY is no longer claimed, and every other type still is.
func ExampleChain_disable() {
	chain := piidetect.New()
	chain.Disable = []string{piidetect.TypeDOB}
	clean, _ := chain.Redact(context.Background(), "Run 03/14/2026 flagged member 078-05-1120.")
	fmt.Println(clean)
	// Output: Run 03/14/2026 flagged member [SSN].
}
