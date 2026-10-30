package piidetect_test

import (
	"context"
	"fmt"

	"github.com/jchigg2000-git/piidetect"
)

// The README quickstart: the regex floor alone, no network, no configuration.
func ExampleChain_Redact() {
	clean, errs := piidetect.New().Redact(context.Background(),
		"Member 078-05-1120 paid with 4111 1111 1111 1111; reach her at jane.doe@example.org.")
	if len(errs) > 0 {
		// Fail closed: a value may have been missed.
		fmt.Println("dropped")
		return
	}
	fmt.Println(clean)
	// Output: Member [SSN] paid with [CREDIT_CARD]; reach her at [EMAIL].
}

// Mask applies spans from any source, merging overlaps first so no fragment of
// either claim survives.
func ExampleMask() {
	text := "call 415-555-0173 now"
	spans := []piidetect.Span{
		{Start: 5, End: 12, Type: "PHONE"},
		{Start: 9, End: 17, Type: "PHONE"},
	}
	fmt.Println(piidetect.Mask(text, spans))
	// Output: call [PHONE] now
}

// A pattern pack adds recognizers to the floor at runtime, swapped in
// atomically with no restart.
func ExampleRegex_SetPatternPack() {
	regex := piidetect.NewRegex()
	err := regex.SetPatternPack([]piidetect.PatternRule{
		{ID: "emp-id", Type: "EMPLOYEE_ID", Regex: `\bEMP\d{6}\b`, Confidence: 0.9},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	text := "badge EMP123456 issued"
	spans, _ := regex.Detect(context.Background(), text)
	fmt.Println(piidetect.Mask(text, spans))
	// Output: badge [EMPLOYEE_ID] issued
}

// An allow list rules a term a false positive for one type, whichever
// detector claimed it. It suppresses that term only: the address beside it is
// still masked.
func ExampleChain_SetPatternPack() {
	chain := piidetect.New()
	chain.SetPatternPack([]piidetect.PatternRule{
		{ID: "not-ours", Type: "EMAIL", Kind: "allow_list", AllowList: []string{"support@example.com"}},
	})
	clean, _ := chain.Redact(context.Background(),
		"Write to support@example.com, not jane.doe@example.org.")
	fmt.Println(clean)
	// Output: Write to support@example.com, not [EMAIL].
}
