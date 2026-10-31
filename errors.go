package piidetect

import "errors"

// ErrNoDetectors is reported by a Chain with no Detectors. Such a Chain runs
// the built-in regex floor in their place rather than return text unredacted.
var ErrNoDetectors = errors.New("piidetect: chain has no detectors; ran the built-in regex floor")

// ErrSpanOutOfRange is reported, inside the detector's DetectorError, when a
// detector returns spans with offsets outside the text. Run drops those spans:
// kept, they would panic a type guard or merge with valid neighbours into a
// union Mask cannot apply. Match it with errors.Is.
var ErrSpanOutOfRange = errors.New("piidetect: span offsets outside the text")

// DetectorError is one detector's failure on a Run: its Detect failed, it
// returned spans outside the text, or it rejected the chain's pattern pack.
// Run joins one per failure; find them with errors.As. Detector is the
// failing detector's Name.
type DetectorError struct {
	Detector string
	Err      error
}

func (e *DetectorError) Error() string { return e.Detector + ": " + e.Err.Error() }

func (e *DetectorError) Unwrap() error { return e.Err }
