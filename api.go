package piidetect

import (
	"context"
	"time"
)

// DefaultTimeout bounds each detector on a Run. A Presidio sidecar can need
// it; the regex floor only on text of several megabytes, where it stops and
// reports the deadline — set Chain.Timeout higher for input that large.
const DefaultTimeout = 2 * time.Second

// New returns a Chain carrying just the built-in regex floor — no sidecar, no
// network, no configuration. This is the entry point for most callers.
func New() *Chain {
	return &Chain{Detectors: []Detector{NewRegex()}, Timeout: DefaultTimeout}
}

// WithPresidio returns a Chain that runs the regex floor first and then a
// presidio-analyzer sidecar at url (e.g. "http://localhost:5002"). The floor
// runs regardless, so a sidecar that is down degrades to regex-only rather
// than failing open: Run reports the sidecar error alongside the spans the
// floor still found.
func WithPresidio(url string) *Chain {
	return &Chain{
		Detectors: []Detector{NewRegex(), NewPresidio(url)},
		Timeout:   DefaultTimeout,
	}
}

// Redact is the one-call path: detect, then replace every span with its typed
// placeholder. Detector errors are returned and every span found, before an
// error too, is still masked — but an error means a value may have been
// missed, so fail closed on one (drop the text or mask all of it) wherever a
// leak matters. A Chain with no Detectors redacts with the built-in regex
// floor and reports ErrNoDetectors.
func (c *Chain) Redact(ctx context.Context, text string) (string, []error) {
	spans, errs := c.Run(ctx, text)
	return Mask(text, spans), errs
}

// RedactWith is Redact with each merged span replaced by f(span, value)
// instead of [TYPE]; see MaskFunc. Errors mean what they mean for Redact. A
// nil f is Redact.
func (c *Chain) RedactWith(ctx context.Context, text string, f MaskFunc) (string, []error) {
	spans, errs := c.Run(ctx, text)
	return MaskWith(text, spans, f), errs
}
