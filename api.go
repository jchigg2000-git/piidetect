package piidetect

import (
	"context"
	"time"
)

// DefaultTimeout bounds each detector on a Run. The regex floor never needs
// it; a Presidio sidecar can.
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
// placeholder. Detector errors are returned but the redacted text is always
// usable — spans found before an error are still masked.
func (c *Chain) Redact(ctx context.Context, text string) (string, []error) {
	spans, errs := c.Run(ctx, text)
	return Mask(text, spans), errs
}
