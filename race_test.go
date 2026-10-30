//go:build race

package piidetect

// The race detector slows the regex engine some twentyfold, so the tests that
// read large texts many times read fewer of them under it.
func init() { raceEnabled = true }
