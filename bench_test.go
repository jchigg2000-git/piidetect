package piidetect

import (
	"context"
	"strings"
	"testing"
)

// Benchmarks of the regex floor on the three shapes it is fed: a log line, a
// JSON body and prose. Each is read clean (no value), dirty (a few values),
// and clean with one %20 or one NBSP, either of which sends the whole text
// through the normalized second pass. Run with
//
//	go test -run '^$' -bench RegexDetect -count 5
func BenchmarkRegexDetect(b *testing.B) {
	shapes := []struct {
		name  string
		clean string
		dirty []string // values spliced in at even intervals
	}{
		{"log1KB", benchFill(benchLogLine, 1<<10), []string{
			" email=jane.doe@example.org", " ssn=078-05-1120", " phone=(415) 555-0173",
		}},
		{"json100KB", benchFill(benchJSONRecord, 100<<10), []string{
			`{"email":"jane.doe@example.org"},`, `{"mrn":"4481920"},`,
			`{"dob":"1985-03-14"},`, `{"card":"4111 1111 1111 1111"},`,
		}},
		{"prose1MB", benchFill(benchProse, 1<<20), []string{
			" Write to jane.doe@example.org. ", " Her SSN is 078-05-1120. ",
			" Call 415-555-0173. ", " DOB: 03/14/1985. ", " MRN 4481920. ",
		}},
	}
	det := NewRegex()
	ctx := context.Background()
	for _, s := range shapes {
		variants := []struct{ name, text string }{
			{"clean", s.clean},
			{"dirty", benchSplice(s.clean, s.dirty...)},
			{"pct20", benchSplice(s.clean, " a%20b ")},
			{"nbsp", benchSplice(s.clean, " a b ")},
		}
		for _, v := range variants {
			b.Run(s.name+"/"+v.name, func(b *testing.B) {
				b.SetBytes(int64(len(v.text)))
				b.ReportAllocs()
				for range b.N {
					if _, err := det.Detect(ctx, v.text); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

const benchLogLine = `2026-10-30T14:30:17.123Z INFO http request_id=9f1c2d7e-41b0-4c55-a1f2-3be0d4c7a911 ` +
	`method=GET path=/api/v2/orders/item/latest status=200 bytes=5120 latency_ms=12.48 ` +
	`ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15" ` +
	`region=us-west-2 cache=hit retries=0 trace=00f067aa0ba902b7 build=v4.18.2-rc.1` + "\n"

const benchJSONRecord = `{"id":"ord_7Hq2LmX9","status":"shipped","items":3,"total":"148.20","currency":"USD",` +
	`"carrier":"ground","created_at":"2026-10-30T14:30:17Z","tags":["gift","priority"],"notes":"leave at the side door"},`

const benchProse = `The committee met on a grey morning to review the quarterly plans for the river ` +
	`project. Several members argued that the budget should favour the northern bank, where the ` +
	`old mill still stands and the footpath floods each spring. Others preferred to wait for the ` +
	`survey, which the engineers expect to finish before the winter. After a long discussion the ` +
	`chair asked for a short summary of every option, with costs, risks and a timeline, to be ` +
	`circulated well ahead of the next meeting. `

// benchFill repeats unit until the text is n bytes long, cutting the last copy.
func benchFill(unit string, n int) string {
	return strings.Repeat(unit, n/len(unit)+1)[:n]
}

// benchSplice inserts each value into text at even intervals, each at a space
// so no word is cut, and keeps the text's length.
func benchSplice(text string, values ...string) string {
	out := text
	for i, v := range values {
		at := len(text) * (i + 1) / (len(values) + 1)
		if sp := strings.IndexByte(out[at:], ' '); sp >= 0 {
			at += sp
		}
		out = out[:at] + v + out[at+len(v):]
	}
	return out
}
