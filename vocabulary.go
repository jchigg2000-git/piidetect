package piidetect

// Presidio vocabulary: the mapping between a presidio-analyzer sidecar's
// entity types and this package's own, plus the score gate applied to its
// results. Exported because extending the map is how you teach the Presidio
// tier a new type — but note that a type added here bypasses typeGuards
// unless you also add a validator there.

// PresidioDefaultScoreGate is the acceptance threshold applied to Presidio
// results unless a threshold rule lowers it for a specific type.
const PresidioDefaultScoreGate = 0.4

// PresidioEntityMap normalizes Presidio entity types onto this package's
// vocabulary. Types mapping to "" are dropped: DATE_TIME in particular is
// false-positive noise against semver strings and order numbers.
var PresidioEntityMap = map[string]string{
	"PERSON":          "PERSON_NAME",
	"LOCATION":        "ADDRESS",
	"EMAIL_ADDRESS":   "EMAIL",
	"PHONE_NUMBER":    "PHONE",
	"US_SSN":          "SSN",
	"US_ITIN":         "SSN", // SSN-shaped tax id; inherits the SSN hyphen guard
	"CREDIT_CARD":     "CREDIT_CARD",
	"IP_ADDRESS":      "IP",
	"IBAN_CODE":       "IBAN",
	"MEDICAL_LICENSE": "MRN",
	"DATE_TIME":       "",
	"URL":             "",
	"NRP":             "",
}

// RuneToByteOffsets maps each rune index (plus one past the end) to its byte
// offset. Presidio speaks unicode codepoints; Span offsets are bytes.
func RuneToByteOffsets(s string) []int {
	offs := make([]int, 0, len(s)+1)
	for i := range s {
		offs = append(offs, i)
	}
	offs = append(offs, len(s))
	return offs
}
