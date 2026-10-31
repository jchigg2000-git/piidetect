package piidetect

// The built-in type names: the Span.Type the regex floor and the mapped
// Presidio entities claim, and so the placeholder Mask writes ("[SSN]"). Use
// them for Chain.Disable, pattern rules and switches on Span.Type; a pattern
// pack may add types of its own beside them.
const (
	TypeSSN        = "SSN"
	TypeCreditCard = "CREDIT_CARD"
	TypeIBAN       = "IBAN"
	TypeIP         = "IP"
	TypeEmail      = "EMAIL"
	TypePhone      = "PHONE"
	TypeMRN        = "MRN"
	TypeDOB        = "DOB"
	// The Presidio tier's alone: the regex floor claims neither.
	TypePersonName = "PERSON_NAME"
	TypeAddress    = "ADDRESS"
)

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
//
// NewPresidio (and so NewWithPresidio) copies this map, so edits must come before
// construction: a running Presidio never reads the global, and a later edit
// reaches only the instances built after it.
var PresidioEntityMap = map[string]string{
	"PERSON":          TypePersonName,
	"LOCATION":        TypeAddress,
	"EMAIL_ADDRESS":   TypeEmail,
	"PHONE_NUMBER":    TypePhone,
	"US_SSN":          TypeSSN,
	"US_ITIN":         TypeSSN, // SSN-shaped tax id; inherits the SSN hyphen guard
	"CREDIT_CARD":     TypeCreditCard,
	"IP_ADDRESS":      TypeIP,
	"IBAN_CODE":       TypeIBAN,
	"MEDICAL_LICENSE": TypeMRN,
	"DATE_TIME":       "",
	"URL":             "",
	"NRP":             "",
}

// runeToByteOffsets maps each rune index (plus one past the end) to its byte
// offset. Presidio speaks unicode codepoints; Span offsets are bytes.
func runeToByteOffsets(s string) []int {
	offs := make([]int, 0, len(s)+1)
	for i := range s {
		offs = append(offs, i)
	}
	offs = append(offs, len(s))
	return offs
}
