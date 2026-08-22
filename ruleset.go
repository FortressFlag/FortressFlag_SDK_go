package fortressflag

import (
	"bytes"
	"encoding/json"
)

// The ruleset payload types, in the server export's wire shape (server-contract-v1.md).
//
// These are this package's own types, decoded from the wire — a PORT of the backend's
// clientapi rule types, never a share (the port-don't-share doctrine: the two components must
// be free to diverge, and nothing management-side can silently ride into this decoder).
// Unexported: the wire shape is not public API; the public surface is fortressflag.go.

// flagCondition is one ANDed test inside a rule. Position is implicit in slice order.
type flagCondition struct {
	TagKey   string `json:"tagKey"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// flagRule is one targeting rule: the ordered ANDed conditions, the value a match serves, and
// the optional rollout gate. Serve stays raw until evaluation decodes it by the flag's kind.
type flagRule struct {
	Conditions        []flagCondition `json:"conditions"`
	Serve             json.RawMessage `json:"serve"`
	RolloutPercentage *int            `json:"rolloutPercentage"`
}

// flagConfig is everything the export says about one flag: the kind, the default served when
// no rule matches, and the ordered rule list. Default stays json.RawMessage because ABSENT
// and false must not be confused (a boolean flag's false default is a value; a multivariate
// flag with no default variant has the field omitted) — a plain `any` field cannot tell
// "absent" from "null", and a naive decode would turn false into a nil-looking value.
type flagConfig struct {
	Kind    string          `json:"kind"`
	Default json.RawMessage `json:"default"`
	Rules   []flagRule      `json:"rules"`
}

var jsonNull = []byte("null")

// decodeValue decodes a raw wire value by the flag's kind, reporting whether a usable value
// was present. An absent field (len 0) and an explicit null are treated identically as
// no-value: the contract omits the field for a multivariate flag with no default variant, and
// a decoder that crashed on a null would violate fail-safe — tolerating it costs nothing.
// A value that does not follow the kind, or a kind this binary does not know, is no-value
// too: fail closed into the caller's fallback rather than serve a guess (Founding §8.3).
func decodeValue(raw json.RawMessage, kind string) (any, bool) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), jsonNull) {
		return nil, false
	}
	switch kind {
	case "boolean":
		var v bool
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, false
		}
		return v, true
	case "string":
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, false
		}
		return v, true
	case "number":
		var v float64
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, false
		}
		return v, true
	default:
		return nil, false
	}
}
