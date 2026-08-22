package fortressflag

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// The wire envelope (server-contract-v1.md): the client envelope design, reused. sig is
// omitted until backend M4 ships; when present it is a detached signature over the payload's
// exact base64url bytes.

// supportedServerContractVersion is the sv this SDK requests and accepts.
const supportedServerContractVersion = 1

type wireEnvelope struct {
	Payload string  `json:"payload"`
	Sig     *string `json:"sig"`
}

// rulesetPayload is the decoded payload document.
type rulesetPayload struct {
	SV          int                   `json:"sv"`
	Tenant      string                `json:"tenant"`
	Project     string                `json:"project"`
	Environment string                `json:"environment"`
	IssuedAt    string                `json:"issuedAt"`
	ExpiresAt   string                `json:"expiresAt"`
	Flags       map[string]flagConfig `json:"flags"`
}

// parseEnvelope splits raw bytes into the envelope and its decoded payload bytes, reporting
// failure rather than erroring — a body that is not an envelope is a rejection, never a
// crash (captive portals serve HTML with a 200; the transport treats the server as hostile).
func parseEnvelope(raw []byte) (envelope wireEnvelope, payloadBytes []byte, ok bool) {
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Payload == "" {
		return wireEnvelope{}, nil, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return wireEnvelope{}, nil, false
	}
	return envelope, payloadBytes, true
}

// parsePayload decodes the payload document, requiring the fields whose absence would make
// the binding checks meaningless. Unknown fields are ignored — additive server changes ride
// sv=1 (the contract's versioning rule), and the raw bytes are what the cache retains.
//
// Flag KINDS are validated here, and a payload carrying one this binary does not know is
// rejected WHOLE — the client SDKs' union-violation posture, applied to configs: the
// contract makes a new kind an sv bump, so an unknown kind on sv=1 is corruption or
// hostility, and under wholesale snapshot overwrite an accepted half-broken payload would
// dislodge held values into fallbacks. Rejecting keeps the last verified state serving,
// which is the cascade's whole point. (Value-vs-kind mismatches inside rules stay per-flag
// fail-closed in the evaluator, the backend's own defensive posture.)
func parsePayload(payloadBytes []byte) (rulesetPayload, bool) {
	var payload rulesetPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return rulesetPayload{}, false
	}
	if payload.Environment == "" || payload.IssuedAt == "" || payload.ExpiresAt == "" {
		return rulesetPayload{}, false
	}
	for _, config := range payload.Flags {
		switch config.Kind {
		case "boolean", "string", "number":
		default:
			return rulesetPayload{}, false
		}
	}
	return payload, true
}

// parseWireTime parses the contract's RFC 3339 timestamps, fractional seconds tolerated.
func parseWireTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
