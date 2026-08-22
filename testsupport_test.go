package fortressflag

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Shared envelope fixtures. The fixture clock is fixed so expiry checks are deterministic.

var fixtureNow = time.Date(2026, 8, 21, 10, 15, 0, 0, time.UTC)

// fixturePayloadJSON builds a payload document, with overrides applied over sane defaults.
func fixturePayloadJSON(overrides map[string]any) []byte {
	document := map[string]any{
		"sv":          1,
		"tenant":      "00000000-0000-4000-8000-000000000001",
		"project":     "default",
		"environment": "dev",
		"issuedAt":    "2026-08-21T10:00:00Z",
		"expiresAt":   "2026-08-21T10:30:00Z",
		"flags": map[string]any{
			"dark-mode": map[string]any{
				"kind":    "boolean",
				"default": false,
				"rules": []any{map[string]any{
					"conditions": []any{map[string]any{"tagKey": "cohort", "operator": "eq", "value": "beta"}},
					"serve":      true,
				}},
			},
			"checkout-cta": map[string]any{
				"kind":    "string",
				"default": "buy-now",
				"rules":   []any{},
			},
		},
	}
	for key, value := range overrides {
		if value == nil {
			delete(document, key)
			continue
		}
		document[key] = value
	}
	raw, err := json.Marshal(document)
	if err != nil {
		panic(err) // test-only fixture builder
	}
	return raw
}

// fixtureEnvelope wraps payload bytes in the wire envelope, optionally signed.
func fixtureEnvelope(payloadBytes []byte, sig string) []byte {
	envelope := map[string]any{"payload": base64.RawURLEncoding.EncodeToString(payloadBytes)}
	if sig != "" {
		envelope["sig"] = sig
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		panic(err) // test-only fixture builder
	}
	return raw
}
