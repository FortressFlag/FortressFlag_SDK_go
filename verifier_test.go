package fortressflag

import "testing"

func expectDev(enforceExpiry bool) expectations {
	return expectations{environment: "dev", now: fixtureNow, enforceExpiry: enforceExpiry}
}

func TestVerifyAcceptsAGoodEnvelopeAndRetainsTheRawBytes(t *testing.T) {
	raw := fixtureEnvelope(fixturePayloadJSON(nil), "")
	envelope, code, ok := verifyEnvelope(raw, SignatureDisabled, expectDev(true))
	if !ok {
		t.Fatalf("rejected: %s", code)
	}
	if string(envelope.raw) != string(raw) {
		t.Fatal("the verified envelope does not retain the exact bytes it arrived as")
	}
	if len(envelope.payload.Flags) != 2 {
		t.Fatalf("flags = %d, want 2", len(envelope.payload.Flags))
	}
}

func TestVerifyRejectsMalformedEnvelopes(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":                 {},
		"not json":              []byte("<html>captive portal</html>"),
		"truncated":             fixtureEnvelope(fixturePayloadJSON(nil), "")[:20],
		"no payload field":      []byte(`{"sig":"x"}`),
		"payload not base64url": []byte(`{"payload":"!!!"}`),
		"json null":             []byte("null"),
	} {
		if _, code, ok := verifyEnvelope(raw, SignatureDisabled, expectDev(true)); ok || code != rejectMalformedEnvelope {
			t.Errorf("%s: (%s, %v), want malformedEnvelope", name, code, ok)
		}
	}
}

func TestVerifyRejectsMalformedPayloads(t *testing.T) {
	for name, payload := range map[string][]byte{
		"not json":            []byte("{"),
		"missing environment": fixturePayloadJSON(map[string]any{"environment": nil}),
		"missing issuedAt":    fixturePayloadJSON(map[string]any{"issuedAt": nil}),
		"garbage issuedAt":    fixturePayloadJSON(map[string]any{"issuedAt": "yesterday"}),
	} {
		raw := fixtureEnvelope(payload, "")
		if _, code, ok := verifyEnvelope(raw, SignatureDisabled, expectDev(true)); ok || code != rejectMalformedPayload {
			t.Errorf("%s: (%s, %v), want malformedPayload", name, code, ok)
		}
	}
}

func TestVerifyRejectsTheWrongScopeOrVersion(t *testing.T) {
	wrongEnv := fixtureEnvelope(fixturePayloadJSON(map[string]any{"environment": "prod"}), "")
	if _, code, ok := verifyEnvelope(wrongEnv, SignatureDisabled, expectDev(true)); ok || code != rejectEnvironmentMismatch {
		t.Errorf("wrong environment: (%s, %v)", code, ok)
	}
	wrongSV := fixtureEnvelope(fixturePayloadJSON(map[string]any{"sv": 99}), "")
	if _, code, ok := verifyEnvelope(wrongSV, SignatureDisabled, expectDev(true)); ok || code != rejectUnsupportedSV {
		t.Errorf("sv 99: (%s, %v)", code, ok)
	}
}

func TestVerifyExpiryAsymmetry(t *testing.T) {
	// fixtureNow is 10:15; this payload expired at 09:30, 45 minutes ago — beyond skew.
	expired := fixtureEnvelope(fixturePayloadJSON(map[string]any{
		"issuedAt": "2026-08-21T09:00:00Z", "expiresAt": "2026-08-21T09:30:00Z",
	}), "")

	// Live response: refused. Staleness where fresh data was expected is the replay window.
	if _, code, ok := verifyEnvelope(expired, SignatureDisabled, expectDev(true)); ok || code != rejectExpired {
		t.Fatalf("live expired payload: (%s, %v), want expired", code, ok)
	}

	// Cache load: accepted. A service that restarts after a long outage keeps evaluating
	// with what it last saw — expiring the cache would turn the outage into a feature
	// regression (Founding §8.4; the contract's expiry asymmetry).
	if _, code, ok := verifyEnvelope(expired, SignatureDisabled, expectDev(false)); !ok {
		t.Fatalf("cache-load expired payload rejected: %s", code)
	}
}

func TestVerifyExpiryToleratesClockSkew(t *testing.T) {
	// Expired 2 minutes ago — inside the 300 s tolerance; a slightly-slow producer clock
	// must not cost a fleet its updates.
	barelyExpired := fixtureEnvelope(fixturePayloadJSON(map[string]any{"expiresAt": "2026-08-21T10:13:00Z"}), "")
	if _, code, ok := verifyEnvelope(barelyExpired, SignatureDisabled, expectDev(true)); !ok {
		t.Fatalf("payload expired within skew tolerance rejected: %s", code)
	}
}

func TestVerifyRejectsTheFuture(t *testing.T) {
	future := fixtureEnvelope(fixturePayloadJSON(map[string]any{"issuedAt": "2026-08-21T11:00:00Z"}), "")
	if _, code, ok := verifyEnvelope(future, SignatureDisabled, expectDev(true)); ok || code != rejectIssuedInTheFuture {
		t.Fatalf("future issuedAt: (%s, %v)", code, ok)
	}
	// 4 minutes ahead is inside the skew tolerance.
	slightlyAhead := fixtureEnvelope(fixturePayloadJSON(map[string]any{"issuedAt": "2026-08-21T10:19:00Z"}), "")
	if _, _, ok := verifyEnvelope(slightlyAhead, SignatureDisabled, expectDev(true)); !ok {
		t.Fatal("issuedAt within skew tolerance rejected")
	}
}

// The fail-closed signature matrix: under a required policy with a trust store, every
// signature shape rejects — absent, malformed, wrong algorithm, unknown key, and (until M4
// supplies the primitive) even a plausible one. The stub can never accept a forgery.
func TestVerifySignatureRequiredFailsClosed(t *testing.T) {
	policy := SignatureRequired(map[string][]byte{"k1": make([]byte, 32)})
	payload := fixturePayloadJSON(nil)

	for _, tc := range []struct {
		name string
		sig  string
		want rejectionCode
	}{
		{"unsigned", "", rejectMissingSignature},
		{"garbage", "garbage", rejectMalformedSignature},
		{"two-part", "ed25519:AAAA", rejectMalformedSignature},
		{"empty signature part", "ed25519:k1:", rejectMalformedSignature},
		{"not base64url", "ed25519:k1:!!!", rejectMalformedSignature},
		{"wrong algorithm", "p256:k1:AAAA", rejectUnsupportedAlgorithm},
		{"unknown key", "ed25519:unknown:AAAA", rejectUnknownKeyID},
		{"plausible but unverifiable", "ed25519:k1:AAAA", rejectBadSignature},
	} {
		raw := fixtureEnvelope(payload, tc.sig)
		if _, code, ok := verifyEnvelope(raw, policy, expectDev(true)); ok || code != tc.want {
			t.Errorf("%s: (%s, %v), want %s", tc.name, code, ok, tc.want)
		}
	}

	// And under the disabled policy the same signed shapes are all accepted — the sig field
	// is simply not consulted.
	for _, sig := range []string{"", "garbage", "ed25519:k1:AAAA"} {
		raw := fixtureEnvelope(payload, sig)
		if _, code, ok := verifyEnvelope(raw, SignatureDisabled, expectDev(true)); !ok {
			t.Errorf("disabled policy rejected sig %q: %s", sig, code)
		}
	}
}

func TestVerifyRejectsUnknownFlagKindsWhole(t *testing.T) {
	// An unknown kind on sv=1 is corruption or hostility (a real new kind is an sv bump).
	// The payload is rejected WHOLE: under wholesale snapshot overwrite, accepting it would
	// dislodge held values into fallbacks — the client SDKs' union-violation posture.
	raw := fixtureEnvelope(fixturePayloadJSON(map[string]any{"flags": map[string]any{
		"dark-mode": map[string]any{"kind": "datetime", "default": true, "rules": []any{}},
	}}), "")
	if _, code, ok := verifyEnvelope(raw, SignatureDisabled, expectDev(true)); ok || code != rejectMalformedPayload {
		t.Fatalf("unknown kind: (%s, %v), want malformedPayload", code, ok)
	}
}
