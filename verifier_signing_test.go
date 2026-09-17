package fortressflag

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// The published signature vectors (FortressFlag_Standards/vectors/signing.json, backend
// ADR-0025): each `envelope` is the exact wire bytes, fed to the verifier unchanged — never
// re-serialised. The key pair is RFC 8032 §7.1 TEST 1; only the public key is in the file.

type signingVectorFile struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Accept    []struct {
		Name     string `json:"name"`
		Envelope string `json:"envelope"`
	} `json:"accept"`
	Reject []struct {
		Name     string `json:"name"`
		Envelope string `json:"envelope"`
		Code     string `json:"code"`
	} `json:"reject"`
}

func loadSigningVectors(t *testing.T) (signingVectorFile, SignaturePolicy) {
	t.Helper()
	raw, err := os.ReadFile("internal/vectors/signing.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file signingVectorFile
	if parseErr := json.Unmarshal(raw, &file); parseErr != nil {
		t.Fatalf("parse vectors: %v", parseErr)
	}
	key, err := base64.RawURLEncoding.DecodeString(file.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatalf("vector public key is not 32 raw bytes: %v", err)
	}
	return file, SignatureRequired(map[string][]byte{file.KeyID: key})
}

// The vector's expectations: environment prod, expiry in 2099, issued 2026-09-16.
func expectVector() expectations {
	return expectations{environment: "prod", now: time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC), enforceExpiry: true}
}

func TestSigningVectorsAccept(t *testing.T) {
	file, policy := loadSigningVectors(t)
	if len(file.Accept) != 2 {
		t.Fatalf("accept entries = %d, want 2", len(file.Accept))
	}
	for _, entry := range file.Accept {
		raw, err := base64.RawURLEncoding.DecodeString(entry.Envelope)
		if err != nil {
			t.Fatalf("%s: envelope is not base64url: %v", entry.Name, err)
		}
		envelope, payloadBytes, ok := parseEnvelope(raw)
		if !ok {
			t.Fatalf("%s: not an envelope", entry.Name)
		}
		// The signature stage alone: the client-v2 entry is a client-plane payload this SDK
		// does not speak (no sv), so only its signature can be checked here — the same bytes
		// and the same primitive.
		if code, accepted := checkSignature(envelope.Sig, payloadBytes, policy); !accepted {
			t.Errorf("%s: signature rejected as %s", entry.Name, code)
		}
		if entry.Name == "server-sv1" {
			verified, code, accepted := verifyEnvelope(raw, policy, expectVector())
			if !accepted {
				t.Fatalf("%s: full verification rejected as %s", entry.Name, code)
			}
			if string(verified.raw) != string(raw) || len(verified.payload.Flags) != 3 {
				t.Errorf("%s: verified envelope does not carry the vector's bytes and flags", entry.Name)
			}
		}
	}
}

func TestSigningVectorsReject(t *testing.T) {
	file, policy := loadSigningVectors(t)
	if len(file.Reject) != 4 {
		t.Fatalf("reject entries = %d, want 4", len(file.Reject))
	}
	for _, entry := range file.Reject {
		raw, err := base64.RawURLEncoding.DecodeString(entry.Envelope)
		if err != nil {
			t.Fatalf("%s: envelope is not base64url: %v", entry.Name, err)
		}
		_, code, accepted := verifyEnvelope(raw, policy, expectVector())
		if accepted || string(code) != entry.Code {
			t.Errorf("%s: (%s, %v), want %s", entry.Name, code, accepted, entry.Code)
		}
	}
}

// signedFixture signs the fixture payload with a fresh key, as the backend would.
func signedFixture(t *testing.T, payload []byte, keyID string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := "ed25519:" + keyID + ":" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return fixtureEnvelope(payload, sig), pub
}

func TestVerifyAcceptsAFreshlySignedPayloadAndRejectsEveryVariation(t *testing.T) {
	payload := fixturePayloadJSON(nil)
	raw, pub := signedFixture(t, payload, "k1")
	policy := SignatureRequired(map[string][]byte{"k1": pub})

	if _, code, ok := verifyEnvelope(raw, policy, expectDev(true)); !ok {
		t.Fatalf("freshly signed payload rejected: %s", code)
	}

	// One flag flipped after signing — the man-in-the-middle / poisoned-cache shape.
	var envelope wireEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(payload), `"default":false`, `"default":true`, 1))
	if string(tampered) == string(payload) {
		t.Fatal("fixture has no flag to flip")
	}
	forged := fixtureEnvelope(tampered, *envelope.Sig)
	if _, code, ok := verifyEnvelope(forged, policy, expectDev(true)); ok || code != rejectBadSignature {
		t.Errorf("tampered payload: (%s, %v), want badSignature", code, ok)
	}

	// The key id is absent from the trust store.
	if _, code, ok := verifyEnvelope(raw, SignatureRequired(map[string][]byte{"k2": pub}), expectDev(true)); ok || code != rejectUnknownKeyID {
		t.Errorf("unknown key id: (%s, %v), want unknownKeyId", code, ok)
	}

	// The right key id but a different key: wrong key for a known key ID.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, code, ok := verifyEnvelope(raw, SignatureRequired(map[string][]byte{"k1": otherPub}), expectDev(true)); ok || code != rejectBadSignature {
		t.Errorf("wrong key for a known id: (%s, %v), want badSignature", code, ok)
	}

	// A malformed key in our own trust store is unknownKeyId, not a crash and not
	// badSignature.
	if _, code, ok := verifyEnvelope(raw, SignatureRequired(map[string][]byte{"k1": pub[:31]}), expectDev(true)); ok || code != rejectUnknownKeyID {
		t.Errorf("31-byte trusted key: (%s, %v), want unknownKeyId", code, ok)
	}

	// Disabled accepts the unsigned form.
	if _, code, ok := verifyEnvelope(fixtureEnvelope(payload, ""), SignatureDisabled, expectDev(true)); !ok {
		t.Errorf("disabled policy rejected an unsigned envelope: %s", code)
	}
}

func TestDefaultPolicyRejectsAnUnsignedEnvelopeAndAcceptsOnlyTheProductionKey(t *testing.T) {
	resolved, err := resolveConfiguration(Configuration{Key: "ffs_prod_k"})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := fixtureEnvelope(fixturePayloadJSON(map[string]any{"environment": "prod"}), "")
	if _, code, ok := verifyEnvelope(unsigned, resolved.signature, expectations{environment: "prod", now: fixtureNow, enforceExpiry: true}); ok || code != rejectMissingSignature {
		t.Errorf("default policy on an unsigned envelope: (%s, %v), want missingSignature", code, ok)
	}
	signed, _ := signedFixture(t, fixturePayloadJSON(map[string]any{"environment": "prod"}), "prod-2026-09-k1")
	if _, code, ok := verifyEnvelope(signed, resolved.signature, expectations{environment: "prod", now: fixtureNow, enforceExpiry: true}); ok || code != rejectBadSignature {
		t.Errorf("default policy on a payload signed by a stranger's key under the production id: (%s, %v), want badSignature", code, ok)
	}
}
