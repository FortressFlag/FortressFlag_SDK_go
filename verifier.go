package fortressflag

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"time"
)

// Envelope verification: is this payload from FortressFlag (signature policy), about us
// (environment), and now (issuedAt/expiresAt)? A rejection is never fatal: it means "keep
// serving the last verified snapshot" (Founding §8.4). Rejections are enumerated in this
// much detail because "flags stopped updating" is otherwise one of the hardest things to
// debug in a customer's service, and the answer should be one Diagnostics() read.

// rejectionCode says why an envelope was not accepted.
type rejectionCode string

const (
	rejectMalformedEnvelope    rejectionCode = "malformedEnvelope"
	rejectMissingSignature     rejectionCode = "missingSignature"
	rejectMalformedSignature   rejectionCode = "malformedSignature"
	rejectUnsupportedAlgorithm rejectionCode = "unsupportedSignatureAlgorithm"
	rejectUnknownKeyID         rejectionCode = "unknownKeyId"
	rejectBadSignature         rejectionCode = "badSignature"
	rejectMalformedPayload     rejectionCode = "malformedPayload"
	rejectUnsupportedSV        rejectionCode = "unsupportedContractVersion"
	rejectEnvironmentMismatch  rejectionCode = "environmentMismatch"
	rejectExpired              rejectionCode = "expired"
	rejectIssuedInTheFuture    rejectionCode = "issuedInTheFuture"
)

// verifiedEnvelope is an envelope that passed every check, kept alongside the exact bytes it
// arrived as. raw is retained so the cache stores what was (or will one day be) signed
// rather than a re-serialisation of what we parsed — re-serialising would silently strip any
// field a future server adds and break the signature on reload (the web verifier's rule,
// ported).
type verifiedEnvelope struct {
	raw     []byte
	payload rulesetPayload
}

// expectations is what the payload must claim to be, for it to be about us.
type expectations struct {
	environment string
	now         time.Time
	// enforceExpiry: TRUE for a live response, FALSE when loading the CachePath file — and
	// that asymmetry is the single most load-bearing rule in this SDK. On a live response,
	// expiry is the replay window: without it, anyone who captured a valid response could
	// serve it back forever, pinning a fleet to old flag values. On a cache load it must NOT
	// apply: the last verified snapshot is the primary fallback, and a service that restarts
	// after a long outage keeps evaluating with what it last saw. Enforcing expiry there
	// would silently revert every flag to caller defaults after any 30-minute outage plus
	// one restart — turning an outage into a feature regression, which is precisely the
	// failure the cascade exists to prevent. Expiry governs freshness, not validity.
	enforceExpiry bool
}

// clockSkewTolerance forgives a wrong server-or-host clock. Machines drift; a host an hour
// fast should not lose flag updates — but 300 s is the ceiling on how far issuedAt may sit
// in the future before the payload is refused.
const clockSkewTolerance = 300 * time.Second

// verifyEnvelope runs every check in the contract's order and reports the outcome.
func verifyEnvelope(raw []byte, policy SignaturePolicy, expect expectations) (verifiedEnvelope, rejectionCode, bool) {
	envelope, payloadBytes, ok := parseEnvelope(raw)
	if !ok {
		return verifiedEnvelope{}, rejectMalformedEnvelope, false
	}

	if policy.required {
		if code, accepted := checkSignature(envelope.Sig, payloadBytes, policy); !accepted {
			return verifiedEnvelope{}, code, false
		}
	}

	payload, ok := parsePayload(payloadBytes)
	if !ok {
		return verifiedEnvelope{}, rejectMalformedPayload, false
	}

	if payload.SV != supportedServerContractVersion {
		// A version this binary does not speak might mean anything; refusing to guess is
		// the contract's own instruction ("never guesses at a payload whose meaning may
		// have changed").
		return verifiedEnvelope{}, rejectUnsupportedSV, false
	}
	if payload.Environment != expect.environment {
		// A production payload replayed at a dev process (or vice versa) is refused even
		// though the key, not the payload, chose the scope: the key's claim and the
		// payload's claim must agree.
		return verifiedEnvelope{}, rejectEnvironmentMismatch, false
	}

	issuedAt, ok := parseWireTime(payload.IssuedAt)
	if !ok {
		return verifiedEnvelope{}, rejectMalformedPayload, false
	}
	expiresAt, ok := parseWireTime(payload.ExpiresAt)
	if !ok {
		return verifiedEnvelope{}, rejectMalformedPayload, false
	}
	if issuedAt.Sub(expect.now) > clockSkewTolerance {
		return verifiedEnvelope{}, rejectIssuedInTheFuture, false
	}
	if expect.enforceExpiry && expect.now.Sub(expiresAt) > clockSkewTolerance {
		return verifiedEnvelope{}, rejectExpired, false
	}

	return verifiedEnvelope{raw: raw, payload: payload}, "", true
}

// checkSignature verifies `algorithm:keyID:signature` with pure Ed25519 over payloadBytes —
// the payload exactly as transmitted, never a re-serialisation (backend ADR-0025,
// contract-v1 §Signing keys). A missing signature under a required policy is rejected: fail
// closed, the client-SDK posture byte for byte.
func checkSignature(sig *string, payloadBytes []byte, policy SignaturePolicy) (rejectionCode, bool) {
	if sig == nil || *sig == "" {
		return rejectMissingSignature, false
	}

	// Split at the first two colons: the SIGNATURE part may carry extra colons, the key ID
	// never can (the backend refuses to mint one; contract-v1 §Signing keys).
	first := strings.Index(*sig, ":")
	second := -1
	if first >= 0 {
		offset := strings.Index((*sig)[first+1:], ":")
		if offset >= 0 {
			second = first + 1 + offset
		}
	}
	if first < 0 || second < 0 {
		return rejectMalformedSignature, false
	}

	algorithm := (*sig)[:first]
	keyID := (*sig)[first+1 : second]
	signature := (*sig)[second+1:]
	if algorithm != "ed25519" {
		return rejectUnsupportedAlgorithm, false
	}
	if signature == "" {
		return rejectMalformedSignature, false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return rejectMalformedSignature, false
	}
	key, known := policy.trustedKeys[keyID]
	if !known || len(key) != ed25519.PublicKeySize {
		// A malformed key in our own trust store reads as "cannot verify with this key" so
		// one bad entry does not disable a rotation set (the iOS rule).
		return rejectUnknownKeyID, false
	}
	if !ed25519.Verify(ed25519.PublicKey(key), payloadBytes, sigBytes) {
		return rejectBadSignature, false
	}
	return "", true
}
