package fortressflag

import (
	"crypto/sha256"
	"encoding/binary"
)

// bucket places one context in [0, 100) for one flag's percentage rollout (ADR-0008,
// published in contract-v2.md and pinned by vectors/buckets.json):
//
//	uint64_be(SHA-256(contextKey + ":" + flagKey)[0..8]) mod 100
//
// The contextKey is EXACTLY the opaque identifier string the caller gave this SDK — a user
// id, a session id, the customer's choice — never validated, trimmed or normalised: the
// backend hashes a device ID the same way, and any deviation from "hash exactly the bytes
// given" flips cohorts between components evaluating for the same person. Nothing is stored:
// a context's bucket is recomputed per evaluation and exists nowhere else. The ":" + flagKey
// suffix makes buckets per-flag (a 10% rollout is not always the same unlucky 10%) and
// sticky (the same pair answers the same bucket on every call).
func bucket(contextKey, flagKey string) int {
	sum := sha256.Sum256([]byte(contextKey + ":" + flagKey))
	return int(binary.BigEndian.Uint64(sum[:8]) % 100)
}
