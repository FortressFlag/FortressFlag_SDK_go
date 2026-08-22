package fortressflag

import "time"

// snapshot is one immutable ruleset. The client publishes whole snapshots behind an
// atomic.Pointer and NEVER mutates one after publication — evaluation reads are lock-free
// and safe from any goroutine, and the poller's swap is wholesale: a flag that leaves the
// payload leaves the snapshot on the same poll, so archiving a flag ends it fleet-wide
// within one interval (the web SDK's wholesale-overwrite rule).
type snapshot struct {
	flags    map[string]flagConfig
	issuedAt time.Time
	// fromCache records provenance: false for a live response, true for a CachePath load.
	fromCache bool
}

func snapshotOf(envelope verifiedEnvelope, fromCache bool) *snapshot {
	issuedAt, _ := parseWireTime(envelope.payload.IssuedAt)
	return &snapshot{
		flags:     envelope.payload.Flags,
		issuedAt:  issuedAt,
		fromCache: fromCache,
	}
}
