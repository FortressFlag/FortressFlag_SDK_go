package fortressflag

import (
	"context"
	"time"
)

// The public surface of the SDK, enumerated in this one file (plus Configuration,
// SignaturePolicy, SignatureDisabled, SignatureRequired and ErrMalformedKey in
// configuration.go, which this list is the index of). Everything else in the package is
// internal. From the first release onward this surface is backward-compatibility sacred
// (Founding §5, §8.3): we cannot recall a shipped SDK.
//
//	New(Configuration) (*Client, error)
//	(*Client).Start(context.Context) StartOutcome
//	(*Client).Bool / String / Number(key, Context, fallback)
//	(*Client).Diagnostics() Diagnostics
//	(*Client).Close()

// Context is one evaluation's input: the customer's stable context identifier and the tags
// their rules target. Key is an opaque string — a user ID, a session ID, whatever the
// caller uses consistently — and it feeds the rollout bucket, so the same key must mean the
// same subject everywhere. It is never validated, never stored and never transmitted; a
// user ID is the expected case, and it is the customer's data (Founding §7.3).
type Context struct {
	Key  string
	Tags map[string]string
}

// StartOutcome is what Start delivered — a statement of fact, never a failure: the client
// keeps polling in the background whichever way Start returns.
type StartOutcome int

const (
	// StartReady means a live ruleset was fetched and verified: evaluation answers current
	// values.
	StartReady StartOutcome = iota
	// StartCacheOnly means the network has not answered yet but the CachePath file had a
	// verified ruleset: evaluation answers the last state this deployment saw.
	StartCacheOnly
	// StartTimedOut means the context ended before any ruleset existed: evaluation answers
	// caller fallbacks until a poll succeeds.
	StartTimedOut
)

// String names the outcome for logs and the example program.
func (o StartOutcome) String() string {
	switch o {
	case StartReady:
		return "ready"
	case StartCacheOnly:
		return "cache-only"
	default:
		return "timed-out-serving-defaults"
	}
}

// Diagnostics is the SDK's observable state — the one-read answer to "why is this flag not
// what I expected?". It contains no secrets (the key appears in no form, not even its
// prefix) and none of the caller's context data.
type Diagnostics struct {
	// LastFetchAt is when the poller last completed an attempt, zero before the first.
	LastFetchAt time.Time
	// LastFetchStatus names the outcome: fresh, notModified, unauthorized, rateLimited,
	// serverError, unexpectedStatus, transportError, responseTooLarge, rejectedEnvelope,
	// neverFetched.
	LastFetchStatus string
	// LastRejection is the envelope-verification rejection behind a rejectedEnvelope
	// status, empty otherwise.
	LastRejection string
	// ETag is the validator the next conditional poll will present.
	ETag string
	// ConsecutiveFailures is the failure streak feeding the backoff; 0 in steady state.
	ConsecutiveFailures int
	// SnapshotIssuedAt is the served ruleset's issue time — its age is the staleness bound.
	SnapshotIssuedAt time.Time
	// SnapshotSource is "network", "cache", or "" while no snapshot exists.
	SnapshotSource string
	// FlagCount is how many flags the snapshot carries.
	FlagCount int
	// CacheState reports the CachePath file: disabled, empty, loaded, loadFailed, stored,
	// storeFailed.
	CacheState string
	// Resolutions counts how evaluations were answered since construction.
	Resolutions ResolutionCounters
}

// ResolutionCounters counts evaluation outcomes: Served answered from the ruleset; the
// Fallback counters answered the caller's fallback, by reason.
type ResolutionCounters struct {
	Served               uint64
	FallbackNoSnapshot   uint64
	FallbackUnknownFlag  uint64
	FallbackKindMismatch uint64
	FallbackNoValue      uint64
}

// New validates the configuration and builds a client. This is the ONE place the SDK
// returns an error (a malformed key or configuration), deliberately at construction —
// before the customer's process serves anything. After New, no call errors and no call
// panics (Founding §8.1).
func New(configuration Configuration) (*Client, error) {
	resolved, err := resolveConfiguration(configuration)
	if err != nil {
		return nil, err
	}
	return newClient(resolved, newTransport(resolved)), nil
}

// Start launches the poller (loading the CachePath file first, when configured) and blocks
// until the first ruleset exists — from network or cache — or ctx is done. It returns a
// StartOutcome, never an error: a service must be free to finish starting while flags are
// still on their way, serving caller fallbacks meanwhile. Calling Start again reports the
// current state without side effects.
func (c *Client) Start(ctx context.Context) StartOutcome {
	return c.start(ctx)
}

// Close stops the poller and waits for it to finish. Safe to call more than once.
func (c *Client) Close() {
	c.close()
}

// Bool answers a boolean flag for one evaluation context, or fallback when it cannot: no
// snapshot yet, unknown or archived flag, a flag of a different kind. It never errors and
// never blocks — a lock-free read of the current snapshot plus a pure evaluation.
func (c *Client) Bool(key string, evaluation Context, fallback bool) bool {
	value, ok := c.value(key, evaluation, "boolean")
	if !ok {
		return fallback
	}
	result, isBool := value.(bool)
	if !isBool {
		return fallback
	}
	return result
}

// String answers a string flag, or fallback. See Bool for the resolution rules.
func (c *Client) String(key string, evaluation Context, fallback string) string {
	value, ok := c.value(key, evaluation, "string")
	if !ok {
		return fallback
	}
	result, isString := value.(string)
	if !isString {
		return fallback
	}
	return result
}

// Number answers a number flag, or fallback. See Bool for the resolution rules.
func (c *Client) Number(key string, evaluation Context, fallback float64) float64 {
	value, ok := c.value(key, evaluation, "number")
	if !ok {
		return fallback
	}
	result, isNumber := value.(float64)
	if !isNumber {
		return fallback
	}
	return result
}

// Diagnostics reports the SDK's current observable state.
func (c *Client) Diagnostics() Diagnostics {
	return c.diagnostics()
}
