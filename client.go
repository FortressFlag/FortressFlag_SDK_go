package fortressflag

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// The client core: one poller goroutine feeding an atomic snapshot the getters read
// lock-free. After New, nothing in here errors or panics — every failure becomes backoff
// plus a Diagnostics note while the last snapshot keeps answering (Founding §8.1/§8.4).

// rulesetFetcher is what the poller needs from the transport; tests script it.
type rulesetFetcher interface {
	fetchRuleset(ctx context.Context, etag string) fetchOutcome
}

// fetchStatus names the last poll's outcome for Diagnostics — the one-line answer to
// "why are flags not updating?".
const (
	statusNeverFetched     = "neverFetched"
	statusFresh            = "fresh"
	statusNotModified      = "notModified"
	statusRejectedEnvelope = "rejectedEnvelope"
	statusUnauthorized     = "unauthorized"
	statusRateLimited      = "rateLimited"
	statusServerError      = "serverError"
	statusUnexpectedStatus = "unexpectedStatus"
	statusTransportError   = "transportError"
	statusResponseTooLarge = "responseTooLarge"
)

// cacheState names the durable cache's condition for Diagnostics.
const (
	cacheDisabled    = "disabled"
	cacheEmpty       = "empty"
	cacheLoaded      = "loaded"
	cacheLoadFailed  = "loadFailed"
	cacheStored      = "stored"
	cacheStoreFailed = "storeFailed"
)

type clientState struct {
	sync.Mutex
	lastFetchAt         time.Time
	lastFetchStatus     string
	lastRejection       rejectionCode
	etag                string
	consecutiveFailures int
	cacheState          string
}

// Client polls the ruleset export and answers evaluations from its snapshot. Create with
// New; a zero Client is not usable.
type Client struct {
	configuration resolvedConfiguration
	fetcher       rulesetFetcher
	cache         *fileCache // nil when CachePath is unset

	snapshot atomic.Pointer[snapshot]
	state    clientState

	served               atomic.Uint64
	fallbackNoSnapshot   atomic.Uint64
	fallbackUnknownFlag  atomic.Uint64
	fallbackKindMismatch atomic.Uint64
	fallbackNoValue      atomic.Uint64

	// firstAttempt closes when the first fetch completes, whichever way — what Start blocks
	// on. networkReady closes when a live snapshot first exists.
	firstAttempt chan struct{}
	networkReady chan struct{}

	now    func() time.Time
	random randomInRange

	startOnce sync.Once
	closeOnce sync.Once
	stop      context.CancelFunc
	done      chan struct{}
}

func newClient(configuration resolvedConfiguration, fetcher rulesetFetcher) *Client {
	client := &Client{
		configuration: configuration,
		fetcher:       fetcher,
		firstAttempt:  make(chan struct{}),
		networkReady:  make(chan struct{}),
		now:           time.Now,
		random: func(low, high float64) float64 {
			if low >= high {
				return low
			}
			return low + rand.Float64()*(high-low) //nolint:gosec // jitter, not key material
		},
		done: make(chan struct{}),
	}
	client.state.lastFetchStatus = statusNeverFetched
	client.state.cacheState = cacheDisabled
	if configuration.cachePath != "" {
		client.cache = &fileCache{path: configuration.cachePath}
		client.state.cacheState = cacheEmpty
	}
	return client
}

// start loads the cache if configured, launches the poller, and blocks until the first
// fetch attempt completes or ctx is done. Never an error: the worst outcome is "serving
// fallbacks until the network appears", stated in the StartOutcome.
func (c *Client) start(ctx context.Context) StartOutcome {
	c.startOnce.Do(func() {
		c.loadCache()
		pollCtx, cancel := context.WithCancel(context.Background())
		c.stop = cancel
		go c.poll(pollCtx)
	})

	select {
	case <-c.networkReady:
		return StartReady
	case <-ctx.Done():
	case <-c.firstAttempt:
		// The first fetch completed. If it produced a live snapshot we are ready; if not,
		// the cache (when it loaded) is what start delivered.
		select {
		case <-c.networkReady:
			return StartReady
		default:
		}
	}
	if snap := c.snapshot.Load(); snap != nil && snap.fromCache {
		return StartCacheOnly
	}
	select {
	case <-c.networkReady:
		return StartReady
	default:
		return StartTimedOut
	}
}

// close stops the poller and waits for it. Safe to call more than once, and before start.
func (c *Client) close() {
	c.closeOnce.Do(func() {
		if c.stop != nil {
			c.stop()
			<-c.done
			return
		}
		close(c.done)
	})
}

func (c *Client) loadCache() {
	if c.cache == nil {
		return
	}
	raw, ok := c.cache.load()
	if !ok {
		return
	}
	// Expiry deliberately unenforced: this is THE cache-load half of the contract's expiry
	// asymmetry — a service that restarts after a long outage keeps evaluating with what it
	// last saw. See expectations.enforceExpiry.
	envelope, _, verified := verifyEnvelope(raw, c.configuration.signature, expectations{
		environment:   c.configuration.environment,
		now:           c.now(),
		enforceExpiry: false,
	})
	c.state.Lock()
	defer c.state.Unlock()
	if !verified {
		c.state.cacheState = cacheLoadFailed
		return
	}
	c.state.cacheState = cacheLoaded
	c.snapshot.Store(snapshotOf(envelope, true))
}

func (c *Client) poll(ctx context.Context) {
	defer close(c.done)
	first := true
	for {
		c.state.Lock()
		etag := c.state.etag
		c.state.Unlock()

		outcome := c.fetcher.fetchRuleset(ctx, etag)
		if ctx.Err() != nil {
			if first {
				close(c.firstAttempt)
			}
			return
		}
		c.record(outcome)
		if first {
			close(c.firstAttempt)
			first = false
		}

		c.state.Lock()
		failures := c.state.consecutiveFailures
		c.state.Unlock()

		var delay time.Duration
		if failures == 0 {
			delay = pollDelay(c.configuration.interval, c.random)
		} else {
			delay = retryDelayWithServerHint(outcome.retryAfterSeconds, failures, c.random)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// record turns one fetch outcome into snapshot/cache/diagnostics updates.
func (c *Client) record(outcome fetchOutcome) {
	c.state.Lock()
	defer c.state.Unlock()
	c.state.lastFetchAt = c.now()

	switch outcome.kind {
	case fetchSuccess:
		envelope, rejection, verified := verifyEnvelope(outcome.raw, c.configuration.signature, expectations{
			environment:   c.configuration.environment,
			now:           c.now(),
			enforceExpiry: true, // a live response past expiry is the replay window — refused
		})
		if !verified {
			// A rejected envelope never dislodges the snapshot or the cache: the last
			// verified state keeps serving, and the rejection is one Diagnostics read away.
			c.state.lastFetchStatus = statusRejectedEnvelope
			c.state.lastRejection = rejection
			c.state.consecutiveFailures++
			return
		}
		c.state.lastFetchStatus = statusFresh
		c.state.lastRejection = ""
		c.state.etag = outcome.etag
		c.state.consecutiveFailures = 0
		c.snapshot.Store(snapshotOf(envelope, false))
		if c.cache != nil {
			if c.cache.store(envelope.raw) {
				c.state.cacheState = cacheStored
			} else {
				c.state.cacheState = cacheStoreFailed
			}
		}
		select {
		case <-c.networkReady:
		default:
			close(c.networkReady)
		}
	case fetchNotModified:
		// The steady state of a polling fleet: the cached ruleset is current.
		c.state.lastFetchStatus = statusNotModified
		c.state.consecutiveFailures = 0
	case fetchUnauthorized:
		// A revoked key. The contract's instruction: answered like any failed fetch — keep
		// evaluating with the last downloaded ruleset, indefinitely, until given a new key.
		c.state.lastFetchStatus = statusUnauthorized
		c.state.consecutiveFailures++
	case fetchRateLimited:
		c.state.lastFetchStatus = statusRateLimited
		c.state.consecutiveFailures++
	case fetchServerError:
		c.state.lastFetchStatus = statusServerError
		c.state.consecutiveFailures++
	case fetchResponseTooLarge:
		c.state.lastFetchStatus = statusResponseTooLarge
		c.state.consecutiveFailures++
	case fetchUnexpectedStatus:
		c.state.lastFetchStatus = statusUnexpectedStatus
		c.state.consecutiveFailures++
	default: // fetchTransportError
		c.state.lastFetchStatus = statusTransportError
		c.state.consecutiveFailures++
	}
}

// value is the getters' shared path: lock-free snapshot read, kind check, evaluate. A false
// second return means "answer the caller's fallback", with the reason counted.
func (c *Client) value(flagKey string, evaluation Context, wantKind string) (any, bool) {
	snap := c.snapshot.Load()
	if snap == nil {
		c.fallbackNoSnapshot.Add(1)
		return nil, false
	}
	config, present := snap.flags[flagKey]
	if !present {
		// Absence means the flag does not exist or was archived: the caller's fallback is
		// the contract's answer.
		c.fallbackUnknownFlag.Add(1)
		return nil, false
	}
	if config.Kind != wantKind {
		// Asking Bool of a string flag is a caller bug, but never a panic: fallback, and
		// the mismatch is visible on Diagnostics.
		c.fallbackKindMismatch.Add(1)
		return nil, false
	}
	result, ok := evaluateFlag(config, evaluation.Tags, evaluation.Key, flagKey)
	if !ok {
		c.fallbackNoValue.Add(1)
		return nil, false
	}
	c.served.Add(1)
	return result, true
}

func (c *Client) diagnostics() Diagnostics {
	c.state.Lock()
	defer c.state.Unlock()
	diagnostics := Diagnostics{
		LastFetchAt:         c.state.lastFetchAt,
		LastFetchStatus:     c.state.lastFetchStatus,
		LastRejection:       string(c.state.lastRejection),
		ETag:                c.state.etag,
		ConsecutiveFailures: c.state.consecutiveFailures,
		CacheState:          c.state.cacheState,
		Resolutions: ResolutionCounters{
			Served:               c.served.Load(),
			FallbackNoSnapshot:   c.fallbackNoSnapshot.Load(),
			FallbackUnknownFlag:  c.fallbackUnknownFlag.Load(),
			FallbackKindMismatch: c.fallbackKindMismatch.Load(),
			FallbackNoValue:      c.fallbackNoValue.Load(),
		},
	}
	if snap := c.snapshot.Load(); snap != nil {
		diagnostics.SnapshotIssuedAt = snap.issuedAt
		diagnostics.FlagCount = len(snap.flags)
		if snap.fromCache {
			diagnostics.SnapshotSource = "cache"
		} else {
			diagnostics.SnapshotSource = "network"
		}
	}
	return diagnostics
}
