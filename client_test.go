package fortressflag

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// scriptedFetcher plays outcomes in order, then repeats the last one.
type scriptedFetcher struct {
	sync.Mutex
	script []fetchOutcome
	calls  int
}

func (s *scriptedFetcher) fetchRuleset(context.Context, string) fetchOutcome {
	s.Lock()
	defer s.Unlock()
	index := s.calls
	if index >= len(s.script) {
		index = len(s.script) - 1
	}
	s.calls++
	return s.script[index]
}

func testClient(t *testing.T, fetcher rulesetFetcher, mutate func(*Configuration)) *Client {
	t.Helper()
	// Fixtures are unsigned, so the default (required, production key) is opted out here and
	// the signature tests opt back in per case.
	configuration := Configuration{Key: "ffs_dev_k", Signature: SignatureDisabled}
	if mutate != nil {
		mutate(&configuration)
	}
	resolved, err := resolveConfiguration(configuration)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	client := newClient(resolved, fetcher)
	client.now = func() time.Time { return fixtureNow }
	t.Cleanup(client.close)
	return client
}

func goodFetch() fetchOutcome {
	return fetchOutcome{kind: fetchSuccess, raw: fixtureEnvelope(fixturePayloadJSON(nil), ""), etag: `"e1"`}
}

func TestStartReadyOnALiveFetch(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{goodFetch()}}, nil)

	outcome := client.Start(context.Background())
	if outcome != StartReady {
		t.Fatalf("Start = %v, want ready", outcome)
	}
	if !client.Bool("dark-mode", Context{Key: "user-1", Tags: map[string]string{"cohort": "beta"}}, false) {
		t.Fatal("the beta cohort rule did not serve true")
	}
	if got := client.String("checkout-cta", Context{Key: "user-1"}, "fallback"); got != "buy-now" {
		t.Fatalf("checkout-cta = %q", got)
	}
	diagnostics := client.Diagnostics()
	if diagnostics.LastFetchStatus != statusFresh || diagnostics.SnapshotSource != "network" || diagnostics.ETag != `"e1"` {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
}

func TestStartTimedOutServesFallbacks(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}}, nil)

	outcome := client.Start(context.Background())
	if outcome != StartTimedOut {
		t.Fatalf("Start = %v, want timed out", outcome)
	}
	if client.Bool("dark-mode", Context{Key: "user-1"}, false) {
		t.Fatal("no snapshot must answer the fallback")
	}
	if got := client.Number("retry-limit", Context{Key: "user-1"}, 7); got != 7 {
		t.Fatalf("fallback number = %v", got)
	}
	if client.Diagnostics().Resolutions.FallbackNoSnapshot != 2 {
		t.Fatalf("resolutions = %+v", client.Diagnostics().Resolutions)
	}
}

func TestStartCacheOnlyWhenTheNetworkIsDown(t *testing.T) {
	// Seed a cache file whose payload EXPIRED long before fixtureNow: the load must accept
	// it (expiry governs freshness, not validity) and Start must say cache-only.
	path := filepath.Join(t.TempDir(), "ruleset.cache")
	expired := fixtureEnvelope(fixturePayloadJSON(map[string]any{
		"issuedAt": "2026-08-01T09:00:00Z", "expiresAt": "2026-08-01T09:30:00Z",
	}), "")
	if !(&fileCache{path: path}).store(expired) {
		t.Fatal("seed store failed")
	}

	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}},
		func(c *Configuration) { c.CachePath = path })

	outcome := client.Start(context.Background())
	if outcome != StartCacheOnly {
		t.Fatalf("Start = %v, want cache-only", outcome)
	}
	if !client.Bool("dark-mode", Context{Key: "user-1", Tags: map[string]string{"cohort": "beta"}}, false) {
		t.Fatal("the cached ruleset did not serve")
	}
	diagnostics := client.Diagnostics()
	if diagnostics.SnapshotSource != "cache" || diagnostics.CacheState != cacheLoaded {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
}

func TestAFreshFetchWritesTheCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ruleset.cache")
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{goodFetch()}},
		func(c *Configuration) { c.CachePath = path })

	if outcome := client.Start(context.Background()); outcome != StartReady {
		t.Fatalf("Start = %v", outcome)
	}
	loaded, ok := (&fileCache{path: path}).load()
	if !ok || string(loaded) != string(goodFetch().raw) {
		t.Fatal("the verified envelope's raw bytes did not reach the cache file")
	}
	if client.Diagnostics().CacheState != cacheStored {
		t.Fatalf("cacheState = %s", client.Diagnostics().CacheState)
	}
}

// The state-transition table, driven through record() directly so no poll timing is
// involved.
func TestRecordTransitions(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}}, nil)

	// A fresh success publishes the snapshot and resets the failure streak.
	client.record(goodFetch())
	if diagnostics := client.Diagnostics(); diagnostics.ConsecutiveFailures != 0 || diagnostics.FlagCount != 2 {
		t.Fatalf("after success: %+v", diagnostics)
	}

	// A 304 is a success: streak stays 0, snapshot untouched.
	client.record(fetchOutcome{kind: fetchNotModified})
	if diagnostics := client.Diagnostics(); diagnostics.LastFetchStatus != statusNotModified ||
		diagnostics.ConsecutiveFailures != 0 || diagnostics.FlagCount != 2 {
		t.Fatalf("after 304: %+v", diagnostics)
	}

	// A revoked key: polls fail, evaluation keeps serving the last snapshot.
	client.record(fetchOutcome{kind: fetchUnauthorized})
	client.record(fetchOutcome{kind: fetchUnauthorized})
	diagnostics := client.Diagnostics()
	if diagnostics.LastFetchStatus != statusUnauthorized || diagnostics.ConsecutiveFailures != 2 {
		t.Fatalf("after 401s: %+v", diagnostics)
	}
	if !client.Bool("dark-mode", Context{Key: "u", Tags: map[string]string{"cohort": "beta"}}, false) {
		t.Fatal("a revoked key dislodged the snapshot")
	}

	// A rejected envelope (wrong environment) never dislodges the snapshot either.
	client.record(fetchOutcome{kind: fetchSuccess,
		raw: fixtureEnvelope(fixturePayloadJSON(map[string]any{"environment": "prod"}), "")})
	diagnostics = client.Diagnostics()
	if diagnostics.LastFetchStatus != statusRejectedEnvelope || diagnostics.LastRejection != string(rejectEnvironmentMismatch) {
		t.Fatalf("after rejection: %+v", diagnostics)
	}
	if diagnostics.FlagCount != 2 {
		t.Fatal("a rejected envelope dislodged the snapshot")
	}
}

func TestWholesaleOverwriteDropsDepartedFlags(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}}, nil)
	client.record(goodFetch())
	if got := client.String("checkout-cta", Context{Key: "u"}, "fallback"); got != "buy-now" {
		t.Fatalf("checkout-cta = %q", got)
	}

	// The next payload no longer carries checkout-cta — an archived flag. It must leave
	// the snapshot on the same poll: absence means the caller's fallback, fleet-wide.
	client.record(fetchOutcome{kind: fetchSuccess, raw: fixtureEnvelope(fixturePayloadJSON(map[string]any{
		"flags": map[string]any{
			"dark-mode": map[string]any{"kind": "boolean", "default": true, "rules": []any{}},
		},
	}), "")})
	if got := client.String("checkout-cta", Context{Key: "u"}, "fallback"); got != "fallback" {
		t.Fatalf("an archived flag still served %q", got)
	}
	if client.Diagnostics().Resolutions.FallbackUnknownFlag != 1 {
		t.Fatalf("resolutions = %+v", client.Diagnostics().Resolutions)
	}
}

func TestKindMismatchAnswersTheFallback(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}}, nil)
	client.record(goodFetch())

	if got := client.Bool("checkout-cta", Context{Key: "u"}, true); got != true {
		t.Fatal("Bool of a string flag did not answer the fallback")
	}
	if client.Diagnostics().Resolutions.FallbackKindMismatch != 1 {
		t.Fatalf("resolutions = %+v", client.Diagnostics().Resolutions)
	}
}

func TestCloseStopsThePollerAndIsIdempotent(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{goodFetch()}}, nil)
	if outcome := client.Start(context.Background()); outcome != StartReady {
		t.Fatalf("Start = %v", outcome)
	}
	client.Close()
	client.Close() // must not panic or hang
	// The poller goroutine has exited: done is closed.
	select {
	case <-client.done:
	default:
		t.Fatal("done is not closed after Close")
	}
}

func TestStartAgainReportsWithoutRestarting(t *testing.T) {
	fetcher := &scriptedFetcher{script: []fetchOutcome{goodFetch()}}
	client := testClient(t, fetcher, nil)
	if outcome := client.Start(context.Background()); outcome != StartReady {
		t.Fatalf("first Start = %v", outcome)
	}
	if outcome := client.Start(context.Background()); outcome != StartReady {
		t.Fatalf("second Start = %v", outcome)
	}
}

func TestConcurrentGettersDuringSnapshotSwaps(t *testing.T) {
	// The race detector's job (Trap 10): getters hammer while snapshots swap. A mutex-free
	// read path that is ALMOST right passes every single-threaded test.
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}}, nil)
	client.record(goodFetch())

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					client.Bool("dark-mode", Context{Key: "user-1", Tags: map[string]string{"cohort": "beta"}}, false)
					client.Diagnostics()
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		client.record(goodFetch())
	}
	close(stop)
	wg.Wait()
}
