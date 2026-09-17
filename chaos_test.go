package fortressflag

import (
	"path/filepath"
	"sync"
	"testing"
)

// The suite that proves the one thing this SDK actually promises: **flagging can fail in
// any way at all, and the customer's process neither crashes nor sees an error.** Every
// other test checks that a specific thing works; these check that nothing breaks when
// everything is wrong at once — an outage, a captive portal, a wrong clock, or someone
// actively attacking us. Ported from the web SDK's chaos suite. The Go-specific invariant:
// no panic — the test harness itself fails on one — asserted under -race with getters
// hammering during snapshot swaps (CI runs this suite with -race; a mutex-free read path
// that is ALMOST right passes every single-threaded test).

// hostileOutcomes is every way a poll can go wrong, in one list.
func hostileOutcomes() []fetchOutcome {
	body := func(raw []byte) fetchOutcome {
		return fetchOutcome{kind: fetchSuccess, raw: raw, etag: `"hostile"`}
	}
	return []fetchOutcome{
		// Transport-level failures.
		{kind: fetchTransportError},
		{kind: fetchUnauthorized},
		{kind: fetchRateLimited},
		{kind: fetchRateLimited, retryAfterSeconds: 31_536_000},
		{kind: fetchServerError, status: 500},
		{kind: fetchServerError, status: 503},
		{kind: fetchUnexpectedStatus, status: 418},
		{kind: fetchUnexpectedStatus, status: 400}, // an sv the server does not speak
		{kind: fetchResponseTooLarge},
		// Bodies that are not envelopes at all.
		body(nil),
		body([]byte{}),
		body([]byte("<html>captive portal</html>")),
		body([]byte("{")),
		body([]byte("null")),
		body(make([]byte, 4096)),
		// Envelopes that are structurally valid but must not be trusted.
		body(fixtureEnvelope(fixturePayloadJSON(map[string]any{"environment": "prod"}), "")),
		body(fixtureEnvelope(fixturePayloadJSON(map[string]any{"sv": 99}), "")),
		body(fixtureEnvelope(fixturePayloadJSON(map[string]any{
			"issuedAt": "2026-08-21T08:00:00Z", "expiresAt": "2026-08-21T08:30:00Z",
		}), "")), // expired on a LIVE response — the replay window
		body(fixtureEnvelope(fixturePayloadJSON(map[string]any{"issuedAt": "2026-08-21T12:00:00Z"}), "")),
		// Truncation, the classic mid-flight failure.
		body(fixtureEnvelope(fixturePayloadJSON(nil), "")[:20]),
		// Malformed rules and values at the caps.
		body(fixtureEnvelope(fixturePayloadJSON(map[string]any{"flags": map[string]any{
			"dark-mode": map[string]any{"kind": "boolean", "default": nil, "rules": "not-a-list"},
		}}), "")),
		body(fixtureEnvelope(fixturePayloadJSON(map[string]any{"flags": "not-a-map"}), "")),
		body(fixtureEnvelope(fixturePayloadJSON(map[string]any{"flags": map[string]any{
			"dark-mode": map[string]any{"kind": "datetime", "default": true, "rules": []any{}},
		}}), "")),
		// A 304 with nothing necessarily cached behind it.
		{kind: fetchNotModified},
	}
}

func TestChaosAClientHoldingAGoodValueNeverLosesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ruleset.cache")
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}},
		func(c *Configuration) { c.CachePath = path })
	client.record(goodFetch())
	cachedBefore, ok := (&fileCache{path: path}).load()
	if !ok {
		t.Fatal("the good fetch did not reach the cache")
	}

	beta := Context{Key: "user-1", Tags: map[string]string{"cohort": "beta"}}
	for _, outcome := range hostileOutcomes() {
		client.record(outcome)
		// Whatever just happened, the client still answers from the value it recorded.
		if !client.Bool("dark-mode", beta, false) {
			t.Fatalf("a hostile outcome (%v) dislodged a held value", outcome.kind)
		}
		if got := client.String("checkout-cta", Context{Key: "user-1"}, "fallback"); got != "buy-now" {
			t.Fatalf("a hostile outcome (%v) dislodged checkout-cta: %q", outcome.kind, got)
		}
	}

	// The cache bytes are exactly what they were. Nothing hostile rewrote them.
	cachedAfter, ok := (&fileCache{path: path}).load()
	if !ok || string(cachedAfter) != string(cachedBefore) {
		t.Fatal("hostile outcomes reached the cache file")
	}
}

func TestChaosAColdClientAnswersFallbacksForeverWithoutBreaking(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}}, nil)
	for _, outcome := range hostileOutcomes() {
		client.record(outcome)
		if client.Bool("anything", Context{Key: "user-1"}, false) {
			t.Fatalf("a cold client answered true over a false fallback after %v", outcome.kind)
		}
		if got := client.Number("retry-limit", Context{Key: "user-1"}, 7); got != 7 {
			t.Fatalf("fallback number = %v after %v", got, outcome.kind)
		}
	}
}

func TestChaosSignatureHostileEnvelopesAllRejectUnderRequired(t *testing.T) {
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}},
		func(c *Configuration) {
			c.Signature = SignatureRequired(map[string][]byte{"k1": make([]byte, 32)})
		})

	// Seed via record with a disabled-policy verification path is impossible here — the
	// client's policy is required — so the held-value invariant is "still the fallback":
	// under required, nothing that is not signed by the trusted key can be accepted,
	// including a plausibly-shaped signature that does not verify.
	payload := fixturePayloadJSON(nil)
	for _, sig := range []string{"", "garbage", "ed25519:AAAA", "p256:k1:AAAA", "ed25519:unknown:AAAA", "ed25519:k1:AAAA"} {
		client.record(fetchOutcome{kind: fetchSuccess, raw: fixtureEnvelope(payload, sig)})
		diagnostics := client.Diagnostics()
		if diagnostics.LastFetchStatus != statusRejectedEnvelope {
			t.Fatalf("sig %q was not rejected: %s", sig, diagnostics.LastFetchStatus)
		}
		if diagnostics.FlagCount != 0 {
			t.Fatalf("sig %q produced a snapshot", sig)
		}
	}
}

func TestChaosConcurrentGettersDuringHostileSwaps(t *testing.T) {
	// Trap 10: the race detector's job. Getters hammer from many goroutines while the
	// recorder cycles good and hostile outcomes — the lock-free snapshot path under fire.
	client := testClient(t, &scriptedFetcher{script: []fetchOutcome{{kind: fetchTransportError}}}, nil)
	client.record(goodFetch())

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			beta := Context{Key: "user-1", Tags: map[string]string{"cohort": "beta"}}
			for {
				select {
				case <-stop:
					return
				default:
					if !client.Bool("dark-mode", beta, false) {
						t.Error("a held value was lost mid-swap")
						return
					}
					client.Diagnostics()
				}
			}
		}()
	}
	hostile := hostileOutcomes()
	for i := 0; i < 50; i++ {
		for _, outcome := range hostile {
			client.record(outcome)
		}
		client.record(goodFetch())
	}
	close(stop)
	wg.Wait()
}
