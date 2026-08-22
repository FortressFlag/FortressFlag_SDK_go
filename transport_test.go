package fortressflag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testTransport(t *testing.T, handler http.HandlerFunc) *transport {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	resolved, err := resolveConfiguration(Configuration{Key: "ffs_dev_k", BaseURL: server.URL, HTTPTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return newTransport(resolved)
}

func TestFetchSendsExactlyTheContractsRequest(t *testing.T) {
	var seen *http.Request
	tr := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(context.Background())
		w.Header().Set("ETag", `"e1"`)
		_, _ = w.Write(fixtureEnvelope(fixturePayloadJSON(nil), ""))
	})

	outcome := tr.fetchRuleset(context.Background(), `"cached"`)
	if outcome.kind != fetchSuccess {
		t.Fatalf("outcome = %v", outcome.kind)
	}
	if outcome.etag != `"e1"` {
		t.Errorf("etag = %q", outcome.etag)
	}
	if seen.URL.Path != "/v1/server/ruleset" || seen.URL.RawQuery != "sv=1" {
		t.Errorf("request = %s?%s", seen.URL.Path, seen.URL.RawQuery)
	}
	if got := seen.Header.Get("Authorization"); got != "Bearer ffs_dev_k" {
		t.Errorf("Authorization = %q", got)
	}
	if got := seen.Header.Get("If-None-Match"); got != `"cached"` {
		t.Errorf("If-None-Match = %q", got)
	}
	// The contract names every header this SDK may send; anything beyond the standard
	// library's own transport headers is an undeclared contract change (ADR-0016).
	for header := range seen.Header {
		switch header {
		case "Authorization", "Accept", "If-None-Match", "User-Agent", "Accept-Encoding":
		default:
			t.Errorf("unexpected request header %s", header)
		}
	}
}

func TestFetchStatusMapping(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   fetchOutcomeKind
	}{
		{http.StatusNotModified, fetchNotModified},
		{http.StatusUnauthorized, fetchUnauthorized},
		{http.StatusForbidden, fetchUnauthorized},
		{http.StatusTooManyRequests, fetchRateLimited},
		{http.StatusInternalServerError, fetchServerError},
		{http.StatusServiceUnavailable, fetchServerError},
		{http.StatusTeapot, fetchUnexpectedStatus},
		{http.StatusBadRequest, fetchUnexpectedStatus}, // an sv the server does not speak
	} {
		tr := testTransport(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		})
		if outcome := tr.fetchRuleset(context.Background(), ""); outcome.kind != tc.want {
			t.Errorf("status %d → %v, want %v", tc.status, outcome.kind, tc.want)
		}
	}
}

func TestFetchRefusesRedirects(t *testing.T) {
	// A redirect could replay the Authorization header — which carries a genuine secret —
	// to wherever it points. The client refuses to follow; the poll fails like any other
	// transport failure and the snapshot keeps serving.
	redirected := false
	tr := testTransport(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/elsewhere") {
			redirected = true
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	if outcome := tr.fetchRuleset(context.Background(), ""); outcome.kind != fetchTransportError {
		t.Fatalf("outcome = %v, want transport error", outcome.kind)
	}
	if redirected {
		t.Fatal("the client followed the redirect")
	}
}

func TestFetchCapsTheResponseBody(t *testing.T) {
	tr := testTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	})
	if outcome := tr.fetchRuleset(context.Background(), ""); outcome.kind != fetchResponseTooLarge {
		t.Fatalf("outcome = %v, want responseTooLarge", outcome.kind)
	}
}

func TestFetchTimesOutOnAHangingServer(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	tr := testTransport(t, func(_ http.ResponseWriter, _ *http.Request) {
		<-release // hang until the test ends
	})
	start := time.Now()
	if outcome := tr.fetchRuleset(context.Background(), ""); outcome.kind != fetchTransportError {
		t.Fatalf("outcome = %v, want transport error", outcome.kind)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timeout took %v; the poller goroutine must never park forever", elapsed)
	}
}

func TestParseRetryAfterSeconds(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   int
	}{
		{"", 0},
		{"30", 30},
		{"-1", 0},
		{"not-a-number", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0}, // the HTTP-date form is deliberately not parsed
	} {
		if got := parseRetryAfterSeconds(tc.header); got != tc.want {
			t.Errorf("parseRetryAfterSeconds(%q) = %d, want %d", tc.header, got, tc.want)
		}
	}
}
