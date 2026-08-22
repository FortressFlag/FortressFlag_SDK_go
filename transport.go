package fortressflag

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// The transport: one GET, treated as talking to a potentially hostile network. The three
// lines every FortressFlag SDK transport carries (ports of the Android/web rules):
//
//   - An explicit client Timeout — the zero-value http.Client has NONE, and a hung server
//     would park the poller goroutine forever.
//   - CheckRedirect refuses — following a redirect could replay the Authorization header,
//     which carries a genuine secret, to wherever the redirect points.
//   - The response body is capped at 1 MiB — a hostile or broken server must not be able to
//     balloon this process's memory. Real payloads are kilobytes.

// maxResponseBytes bounds a response body. Shared with the cache's load bound.
const maxResponseBytes = 1 << 20

// fetchOutcome is everything a poll can produce. Never an error to the caller: every way
// the network can fail is an enumerated outcome the poller turns into backoff + diagnostics.
type fetchOutcome struct {
	kind fetchOutcomeKind
	// raw is the body for fetchSuccess.
	raw []byte
	// etag is the validator for fetchSuccess, empty if the server sent none.
	etag string
	// status is the HTTP status for fetchUnexpectedStatus / fetchServerError.
	status int
	// retryAfterSeconds is the parsed Retry-After for fetchRateLimited, 0 if absent.
	retryAfterSeconds int
}

type fetchOutcomeKind int

const (
	fetchSuccess          fetchOutcomeKind = iota
	fetchNotModified                       // 304 — a success: the cached ruleset is current, and the poll still metered
	fetchUnauthorized                      // 401/403 — a revoked or wrong key; keep serving the snapshot
	fetchRateLimited                       // 429 — the per-key abuse ceiling; Retry-After feeds the backoff
	fetchServerError                       // 5xx
	fetchUnexpectedStatus                  // anything else, including a refused redirect's 3xx
	fetchTransportError                    // dial/timeout/cancel — the network itself failed
	fetchResponseTooLarge                  // body exceeded maxResponseBytes
)

type transport struct {
	client  *http.Client
	baseURL string
	key     string
}

func newTransport(configuration resolvedConfiguration) *transport {
	return &transport{
		client: &http.Client{
			Timeout: configuration.httpTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("fortressflag: redirects are refused — a redirect could replay the Authorization header")
			},
		},
		baseURL: configuration.baseURL,
		key:     configuration.key,
	}
}

// fetchRuleset performs one conditional GET of the ruleset export — exactly the request the
// contract shows, no more: Authorization, Accept, If-None-Match. There is no SDK-version
// header and no telemetry; an undocumented header would be an additive contract change that
// goes through an ADR (ADR-0016).
func (t *transport) fetchRuleset(ctx context.Context, etag string) fetchOutcome {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		t.baseURL+"/v1/server/ruleset?sv="+strconv.Itoa(supportedServerContractVersion), nil)
	if err != nil {
		return fetchOutcome{kind: fetchTransportError}
	}
	request.Header.Set("Authorization", "Bearer "+t.key)
	request.Header.Set("Accept", "application/json")
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}

	response, err := t.client.Do(request)
	if err != nil {
		// The redirect refusal surfaces here too — deliberately indistinguishable from any
		// other transport failure: the snapshot keeps serving either way.
		return fetchOutcome{kind: fetchTransportError}
	}
	defer func() { _ = response.Body.Close() }()

	switch {
	case response.StatusCode == http.StatusNotModified:
		return fetchOutcome{kind: fetchNotModified}
	case response.StatusCode == http.StatusOK:
		// Read one byte past the cap to distinguish "exactly at the cap" from "over it".
		body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		if err != nil {
			return fetchOutcome{kind: fetchTransportError}
		}
		if len(body) > maxResponseBytes {
			return fetchOutcome{kind: fetchResponseTooLarge}
		}
		return fetchOutcome{kind: fetchSuccess, raw: body, etag: response.Header.Get("ETag")}
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return fetchOutcome{kind: fetchUnauthorized}
	case response.StatusCode == http.StatusTooManyRequests:
		return fetchOutcome{kind: fetchRateLimited, retryAfterSeconds: parseRetryAfterSeconds(response.Header.Get("Retry-After"))}
	case response.StatusCode >= 500:
		return fetchOutcome{kind: fetchServerError, status: response.StatusCode}
	default:
		return fetchOutcome{kind: fetchUnexpectedStatus, status: response.StatusCode}
	}
}

// parseRetryAfterSeconds reads Retry-After as delta-seconds ONLY. The HTTP-date form is
// deliberately not parsed (the Android/web rule): date parsing against a wrong local clock
// can produce an enormous delay, and the backoff caps whatever this returns anyway.
func parseRetryAfterSeconds(header string) int {
	if header == "" {
		return 0
	}
	seconds, err := strconv.Atoi(header)
	if err != nil || seconds < 0 {
		return 0
	}
	return seconds
}
