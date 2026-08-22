package fortressflag

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Configuration is everything the SDK needs to run. Handed to New; treated as immutable.
type Configuration struct {
	// Key is the ffs_ server key. THIS IS A GENUINE SECRET (server-contract-v1, ADR-0015):
	// it can download the full ruleset, targeting rules included. Store it in an environment
	// variable or a secret manager, never in code, never in a repository, never in a log.
	// The SDK holds it in memory, sends it only on the Authorization header, and the only
	// form of it that may ever reach a log line is keyPrefix's six-character prefix.
	Key string

	// BaseURL is the server data plane's base URL. Defaults to FortressFlag's edge.
	BaseURL string

	// PollInterval is how often to poll for a fresh ruleset. Defaults to 60 seconds — one
	// request per minute per process, so a kill switch reaches a fleet within a minute —
	// floored at the contract's 30 (ADR-0016). Jitter of ±20% is applied so a fleet does not
	// synchronise into a thundering herd against a recovering backend.
	PollInterval time.Duration

	// CachePath opts in to a durable cache: a file where the last VERIFIED envelope's raw
	// bytes persist, so a process that restarts offline keeps evaluating with what it last
	// saw. Unset — the default — means in-memory only: where a server process may write is
	// the operator's call, and this SDK writes nothing unasked (ADR-0016). The file holds
	// only the ruleset envelope, never the key and never any evaluation context.
	CachePath string

	// Signature is how the SDK treats the envelope's signature. The default is
	// SignatureDisabled — the backend does not sign yet (roadmap M4); when it does, a
	// SignatureRequired policy rejects every unverifiable payload, fail closed.
	Signature SignaturePolicy

	// HTTPTimeout is the per-request timeout. Short on purpose: a slow ruleset fetch must
	// never become the customer's problem — the snapshot keeps answering. Defaults to 10 s.
	HTTPTimeout time.Duration
}

// SignaturePolicy is how the SDK treats the signature on a ruleset envelope. Use
// SignatureDisabled (the zero value) or SignatureRequired.
type SignaturePolicy struct {
	required bool
	// trustedKeys maps the key IDs that may appear in an envelope's sig field to public key
	// bytes. Keyed so rotation is a config publish, not a redeploy.
	trustedKeys map[string][]byte
}

// SignatureDisabled accepts unsigned envelopes — the only workable policy until the
// backend's signing milestone (M4) ships, and therefore the default. A named, greppable
// value rather than a silent fallback, so "why is this not verifying?" has an answer in the
// customer's own source.
var SignatureDisabled = SignaturePolicy{}

// SignatureRequired rejects every envelope whose signature cannot be verified against
// trustedKeys — INCLUDING, until backend M4 ships a signing algorithm, every envelope there
// is: the verification stub can reject a forgery but can never accept one. Rejection is
// never fatal — the SDK keeps serving its last verified snapshot.
func SignatureRequired(trustedKeys map[string][]byte) SignaturePolicy {
	copied := make(map[string][]byte, len(trustedKeys))
	for id, key := range trustedKeys {
		copied[id] = append([]byte(nil), key...)
	}
	return SignaturePolicy{required: true, trustedKeys: copied}
}

// defaultBaseURL is FortressFlag's server data plane.
const defaultBaseURL = "https://edge.fortressflag.com"

// minimumPollInterval is the contract's floor. Anything faster is the caller volunteering to
// be rate-limited (the plane's per-key ceiling answers 429) for values that did not change.
const minimumPollInterval = 30 * time.Second

const defaultPollInterval = 60 * time.Second

const defaultHTTPTimeout = 10 * time.Second

// ErrMalformedKey means the configured value is not shaped like an ffs_ server key. It is
// returned by New — the ONE place this SDK errors, at construction, before the customer's
// process serves anything (Founding §8.1: after construction, every failure resolves to a
// fallback, never an error).
var ErrMalformedKey = errors.New("fortressflag: key is not of the form ffs_<environment>_<secret>")

// parseKey validates the configured key's shape and returns the environment it claims.
//
// SplitN with a limit of 3, NOT Split — the backend serverkey comment, ported a third time
// because the bug it prevents is identical here: the secret is base64url, whose alphabet
// includes `_`. An unlimited Split returns four or more parts for any key that happens to
// contain one, and a length check of exactly 3 rejects it — roughly three keys in four. The
// failure is silent, fleet-wide and intermittent, and the happy-path key tested by hand
// would not have contained an underscore.
func parseKey(raw string) (environment string, err error) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != "ffs" || parts[2] == "" {
		return "", ErrMalformedKey
	}
	if !validEnvironmentKey(parts[1]) {
		return "", ErrMalformedKey
	}
	return parts[1], nil
}

// validEnvironmentKey enforces the server's environments_key_format CHECK (2–32 chars,
// lowercase letters, digits and hyphens, starting and ending with a letter or digit) — the
// web SDK's Environment.of rule. A value that could never name an environment on any tenant
// is refused at construction rather than carried into a runtime "flags silently never load".
func validEnvironmentKey(key string) bool {
	if len(key) < 2 || len(key) > 32 {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		lowerOrDigit := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if lowerOrDigit {
			continue
		}
		if c == '-' && i != 0 && i != len(key)-1 {
			continue
		}
		return false
	}
	return true
}

// keyPrefixVisibleChars matches the backend's serverkey.PrefixOf: six characters of the
// random part is enough to tell two keys apart in a log line, far too few to guess the rest.
const keyPrefixVisibleChars = 6

// keyPrefix returns the non-secret leading part of the key — THE ONLY FORM OF A SERVER KEY
// THAT MAY EVER BE LOGGED (ADR-0015, ported). Empty for a malformed key.
func keyPrefix(raw string) string {
	env, err := parseKey(raw)
	if err != nil {
		return ""
	}
	head := len("ffs_") + len(env) + 1
	if len(raw) < head+keyPrefixVisibleChars {
		return ""
	}
	return raw[:head+keyPrefixVisibleChars]
}

// resolvedConfiguration is Configuration with every default applied and the key parsed —
// what the SDK actually runs on.
type resolvedConfiguration struct {
	key         string
	environment string
	baseURL     string
	interval    time.Duration
	cachePath   string
	signature   SignaturePolicy
	httpTimeout time.Duration
}

// resolveConfiguration validates and applies defaults. The one error path in the SDK.
func resolveConfiguration(configuration Configuration) (resolvedConfiguration, error) {
	environment, err := parseKey(configuration.Key)
	if err != nil {
		// Deliberately does NOT include the configured value: a mistyped secret pasted into
		// the wrong field must not land in an error string that lands in a log.
		return resolvedConfiguration{}, fmt.Errorf("fortressflag: invalid configuration: %w", err)
	}

	baseURL := configuration.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	interval := configuration.PollInterval
	if interval == 0 {
		interval = defaultPollInterval
	}
	if interval < minimumPollInterval {
		interval = minimumPollInterval
	}

	timeout := configuration.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}

	return resolvedConfiguration{
		key:         configuration.Key,
		environment: environment,
		baseURL:     baseURL,
		interval:    interval,
		cachePath:   configuration.CachePath,
		signature:   configuration.Signature,
		httpTimeout: timeout,
	}, nil
}
