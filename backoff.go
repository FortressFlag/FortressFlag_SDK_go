package fortressflag

import (
	"math"
	"time"
)

// How long to wait before the next poll — a port of the web SDK's Backoff, reasoning
// included, because the second job matters MORE at server scale. The obvious job is to stop
// a process hammering a failing backend. The less obvious job is DE-SYNCHRONISATION: without
// jitter, every process in a fleet that started polling at the same moment — which, after an
// outage, is all of them — retries in lockstep, and the backend that just came back up is
// knocked over by its own clients. Jitter on the success path matters as much as on the
// failure path: a 100-process deployment restarted by an orchestrator polls as 100 spikes a
// minute forever unless the routine interval is jittered too.
//
// Randomness is injected so the bounds can be asserted in tests instead of hoped for.

type randomInRange func(low, high float64) float64

// backoffCapSeconds is the ceiling: half an hour. A process that has been failing for hours
// is almost certainly firewalled or misconfigured, and there is nothing to gain from asking
// more often — the snapshot is already answering every call.
const backoffCapSeconds = 1800

// backoffBaseSeconds is the delay after the first failure. Doubles from here.
const backoffBaseSeconds = 2

// backoffJitterFraction spreads every delay ±20%.
const backoffJitterFraction = 0.2

// retryDelay answers the wait after consecutiveFailures failures in a row.
func retryDelay(consecutiveFailures int, random randomInRange) time.Duration {
	if consecutiveFailures <= 0 {
		return 0
	}
	// Exponent capped before the power so a long-offline process cannot overflow the
	// multiplier on its ten-thousandth failed attempt.
	exponent := math.Min(float64(consecutiveFailures-1), 32)
	raw := math.Min(backoffBaseSeconds*math.Pow(2, exponent), backoffCapSeconds)
	return jittered(raw, random)
}

// pollDelay answers the wait before the next routine poll — jittered, see above.
func pollDelay(interval time.Duration, random randomInRange) time.Duration {
	return jittered(interval.Seconds(), random)
}

// retryDelayWithServerHint obeys a server that told us when to come back — but never past
// the cap: a hostile or misconfigured Retry-After of a year must not silently disable flag
// updates for a process until it restarts.
func retryDelayWithServerHint(retryAfterSeconds, consecutiveFailures int, random randomInRange) time.Duration {
	if retryAfterSeconds <= 0 {
		return retryDelay(consecutiveFailures, random)
	}
	seconds := math.Min(float64(retryAfterSeconds), backoffCapSeconds)
	return time.Duration(seconds * float64(time.Second))
}

func jittered(seconds float64, random randomInRange) time.Duration {
	spread := seconds * backoffJitterFraction
	return time.Duration(random(seconds-spread, seconds+spread) * float64(time.Second))
}
