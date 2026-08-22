package fortressflag

import (
	"testing"
	"time"
)

// midpoint pins jitter to the centre of its range so exact values can be asserted.
func midpoint(low, high float64) float64 { return (low + high) / 2 }

func TestRetryDelayDoublesToTheCap(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{0, 0},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{10, 1024 * time.Second},
		{11, backoffCapSeconds * time.Second},     // 2048 caps at 1800
		{10_000, backoffCapSeconds * time.Second}, // exponent capped before the power
	} {
		if got := retryDelay(tc.failures, midpoint); got != tc.want {
			t.Errorf("retryDelay(%d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

func TestDelaysAreJitteredOnTheSuccessPathToo(t *testing.T) {
	// The de-synchronisation job: the ROUTINE interval must spread across the fleet, not
	// just the failure retries — after an outage every process restarts at once.
	low := pollDelay(60*time.Second, func(low, _ float64) float64 { return low })
	high := pollDelay(60*time.Second, func(_, high float64) float64 { return high })
	if low != 48*time.Second || high != 72*time.Second {
		t.Fatalf("poll delay bounds = [%v, %v], want [48s, 72s] (±20%%)", low, high)
	}
}

func TestServerRetryHintObeyedButCapped(t *testing.T) {
	if got := retryDelayWithServerHint(30, 5, midpoint); got != 30*time.Second {
		t.Errorf("hint 30 = %v, want 30s", got)
	}
	// A hostile or misconfigured Retry-After of a year must not disable updates until the
	// process restarts.
	if got := retryDelayWithServerHint(31_536_000, 5, midpoint); got != backoffCapSeconds*time.Second {
		t.Errorf("hint 1y = %v, want the cap", got)
	}
	// No hint falls back to the exponential ladder.
	if got := retryDelayWithServerHint(0, 1, midpoint); got != 2*time.Second {
		t.Errorf("no hint = %v, want 2s", got)
	}
}
