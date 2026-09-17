package fortressflag

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The construction-time gate: the ONE place the SDK errors. Fixture keys are short and
// low-entropy on purpose (ffs_dev_k, the Android convention) — a realistic-looking ffs_
// value in this repo SHOULD page a secret scanner.

func TestParseKeyAcceptsUnderscoresInTheSecret(t *testing.T) {
	// The SplitN trap: the secret's base64url alphabet includes `_`. Roughly three real keys
	// in four contain one; an unlimited Split would reject them all.
	for _, key := range []string{"ffs_dev_k", "ffs_dev_a_b_c", "ffs_staging_x_", "ffs_eu-live_k9"} {
		env, err := parseKey(key)
		if err != nil {
			t.Errorf("parseKey(%q) errored: %v", key, err)
		}
		if env == "" {
			t.Errorf("parseKey(%q) returned an empty environment", key)
		}
	}
}

func TestParseKeyRejectsMalformedKeys(t *testing.T) {
	for _, key := range []string{
		"", "ffs", "ffs_", "ffs_dev", "ffs_dev_", "ffc_dev_k", "FFS_dev_k",
		"ffs_d_k",                               // environment below the 2-char floor
		"ffs_Dev_k",                             // uppercase environment
		"ffs_-dev_k",                            // leading hyphen
		"ffs_" + strings.Repeat("e", 33) + "_k", // environment above the 32-char cap
	} {
		if _, err := parseKey(key); !errors.Is(err, ErrMalformedKey) {
			t.Errorf("parseKey(%q) = %v, want ErrMalformedKey", key, err)
		}
	}
}

func TestKeyPrefixIsTheOnlyLoggableForm(t *testing.T) {
	if got := keyPrefix("ffs_dev_abcdefghij"); got != "ffs_dev_abcdef" {
		t.Errorf("keyPrefix = %q, want ffs_dev_abcdef", got)
	}
	// Too short to yield six visible chars, and malformed values, answer empty — never a
	// partial secret.
	for _, key := range []string{"ffs_dev_k", "not-a-key", ""} {
		if got := keyPrefix(key); got != "" {
			t.Errorf("keyPrefix(%q) = %q, want empty", key, got)
		}
	}
}

func TestResolveConfigurationDefaults(t *testing.T) {
	resolved, err := resolveConfiguration(Configuration{Key: "ffs_dev_k"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.environment != "dev" {
		t.Errorf("environment = %q", resolved.environment)
	}
	if resolved.baseURL != defaultBaseURL {
		t.Errorf("baseURL = %q", resolved.baseURL)
	}
	if resolved.interval != 60*time.Second {
		t.Errorf("interval = %v, want 60s", resolved.interval)
	}
	if resolved.httpTimeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", resolved.httpTimeout)
	}
	if !resolved.signature.required {
		t.Error("signature policy did not default to required (ADR-0025)")
	}
	if _, ok := resolved.signature.trustedKeys["prod-2026-09-k1"]; !ok {
		t.Error("default trust store lacks prod-2026-09-k1")
	}
}

func TestResolveConfigurationFloorsThePollInterval(t *testing.T) {
	resolved, err := resolveConfiguration(Configuration{Key: "ffs_dev_k", PollInterval: 5 * time.Second})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.interval != minimumPollInterval {
		t.Errorf("interval = %v, want the %v floor", resolved.interval, minimumPollInterval)
	}
}

func TestResolveConfigurationRejectsMalformedKeyWithoutEchoingIt(t *testing.T) {
	secret := "ffc_dev_pasted-the-wrong-kind-of-key"
	_, err := resolveConfiguration(Configuration{Key: secret})
	if !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("err = %v, want ErrMalformedKey", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("the constructor error echoed the configured value; a mistyped secret must not land in a log")
	}
}

func TestSignatureRequiredCopiesTheTrustStore(t *testing.T) {
	keys := map[string][]byte{"k1": {1, 2, 3}}
	policy := SignatureRequired(keys)
	keys["k2"] = []byte{4}
	keys["k1"][0] = 9
	if len(policy.trustedKeys) != 1 || policy.trustedKeys["k1"][0] != 1 {
		t.Fatal("SignatureRequired shares the caller's map; mutation after construction leaked in")
	}
}

func TestSignatureDisabledIsExplicitAndTheProductionKeyIs32Bytes(t *testing.T) {
	resolved, err := resolveConfiguration(Configuration{Key: "ffs_dev_k", Signature: SignatureDisabled})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.signature.required {
		t.Error("an explicit SignatureDisabled was overridden by the default")
	}
	key := TrustedKeysFortressFlagProduction["prod-2026-09-k1"]
	if len(key) != 32 {
		t.Errorf("production key is %d bytes, want 32", len(key))
	}
	if len(TrustedKeysFortressFlagProduction) != 1 {
		t.Errorf("production trust store has %d keys, want 1", len(TrustedKeysFortressFlagProduction))
	}
}
