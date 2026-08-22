package fortressflag

import (
	"os"
	"path/filepath"
	"testing"
)

// The bug class these tests exist for: "a cache that never persists and nothing notices"
// (the Android SELinux link(2) lesson). Every store is followed by a fresh cache value
// reading the file back — the kill-and-reload shape, since fileCache keeps no state.

func TestFileCacheStoreThenReloadAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ruleset.cache")
	raw := fixtureEnvelope(fixturePayloadJSON(nil), "")

	if !(&fileCache{path: path}).store(raw) {
		t.Fatal("store failed")
	}
	// A NEW instance — the restarted-process read.
	loaded, ok := (&fileCache{path: path}).load()
	if !ok || string(loaded) != string(raw) {
		t.Fatal("reload did not return the exact stored bytes")
	}
}

func TestFileCacheStoreReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ruleset.cache")
	cache := &fileCache{path: path}
	first := fixtureEnvelope(fixturePayloadJSON(nil), "")
	second := fixtureEnvelope(fixturePayloadJSON(map[string]any{"issuedAt": "2026-08-21T10:05:00Z"}), "")

	if !cache.store(first) || !cache.store(second) {
		t.Fatal("store failed")
	}
	loaded, ok := cache.load()
	if !ok || string(loaded) != string(second) {
		t.Fatal("the second store did not replace the first")
	}
	// No temp litter left beside the file.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("cache directory holds %d entries, want only the cache file", len(entries))
	}
}

func TestFileCacheLoadFailuresDegrade(t *testing.T) {
	// Missing file.
	if _, ok := (&fileCache{path: filepath.Join(t.TempDir(), "absent")}).load(); ok {
		t.Fatal("a missing file loaded")
	}
	// Empty file.
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := (&fileCache{path: empty}).load(); ok {
		t.Fatal("an empty file loaded")
	}
	// A file larger than anything we would write.
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, make([]byte, maxResponseBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := (&fileCache{path: big}).load(); ok {
		t.Fatal("an implausibly large file loaded")
	}
}

func TestFileCacheStoreFailureIsReportedNotRaised(t *testing.T) {
	// A directory that does not exist: CreateTemp fails, store reports false — the caller
	// degrades to in-memory, and nothing panics.
	cache := &fileCache{path: filepath.Join(t.TempDir(), "no-such-dir", "ruleset.cache")}
	if cache.store(fixtureEnvelope(fixturePayloadJSON(nil), "")) {
		t.Fatal("store into a missing directory claimed success")
	}
}
