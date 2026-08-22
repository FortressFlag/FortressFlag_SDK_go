package fortressflag

import (
	"io"
	"os"
	"path/filepath"
)

// The opt-in durable cache (ADR-0016): the file named by CachePath holds the last VERIFIED
// envelope's raw bytes — verbatim, never a re-serialisation (re-serialising would strip
// future fields and break the signature on reload), never parsed values, never the key,
// never any evaluation context. The caller re-verifies on load (expiry unenforced — the
// asymmetry), so poisoning the cache requires forging whatever the transport requires, and
// the cache inherits every transport guarantee for free.
//
// Every failure here degrades to in-memory operation with a note on Diagnostics — a cache
// problem is never the customer's problem.

type fileCache struct {
	path string
}

// load returns the cached envelope bytes, or false when there is nothing usable. A file
// larger than the transport's own response cap was not written by us; it is ignored rather
// than read (a hostile or broken writer must not balloon this process's memory).
func (c *fileCache) load() ([]byte, bool) {
	file, err := os.Open(c.path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = file.Close() }()

	raw, err := io.ReadAll(io.LimitReader(file, maxResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxResponseBytes {
		return nil, false
	}
	return raw, true
}

// store atomically replaces the cache file with raw. Temp-file-in-the-SAME-directory +
// rename, deliberately: os.CreateTemp("", …) would put the temp file in the system temp
// directory, and a cross-filesystem rename fails with EXDEV — the "cache that never
// persists and nothing notices" bug class (on Android the equivalent failed silently under
// SELinux and every write was lost). The rename is what makes a crash mid-write leave the
// last good envelope in place rather than a truncated one.
func (c *fileCache) store(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maxResponseBytes {
		return false
	}
	directory := filepath.Dir(c.path)
	temp, err := os.CreateTemp(directory, ".fortressflag-cache-*")
	if err != nil {
		return false
	}
	tempName := temp.Name()
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return false
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return false
	}
	if err := os.Rename(tempName, c.path); err != nil {
		_ = os.Remove(tempName)
		return false
	}
	return true
}
