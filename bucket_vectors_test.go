package fortressflag

import (
	"encoding/json"
	"os"
	"testing"
)

// The published bucketing vectors (FortressFlag_Standards/vectors/buckets.json, ADR-0013).
// The file's input field is named deviceID — the backend hashes device IDs; this SDK feeds
// its caller's context key through the identical algorithm, so the field is read as the
// opaque context-identifier string. Identical bytes in, identical bucket out, whoever
// computes it — a failure here flips real users between cohorts.

type bucketVectorFile struct {
	Algorithm string `json:"algorithm"`
	Vectors   []struct {
		ContextID string `json:"deviceID"`
		FlagKey   string `json:"flagKey"`
		Bucket    int    `json:"bucket"`
	} `json:"vectors"`
}

func TestBucketVectors(t *testing.T) {
	raw, err := os.ReadFile("internal/vectors/buckets.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file bucketVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}

	for _, vector := range file.Vectors {
		if got := bucket(vector.ContextID, vector.FlagKey); got != vector.Bucket {
			t.Errorf("bucket(%q, %q) = %d, want %d", vector.ContextID, vector.FlagKey, got, vector.Bucket)
		}
	}
}
