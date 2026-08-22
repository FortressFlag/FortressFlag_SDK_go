package fortressflag

import (
	"encoding/json"
	"os"
	"testing"
)

// The published evaluation-semantics vectors (FortressFlag_Standards/vectors/evaluation.json,
// ADR-0016), fed through this package's own wire decoder and evaluator — which is the point
// of publishing them in the export's shape. A failure here is a contract divergence, never a
// test to adjust.

type evaluationVectorFile struct {
	Description string `json:"description"`
	Vectors     []struct {
		Name  string     `json:"name"`
		Flag  flagConfig `json:"flag"`
		Input struct {
			ContextKey string            `json:"contextKey"`
			FlagKey    string            `json:"flagKey"`
			Tags       map[string]string `json:"tags"`
		} `json:"input"`
		Expected struct {
			Value   any  `json:"value"`
			NoValue bool `json:"noValue"`
		} `json:"expected"`
	} `json:"vectors"`
}

func TestEvaluationVectors(t *testing.T) {
	raw, err := os.ReadFile("internal/vectors/evaluation.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file evaluationVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}

	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			value, ok := evaluateFlag(vector.Flag, vector.Input.Tags, vector.Input.ContextKey, vector.Input.FlagKey)
			if vector.Expected.NoValue {
				if ok {
					t.Fatalf("evaluateFlag = (%v, true), want no value", value)
				}
				return
			}
			if !ok {
				t.Fatalf("evaluateFlag answered no value, want %v", vector.Expected.Value)
			}
			if value != vector.Expected.Value {
				t.Fatalf("evaluateFlag = %v (%T), want %v (%T)",
					value, value, vector.Expected.Value, vector.Expected.Value)
			}
		})
	}
}
