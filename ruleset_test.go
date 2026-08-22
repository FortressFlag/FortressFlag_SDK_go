package fortressflag

import (
	"encoding/json"
	"testing"
)

// Go-local decode edges the shared vectors cannot carry: the wire decoder's handling of
// absent, null and hostile values. Trap-of-record: encoding/json into a plain field cannot
// distinguish absent from null, and a naive `any` default would make a boolean flag's false
// look like nil — the RawMessage design these tests pin.

func TestDecodeValueAbsentAndNullAreNoValue(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, {}, json.RawMessage("null"), json.RawMessage(" null ")} {
		if v, ok := decodeValue(raw, "string"); ok {
			t.Errorf("decodeValue(%q) = (%v, true), want no value", raw, v)
		}
	}
}

func TestDecodeValueFalseIsAValue(t *testing.T) {
	v, ok := decodeValue(json.RawMessage("false"), "boolean")
	if !ok || v != false {
		t.Fatalf("decodeValue(false) = (%v, %v), want (false, true) — false is a value, not an absence", v, ok)
	}
}

func TestDecodeValueKindMismatchIsNoValue(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		kind string
	}{
		{`"yes"`, "boolean"},
		{`5`, "string"},
		{`true`, "number"},
		{`{"nested":true}`, "boolean"},
		{`[1,2]`, "number"},
	} {
		if v, ok := decodeValue(json.RawMessage(tc.raw), tc.kind); ok {
			t.Errorf("decodeValue(%s, %s) = (%v, true), want no value", tc.raw, tc.kind, v)
		}
	}
}

func TestDecodeValueUnknownKindFailsClosed(t *testing.T) {
	if v, ok := decodeValue(json.RawMessage("true"), "datetime"); ok {
		t.Fatalf("decodeValue(unknown kind) = (%v, true), want no value", v)
	}
}

func TestFlagConfigDecodesAbsentFields(t *testing.T) {
	var config flagConfig
	if err := json.Unmarshal([]byte(`{"kind":"number"}`), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if value, ok := evaluateFlag(config, nil, "user-1", "retry-limit"); ok {
		t.Fatalf("flag with no rules and no default served %v", value)
	}
}

func TestBooleanRuleWithHostileServeFailsClosedPastTheRule(t *testing.T) {
	var config flagConfig
	payload := `{"kind":"boolean","default":true,"rules":[{"conditions":[],"serve":"yes"}]}`
	if err := json.Unmarshal([]byte(payload), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}
	value, ok := evaluateFlag(config, nil, "user-1", "dark-mode")
	if !ok || value != true {
		t.Fatalf("evaluateFlag = (%v, %v), want the default (true, true): a rule this binary cannot interpret must not match", value, ok)
	}
}
