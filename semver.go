package fortressflag

import "strings"

// Dotted-numeric version comparison for the semver_* operators — a PORT of the backend's
// internal/semver, whose package comment is the specification. It is deliberately NOT
// Semantic Versioning 2.0.0: targeting needs "is this version at least 2.0?", and the
// semantics are a contract shared with every SDK (contract-v1.md, ADR-0004; pinned by
// vectors/evaluation.json):
//
//   - Split on '.'; compare numeric components left to right.
//   - A missing component is 0: "2.0" == "2.0.0".
//   - Components must be non-negative base-10 integers. Anything else — "2.0-beta", "v2", ""
//     — does not parse. What non-parsing MEANS belongs to the caller: a context value that
//     does not parse makes the condition not hold (never an error).

// maxVersionComponentDigits bounds one component's length. Ten digits already exceed int32; a
// longer run of digits is not a version, and refusing it keeps a hostile tag value from
// turning the comparison into big-integer work.
const maxVersionComponentDigits = 10

type version []uint64

// parseVersion reports whether s is a dotted non-negative-integer version, and returns it
// parsed. It returns (nil, false) rather than an error: the caller's question is "is this
// comparable?", and evaluation may never fail over the answer.
func parseVersion(s string) (version, bool) {
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	v := make(version, 0, len(parts))
	for _, part := range parts {
		if part == "" || len(part) > maxVersionComponentDigits {
			return nil, false
		}
		var n uint64
		for i := 0; i < len(part); i++ {
			c := part[i]
			if c < '0' || c > '9' {
				return nil, false
			}
			n = n*10 + uint64(c-'0')
		}
		v = append(v, n)
	}
	return v, true
}

// compareVersions returns -1, 0 or 1 as a is less than, equal to, or greater than b. Missing
// components read as 0, which is what makes "2.0" equal "2.0.0" — the property the contract
// documents by example, and the one a naive length comparison would get wrong.
func compareVersions(a, b version) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var av, bv uint64
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		switch {
		case av < bv:
			return -1
		case av > bv:
			return 1
		}
	}
	return 0
}
