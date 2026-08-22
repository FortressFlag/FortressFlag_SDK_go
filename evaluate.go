package fortressflag

// Local evaluation — the reason this SDK exists (Founding §3: evaluation happens as close to
// the customer as possible), and a byte-for-byte behavioural PORT of the backend's
// clientapi evaluateValue walk. The two implementations are pinned to each other by
// vectors/evaluation.json; a semantic difference here is a wire-contract bug, never a local
// judgement call. No I/O, no logging, no allocation beyond the walk — this sits on the
// customer's hot path.

// The operator strings, mirroring the backend's flag_rules_operator_supported CHECK.
const (
	opEq        = "eq"
	opNeq       = "neq"
	opSemverEq  = "semver_eq"
	opSemverGt  = "semver_gt"
	opSemverGte = "semver_gte"
	opSemverLt  = "semver_lt"
	opSemverLte = "semver_lte"
)

// evaluateFlag walks the rules in order and returns the first match's serve value, or the
// default when nothing matches, and whether the flag has a value at all — a multivariate
// flag with no default variant and no matching rule answers (nil, false): the caller's
// fallback serves. The per-rule semantics, exactly as the contract states them:
//
//   - A rule matches when EVERY condition holds — AND within a rule, first-match-wins across
//     rules. An EMPTY condition list holds vacuously (the terminal "everyone else" rule).
//   - A condition whose tag key is absent from the context's tags does not hold; never an
//     error. eq/neq are exact string comparison, case-sensitive, no trimming. The semver
//     operators compare via parseVersion; an unparseable value on EITHER side makes the
//     condition not hold. An operator this binary does not recognise does not hold — fail
//     closed into the default (Founding §8.3).
//   - The rollout gate: conditions held, now the percentage decides. The bucket is computed
//     at most once per flag, only when a matching rule actually carries a gate, and a
//     gated-out context falls THROUGH to later rules and the default — which is what makes
//     "50% rule, then everyone-else rule" compose under first-match-wins.
//   - A rule whose serve value does not follow the flag's kind cannot be written through the
//     management API; if one ever appears, fail closed past it rather than serve a guess.
func evaluateFlag(config flagConfig, tags map[string]string, contextKey, flagKey string) (any, bool) {
	contextBucket := -1
	for _, rule := range config.Rules {
		if !ruleMatches(rule, tags) {
			continue
		}
		if rule.RolloutPercentage != nil {
			if contextBucket < 0 {
				contextBucket = bucket(contextKey, flagKey)
			}
			if contextBucket >= *rule.RolloutPercentage {
				continue
			}
		}
		if value, ok := decodeValue(rule.Serve, config.Kind); ok {
			return value, true
		}
	}
	return decodeValue(config.Default, config.Kind)
}

// ruleMatches ANDs the rule's conditions: every one must hold. Range over an empty slice
// runs zero iterations, which is exactly the vacuous truth the contract specifies.
func ruleMatches(rule flagRule, tags map[string]string) bool {
	for _, condition := range rule.Conditions {
		tagValue, present := tags[condition.TagKey]
		if !present {
			return false
		}
		if !conditionHolds(condition, tagValue) {
			return false
		}
	}
	return true
}

func conditionHolds(condition flagCondition, tagValue string) bool {
	switch condition.Operator {
	case opEq:
		return tagValue == condition.Value
	case opNeq:
		return tagValue != condition.Value
	case opSemverEq, opSemverGt, opSemverGte, opSemverLt, opSemverLte:
		context, ok := parseVersion(tagValue)
		if !ok {
			return false
		}
		target, ok := parseVersion(condition.Value)
		if !ok {
			return false
		}
		cmp := compareVersions(context, target)
		switch condition.Operator {
		case opSemverEq:
			return cmp == 0
		case opSemverGt:
			return cmp > 0
		case opSemverGte:
			return cmp >= 0
		case opSemverLt:
			return cmp < 0
		default: // opSemverLte
			return cmp <= 0
		}
	default:
		return false
	}
}
