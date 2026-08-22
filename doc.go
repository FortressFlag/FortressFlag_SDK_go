// Package fortressflag is the FortressFlag Go server SDK (backend ADR-0016).
//
// It downloads the full evaluable ruleset for one project + environment from
// GET /v1/server/ruleset with an ffs_ server key (a genuine secret — see CLAUDE.md), holds it
// in an immutable in-memory snapshot, and evaluates flags locally, in-process: no network hop
// per flag check. Evaluation never returns an error and never panics; every failure resolves
// to the caller-supplied fallback (Founding §8.1/§8.4, adapted for a server host).
package fortressflag
