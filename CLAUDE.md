# FortressFlag_SDK_go — Agent & Contributor Guide

> **This repo inherits the FortressFlag founding principles.** The canonical, source-of-truth
> document lives in the backend repo (`FortressFlag_Backend/CLAUDE.md`, the founding document).
> Read it before making architectural or design decisions.
>
> ADR-nnnn refers to FortressFlag's internal architecture decision records. The public contract
> every SDK implements is `FortressFlag_Standards`; decision records are not published.
>
> When anything here conflicts with the founding document, the founding document wins.
> Priority order when in doubt: **Security → Compliance → Efficiency → Cost.**

## This repo

The **Go server SDK** — FortressFlag's first server SDK (backend ADR-0016). It embeds in a
customer's own backend service, downloads the full evaluable ruleset for one project +
environment via an `ffs_` server key, and evaluates flags **locally, in-process**. It
implements the contract published in
[`FortressFlag_Standards`](https://github.com/FortressFlag/FortressFlag_Standards)
(`contracts/server-contract-v1.md`, plus `vectors/evaluation.json` and `vectors/buckets.json`
ported as unit tests) — owned by `FortressFlag_Backend`, changed only via ADRs there.

## Non-negotiable rules (see founding doc for the full set)

### Fail-safe evaluation (Founding §8.1, §8.4)

- The SDK **never panics, never calls `os.Exit`, and never returns an error from
  evaluation.** For a server SDK the host is the customer's PROCESS — a flagging outage must
  never take down a customer's service. CI greps library sources for `panic(`, `os.Exit(`
  and `log.Fatal` and fails the build.
- Construction (`New`) is the **one** place the SDK may return an error: a malformed
  configuration, caught before the customer's process serves anything.
- `Bool`/`String`/`Number` always answer. Kind mismatch, unknown flag, no snapshot yet —
  every failure resolves to the **caller-supplied fallback**, with the reason available on
  `Diagnostics()`. There is no compiled-in `false` tier: unlike a client bundle, the caller
  states a default at every call site (a deliberate adaptation of §8.4, recorded in
  ADR-0016).
- The last verified ruleset keeps serving through any outage, indefinitely. **Expiry governs
  freshness, never validity** — a live response past `expiresAt` is refused; a `CachePath`
  load never is (the contract's expiry asymmetry).

### The server key IS a secret (server-contract-v1, ADR-0015)

The inversion of the client SDKs' "the SDK key is not a secret":

- The configuration holds the raw `ffs_` key in memory and sends it on the `Authorization`
  header. It goes **nowhere else** — never into a log line, an error string, a file (the
  opt-in cache holds the RULESET envelope, never the key), or a panic message.
- The **only loggable form is the prefix** (`ffs_<env>_` + six characters) — the backend's
  `serverkey.PrefixOf` rule, ported.
- Test fixtures use short or deliberately low-entropy keys (`ffs_dev_k`, the committed seed
  key's `seedseed…` body): a realistic-looking `ffs_` value in this repo SHOULD page a secret
  scanner, so never commit one and never allowlist a scanner finding — shorten the fixture.

### Context keys and tags are the customer's data (Founding §7.3)

- The context key (a user id, a session id — the customer's choice) and tags exist only as
  evaluation inputs. They are **never logged, never persisted, never transmitted** — this
  plane has no devices and the SDK sends no identity anywhere.
- The context key is an **opaque string**: never validated against the client SDKs'
  `dev_`/`sim_` shape, never trimmed or normalised. The rollout bucket hashes exactly the
  bytes given (`vectors/buckets.json`), or cohorts flip between components.
- The opt-in `CachePath` file holds only the last verified ruleset envelope's raw bytes.

### Zero runtime dependencies (ADR-0016)

The `require` block in `go.mod` is **empty and stays empty** — that emptiness is the gate,
the analogue of the web SDK's 10 kB ceiling (a server library has no bundle size; its
dependency count is the number that matters, and it is zero). Everything the SDK needs is
stdlib: `net/http`, `crypto/sha256`, `encoding/json`, `encoding/base64`, `sync`, `time`. A
dependency is a supply-chain decision the maintainer owns; **ask, don't add.** Dev tooling
(golangci-lint) runs in CI and never ships.

### The network surface is the contract's, exactly

`GET /v1/server/ruleset?sv=1` with `Authorization`, `Accept` and `If-None-Match` — nothing
else, ever. No SDK-version header, no telemetry: an undocumented header is an additive
contract change that goes through a backend ADR, not an SDK convenience. Default poll
interval 60 s, floored at the contract's 30; exponential backoff capped at 1800 s with ±20%
jitter **on the success path too** (fleet de-synchronisation); redirects refused (following
one could replay the Authorization header); response bodies capped at 1 MiB.

## Workflow

- Default branch: `development`. Changes go via PR with review; squash merge, linear history
  (Founding §7.5). CI is the merge gate — we cannot recall a shipped SDK.
- **Commits and PRs are authored as FortressFlag, never a personal identity.** Local commits
  carry `FortressFlag <noreply@fortressflag.com>` (a gitconfig include scoped to the
  maintainer's FortressFlag clones); PRs are opened and merged via the `fortressflag` GitHub App, because GitHub
  authors a squash commit as the PR opener's account regardless of branch authorship.
- **The public SDK API (`fortressflag.go`) and the consumed contract are
  backward-compatibility sacred** (Founding §5, §8.3) — never break a shipped SDK.
- Local gate, the same commands CI runs:
  `go build ./... && go vet ./... && golangci-lint run && go test -race ./...`
- The vector files under `internal/vectors/` are vendored copies; the canonical home is
  `FortressFlag_Standards/vectors/`. A vector change is a wire-contract change arriving via a
  backend ADR — never a test fix, and never edited only here.
