<!--
Keep the PR description honest and specific. State non-obvious tradeoffs and which pillar they
serve: Security → Compliance → Efficiency → Cost (Founding CLAUDE.md §2).
-->

## What & why

## Compliance & security review

<!--
This block is not paperwork. SOC 2 Type II is graded by sampling real changes and asking for
evidence that review happened; GDPR expects data-protection questions to be asked at design time,
not at incident time. Answering here is what turns "we review changes" from a claim into a record.

This repository deserves the sharpest version of these questions. It is a component that runs
inside our customers' own server processes, where we cannot ship a fix on our own schedule —
customers upgrade on theirs. It holds a genuine secret (the ffs_ server key), it receives the
customer's targeting rules, and it is handed the customer's own context identifiers on every
evaluation.

Tick every box that applies — or tick the last one. A block with nothing ticked is an unfinished
PR, not a PR with nothing to declare: that is the whole point of the last box.
-->

- [ ] **Server-key handling** — touches how the `ffs_` key is stored, sent, or could reach a
      log, error string, or file (server-contract-v1 "The server key IS a secret"; ADR-0015).
      _The only loggable form is the prefix. Test fixtures stay short or deliberately
      low-entropy — a realistic `ffs_` value here SHOULD page a secret scanner._
- [ ] **Customer data** — touches what happens to context keys or tags: logged, persisted,
      transmitted anywhere beyond in-process evaluation (Founding §7.3). _They are the
      customer's data — a user ID is the expected case — and exist only as evaluation inputs._
- [ ] **Filesystem** — changes what the opt-in `CachePath` cache writes, where, or how
      (ADR-0016). _The cache holds the last verified ruleset envelope's raw bytes, nothing
      else, written atomically; unset means the SDK writes nothing, ever._
- [ ] **Network surface** — changes what the SDK sends, to where, or how often. _The contract
      names every header; an extra one is an ADR, not a convenience. Poll cadence, backoff and
      the response-size cap are load-bearing._
- [ ] **Host-process impact** — could panic, leak goroutines, block an evaluation path, or
      otherwise affect the customer's process (Founding §8.1). _Evaluation is lock-free reads
      of an immutable snapshot; `Start` is the only sanctioned blocking call._
- [ ] **Public API** — changes the SDK's public surface (`fortressflag.go`). _Backward
      compatibility on public SDK APIs is sacred (§8.3). We cannot recall a shipped version._
- [ ] **None of the above.** I checked, and this change touches none of them.

<!-- For every box ticked above, answer here: what changed, which control covers it, and what you
     updated. -->

## Fallback behaviour

<!--
Founding §8.4, adapted for a server host (ADR-0016): last verified snapshot first, then the
caller-supplied fallback. If this change touches evaluation, caching, or any error path, state
how that still holds — including cold start with no connectivity, a CachePath load after a long
outage (expiry unenforced), and a revoked key mid-run.
-->

## Testing

<!-- What you ran and what it proved. The local gate is
     go build ./... && go vet ./... && golangci-lint run && go test -race ./...
     Say what you verified beyond it — especially against a live backend, which CI cannot do. -->

## Tradeoffs

<!-- What this gives up, and why that is the right call. Delete if genuinely none. -->
