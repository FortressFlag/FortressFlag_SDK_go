# Security Policy

FortressFlag holds the switches that turn our customers' production behavior on and off. A
compromise of FortressFlag is a compromise of every customer that trusts us (Founding CLAUDE.md
§2.1). We would rather hear about a problem early and awkwardly than late and publicly.

## Reporting a vulnerability

**Use GitHub private vulnerability reporting:** open the repository's **Security** tab and choose
**Report a vulnerability**. This creates a private advisory that only maintainers can see, so a
report never sits in a public issue while it is still exploitable.

Please do not open a public issue, pull request, or discussion for a suspected vulnerability.

Helpful reports usually include: what you found, how to reproduce it, which component and version,
and what an attacker gets out of it. A rough report you send today beats a polished one you send
next month.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement that a human has read it | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for critical/high findings | 30 days from assessment |

These are targets for a small team, stated so you know when to chase us rather than assume
silence means indifference. If a target slips, we will tell you where the work stands.

## Scope

This repository is the **Go server SDK** — code that runs inside our customers' own server
processes. It holds a genuine secret (the `ffs_` server key), receives the customer's targeting
rules, and is handed the customer's own context identifiers on every evaluation. Findings we
especially want to hear about:

- **The server key reaching anywhere but the `Authorization` header.** A log line, an error
  string, a panic message, the cache file — the only loggable form is the prefix
  (`ffs_<env>_` plus six characters). Anything wider is a secret leak, not a logging bug.
- **Customer data leaving in-process evaluation.** Context keys and tags are the customer's
  data and exist only as evaluation inputs — never logged, persisted or transmitted.
- **Cache-file exposure.** The opt-in `CachePath` file holds the last verified ruleset
  envelope's raw bytes and nothing else. Anything that stores more, or somewhere other
  processes can read, is a finding.
- **Host-process impact.** The SDK must never panic, leak goroutines, block an evaluation
  path, or take down the customer's process when flagging is unavailable (§8.1).
- **Ruleset or transport integrity** — anything letting an attacker feed the SDK a ruleset it
  should not accept, including around the Ed25519 verification of every payload.

Two notes specific to this repo:

- **We cannot recall a shipped SDK.** A vulnerable version lives in customers' services until
  they upgrade and redeploy, on their schedule. That makes findings here long-lived, and
  worth reporting even when they look minor.
- **Keep example keys low-entropy.** A realistic-looking `ffs_` value in this repository
  should page a secret scanner; fixtures use short, obviously fake keys such as `ffs_dev_k`.

Other components live in their own repositories, each with this policy: the other SDKs
(`FortressFlag_SDK_ios`, `FortressFlag_SDK_android`, `FortressFlag_SDK_web`,
`FortressFlag_SDK_node`, `FortressFlag_SDK_python`, `FortressFlag_SDK_java`), the contract
publication `FortressFlag_Standards`, `FortressFlag_Backend` (control plane),
`FortressFlag_Frontend` (dashboard), `FortressFlag_Infra` (infrastructure).

## Safe harbour

If you make a good-faith effort to follow this policy, we will not pursue legal action against you
for your research. Good faith means: you do not access, modify, or retain data belonging to anyone
but yourself; you do not degrade service for others; you stop when you have proven the issue rather
than exploring how far it goes; and you give us a reasonable chance to fix it before disclosing.

## Disclosure

We will credit reporters who want credit, and coordinate timing on a public advisory once a fix is
available. If a finding affects customer data, our obligations under GDPR — including the 72-hour
notification window for a personal-data breach — take precedence over any disclosure timeline
agreed here.
