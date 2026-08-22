# FortressFlag_SDK_go

The FortressFlag **Go server SDK** (backend ADR-0016): polls the server data plane's ruleset
export with an `ffs_` server key and evaluates flags **locally, in-process** — no network hop
per flag check.

```go
client, err := fortressflag.New(fortressflag.Configuration{
	Key: os.Getenv("FF_SERVER_KEY"),
})
if err != nil {
	// The one place the SDK errors: a malformed configuration, before anything serves.
}
client.Start(ctx) // blocks until the first ruleset (or ctx is done); never fatal
defer client.Close()

enabled := client.Bool("dark-mode", fortressflag.Context{
	Key:  "user-42", // your stable context identifier: a user id, a session id — your choice
	Tags: map[string]string{"cohort": "beta"},
}, false) // the fallback served if the flag is unknown or nothing was ever fetched
```

It implements
[`FortressFlag_Standards/contracts/server-contract-v1.md`](https://github.com/FortressFlag/FortressFlag_Standards/blob/development/contracts/server-contract-v1.md)
— owned by `FortressFlag_Backend`, changed only via ADRs there. Zero runtime dependencies;
evaluation never returns an error and never panics. See `CLAUDE.md` for the rules this repo
holds itself to.

**The `ffs_` server key is a genuine secret** — treat it like a database password. Store it in
an environment variable or a secret manager, never in code or logs.
