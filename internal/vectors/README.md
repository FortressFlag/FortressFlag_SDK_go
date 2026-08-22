# Vendored contract vectors

These files are verbatim copies; the canonical home is
[`FortressFlag_Standards/vectors/`](https://github.com/FortressFlag/FortressFlag_Standards/tree/development/vectors)
(the device-ids.json vendoring precedent from the web SDK). A vector change is a
wire-contract change arriving via a backend ADR — update the canonical file first, then
re-vendor here; never edit only this copy, and never treat a failing vector as a test to fix.

`buckets.json`'s input field is named `deviceID` because the backend hashes device IDs; this
SDK feeds its caller's context key through the same algorithm — the field is the opaque
context-identifier string, and identical bytes must land in identical buckets whoever
computes them.
