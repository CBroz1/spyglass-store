# Change Log

A [changelog](https://keepachangelog.com/en/1.0.0/) of notable changes.

## [0.1.0] (Unreleased)

Nothing has shipped, so this is what the first release contains rather than an
account of getting there.

### Added

- Permission and metering broker for shared NWB storage: device-flow login,
    file resolution, registration, content redirect, and visibility, against the
    v1 contract in `openapi.yaml` #1
- DataJoint data model — `Account`, `File`, `FileAccess`, `AccessLog` — over a
    content-addressed object layout, `spyglass/v1/<ab>/<cd>/<sha256>` #1
- Read permissions: public, owner, or a shared `LabTeam`, and for an analysis
    file the audience of the raw it came from unless it declared its own. Deny
    by default #1
- Spyglass's lab and file tables reflected rather than imported, so the broker
    needs no Spyglass install — and checked at startup, so a rename upstream
    fails the boot instead of a user's request #1
- S3 adapter for any S3-compatible bucket, signing both integrity headers
    because stores disagree about which they honour. `GET /info` reports which
    digests are worth a client computing #1
- Possession proof: knowing a hash is not enough to claim the bytes behind it #1
- Per-account volume quota, aggregated in SQL from the audit log #1
- Admin CLI: accounts, tiers, files, audit, and reconciliation #1
- Deployment recipe: compose stack behind an nginx edge that rate limits the
    unauthenticated login endpoints, an optional TLS overlay, and an
    `env.example` listing every setting #1
