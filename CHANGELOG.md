# Change Log

This is a [changelog](https://keepachangelog.com/en/1.0.0/) designed to document
all notable changes to this project.

## [0.1.0] (Unreleased)

### Added

- Repository scaffold: broker service, admin CLI, and deploy packages #1
- API contract v1 in `openapi.yaml`, covering device-flow login, file
    resolution, registration, content redirect, and visibility #1
- DataJoint data model: `Account`, `File`, `FileAccess`, `AccessLog` #1
- Content-addressed object layout, `spyglass/v1/<ab>/<cd>/<sha256>` #1
- Read Spyglass lab tables via a reflected schema, so the broker needs no
    Spyglass install #1
- Read-permission engine: public, owner, or shared team; deny by default #1
- S3 adapter usable against any S3-compatible bucket, with per-backend
    profiles for Cloudflare R2, SeaweedFS, Ceph RGW, Garage, and AWS #1
- Startup checks for the object store and the Spyglass lab schema, so
    misconfiguration fails the boot rather than a user request #1
- Rate limit on the unauthenticated login endpoints, at an nginx edge that
    publishes the broker; they spend the deployment's shared GitHub client id,
    so an unthrottled caller could deny logins to everyone #1
- Those limits are set from `SPYGLASS_STORE_EDGE_*` in `.env`, rendered into the
    templates in `deploy/nginx/` at startup, so tuning them needs no nginx
    knowledge #1
- TLS at the edge, as `deploy/docker-compose.tls.yml`: publishes 443 in place of
    the plain port, redirects 80 with a 308, and sends HSTS over TLS only.
    Bearer tokens and presigned URLs are what it keeps off the wire #1
- `deploy/env.example`, listing every variable with its default. The broker now
    reads the whole file, so settings like the volume allowances and the
    account-age floor are reachable without compose enumerating them #1
- Compose hardening: restart policies, a broker health check the edge waits on,
    bounded container logs, and the object store's console bound to loopback #1

### Changed

- Quota totals are aggregated by MySQL rather than folded in Python, so the
    check no longer scales with how many requests an account has made #1
- `app.py` split into the routing (`app.py`), the checks each route runs
    (`guards.py`), the wire shapes (`models.py`), and the boot verification
    (`deployment.py`) #1

### Fixed

- Upload volume was metered against download events: `usage_since` ignored the
    action it was asked for and always totalled reads, so a day of downloading
    exhausted the upload allowance #1
