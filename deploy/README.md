# Deployment

The broker talks to any S3-compatible bucket. Which one is a configuration
choice, not a code change: point `SPYGLASS_STORE_S3_ENDPOINT_URL` at the
backend and set the three compatibility knobs below.

That interchangeability is deliberate. The near-term target is a Cloudflare R2
bucket; the intended end state is a self-hosted store running in Docker
alongside the broker. Nothing in the broker should have to change between them.

## Backend profiles

Three settings differ between implementations, and boto3 cannot infer them.

| Setting | Cloudflare R2 | SeaweedFS | Ceph RGW | Garage | AWS S3 |
| --- | --- | --- | --- | --- | --- |
| `S3_REGION` | `auto` | any | any | its configured region | real region |
| `S3_ADDRESSING_STYLE` | `path` | `path` | `path` | `path` | `virtual` |
| `S3_SIGNATURE_VERSION` | `s3v4` | `s3v4` | `s3v4` | `s3v4` | `s3v4` |

`path` addressing is the default because it is what custom endpoints need.
Virtual-hosted style assumes the bucket is a subdomain, which requires wildcard
DNS the self-hosted options generally do not have.

### Cloudflare R2 (near-term)

R2 is S3-compatible with two things worth knowing: the region must be the
literal string `auto`, and the endpoint is account-scoped rather than
region-scoped.

```sh
SPYGLASS_STORE_S3_ENDPOINT_URL=https://<account_id>.r2.cloudflarestorage.com
SPYGLASS_STORE_S3_BUCKET=spyglass-store
SPYGLASS_STORE_S3_REGION=auto
SPYGLASS_STORE_S3_ACCESS_KEY=<r2 access key id>
SPYGLASS_STORE_S3_SECRET_KEY=<r2 secret access key>
```

R2 has no per-object ACLs, which suits this design: the broker is the only
writer, and readers get presigned URLs rather than bucket permissions.

### Self-hosted in Docker (later)

The only change is the endpoint and credentials. Region and addressing style
stay as the defaults.

```sh
SPYGLASS_STORE_S3_ENDPOINT_URL=http://store:8333   # service name on the network
SPYGLASS_STORE_S3_BUCKET=spyglass-store
```

`docker-compose.yml` in this directory is the single-node recipe. Helm later.

## Single node with docker compose

```sh
cp .env.example .env     # at the repository root, then fill it in
docker compose -f deploy/docker-compose.yml up --build
```

Four services: the object store, a one-shot job that creates the bucket, the
broker, and an nginx edge that publishes it. The broker waits for the bucket to
exist, because it verifies storage at startup and will otherwise refuse to
boot.

The broker itself is not published to the host. The edge is the front door, and
it is where the login endpoints are rate limited — see below.

The broker does not create the bucket itself. Provisioning storage is an
operator action; a web service holding the only write credential should not
also be able to make new places to write.

Database configuration is DataJoint's own `DJ_HOST`, `DJ_USER`, `DJ_PASS`
rather than broker settings, so an admin who can already reach the ServerHost
instance needs nothing new.

### The one constraint that is easy to break

**The broker and the object store must be reachable at different origins.**

`GET /file/{id}/content` answers 302 to a presigned URL. Every HTTP client we
tested — `requests`, `httpx`, and the `fsspec`/`aiohttp` stack Spyglass streams
with — keeps its `Authorization` header when a redirect stays within one origin
and strips it when the origin changes. An S3 store that receives that header
drops out of presigned-URL mode into header authentication, then rejects the
request for a missing `x-amz-content-sha256`.

That error names a checksum, not authentication, so the cause is not obvious
from the symptom.

| Layout | Result |
| --- | --- |
| `store.example.org` → broker, `objects.example.org` → store | works |
| `store.example.org/api` → broker, `store.example.org/obj` → store | reads fail |

The second is the natural thing to reach for on a single host, which is why it
is worth stating. Set `SPYGLASS_STORE_PUBLIC_BASE_URL` to the broker's public
URL and it will warn at startup if it detects the collision.

## Rate limiting the login endpoints

`/auth/device` and `/auth/token` are the only routes that take no credential,
and they proxy to GitHub on the broker's own client id. Left open, one caller
exhausts the app's GitHub rate limit and nobody can log in — no account needed,
and the broker's own quota never sees it because there is no account to charge.

`deploy/nginx.conf.template` limits them, and `docker-compose.yml` publishes
that edge instead of the broker. **Publishing the broker's port alongside it
defeats the whole arrangement**, so if you replace this proxy with your own,
keep the broker unpublished.

### Tuning the limits

Set them in `.env` with everything else. The nginx image renders the template
through `envsubst` at startup, so no one has to edit nginx syntax to change a
number, and `docker compose up` works with none of these set.

| Variable | Default | Limits |
| --- | --- | --- |
| `SPYGLASS_STORE_EDGE_DEVICE_RATE` | `6r/m` | `POST /auth/device`, per caller |
| `SPYGLASS_STORE_EDGE_DEVICE_BURST` | `5` | how many may arrive at once |
| `SPYGLASS_STORE_EDGE_POLL_RATE` | `15r/m` | `POST /auth/token`, per caller |
| `SPYGLASS_STORE_EDGE_POLL_BURST` | `20` | how many may arrive at once |
| `SPYGLASS_STORE_EDGE_TOTAL_RATE` | `240r/m` | both routes, all callers together |
| `SPYGLASS_STORE_EDGE_TOTAL_BURST` | `40` | how many may arrive at once |
| `SPYGLASS_STORE_EDGE_RETRY_AFTER` | `60` | seconds sent on a 429 |

`r/m` is nginx's own spelling; `r/s` works too. A rate is the sustained
allowance and a burst is how far a client may run ahead of it — **raise a rate
without its burst and a client that sends a handful of requests together still
gets a 429.** That is the mistake to expect.

These are edge settings, not broker settings. Nothing in `settings.py` reads
them, which is deliberate: the application must not look as though it enforces
something it cannot see.

The token endpoint is looser because GitHub's device flow polls it: a client
asks every `interval` seconds — 5 by default — until the user approves, so an
honest login sustains 12/min for as long as someone takes to find the browser
tab. Tightening that limit breaks slow logins rather than stopping abuse.

The service-wide ceiling exists because per-address limits do nothing against a
spread-out flood, and the thing being protected is shared: one GitHub rate
limit for the deployment. Raise it for a larger site, knowing that what you are
raising is how much of that budget one flood can spend.

Throttling answers 429 with `Retry-After`, matching what `openapi.yaml`
documents for quota, so a client that already backs off correctly needs no
change.

Authenticated routes are deliberately not rate limited here. They are metered
per account by the broker's volume quota, and a request-rate limit on top would
throttle the workload this service exists for — a streamed read re-follows the
content redirect once per range request, which looks exactly like a flood.

### If something else sits in front

A CDN, a load balancer, or a cluster ingress makes every request arrive from
one address, so all callers share a single bucket. Uncomment `set_real_ip_from`
in `nginx.conf.template` and name that hop **exactly**; a wide range there lets
a caller choose their own bucket by forging `X-Forwarded-For`.

That is also why the broker does not do this itself. Behind a proxy it sees
only the proxy, so it would have to trust a caller-supplied header without
knowing how many hops to trust. `X-Forwarded-For` is recorded for audit and
decides nothing (`guards.client_ip`); if that is ever to change, trusted-proxy
handling has to come first.

## Database prerequisite: two tables must be admin-only

The broker does not keep its own copy of who is in the lab or who is on a
team. It reads Spyglass's tables, so that admins curate membership in one
place. The cost of that choice is that those tables become part of the
security boundary:

| Table | Decides |
| --- | --- |
| `common_lab.LabMember.LabMemberInfo` | who is a lab member, and therefore who is verified and may upload |
| `common_lab.LabTeam.LabTeamMember` | who can read a file shared with a team |

**Both must be writable only by an admin on any instance the broker serves.**
A user who can insert their own `github_user_name` promotes themselves to
`verified` and gains upload rights. A user who can add themselves to a team
gains read access to everything shared with it. In both cases the broker is
working exactly as designed and enforcing an answer that was tampered with
before it arrived.

Grant these tables `SELECT` to ordinary users and reserve `INSERT`, `UPDATE`,
and `DELETE` for admins.

The broker cannot verify this for you. A privilege is a property of the
database, not of the rows it reads, so there is nothing for `verify_lab_schema`
to check — it confirms the columns exist, not who may write them. If your
deployment cannot make that guarantee, do not use promotion-on-sight: change
`registry.upsert_account` so that every account starts `unverified` and
requires an explicit admin action to promote.

## Verifying configuration

The broker checks its dependencies at startup rather than on first request:

- `spyglass_store.s3.S3ObjectStore.verify_store` confirms the bucket is
    reachable with the configured credentials, and names the endpoint, region,
    and addressing style if not.
- `spyglass_store.lab.verify_lab_schema` confirms Spyglass still exposes the
    columns the broker reads.

Both run from the application's startup hook, so a misconfigured endpoint or
a renamed upstream column fails the boot rather than a user's upload. A
container that stays up is one whose configuration was good.

If `SPYGLASS_STORE_PUBLIC_BASE_URL` is set, startup also warns when the broker
and the object store share an origin. That one is a warning rather than a
refusal, because it depends on the setting being accurate and refusing to boot
on a heuristic is worse than saying so loudly.

## Migrating between backends

Objects are content-addressed, so keys are derived from file hashes and carry
no backend-specific structure. Moving between buckets is a copy: the registry
keeps pointing at the same keys, and re-uploading an object that already exists
deduplicates rather than duplicating.

## Upload integrity

The broker never sees uploaded bytes, so it cannot itself confirm that what
arrives matches the hash it was registered under. Instead it signs the declared
SHA-256 into the upload URL as a required `x-amz-checksum-sha256`, and the
store verifies on arrival. Because the requirement is part of the signature, a
client that omits the header gets a refusal rather than an unverified upload.

Verified working on MinIO and Cloudflare R2. If a backend rejects the header,
set `SPYGLASS_STORE_S3_ENFORCE_UPLOAD_CHECKSUM=false` — and understand what
that costs: content can then be registered under one hash and uploaded as
another, with nothing downstream able to detect it.

## Quota

Read volume is charged per account when a URL is issued, over a rolling window,
with a per-tier allowance. Exceeding it returns 429 with `Retry-After` set to
when the oldest counted read ages out.

Charging at issue time is a deliberate approximation. The broker leaves the
data path, so it cannot observe whether a transfer happened or how much of it
did. A reader who requests a file and abandons the download is still charged,
and a log write that fails is never retried — so the recorded total is a floor,
not a ledger. Reconcile against object-store metrics if you need the real
number.

The default allowances are placeholders. Set them deliberately before the
broker carries real traffic.

## Administration

Installed with the package as `spyglass-store`. It reaches the database
directly rather than through the HTTP API — an admin is not a broker client
and holds no broker token, and the operator needs these most when the service
is not running.

```sh
spyglass-store account list                     # who exists, and at what tier
spyglass-store account show <github-login>      # teams, volume, file count
spyglass-store account set-tier <login> trusted
spyglass-store account suspend <login>          # --undo to reinstate
spyglass-store account revoke-tokens <login>
spyglass-store file list --owner <login>
spyglass-store file show <file_id>              # grants, and whether bytes exist
spyglass-store audit --login <login> --hours 24
spyglass-store top --hours 24                   # largest consumers
spyglass-store reconcile                        # registry against store
```

**Suspend and revoke are different remedies.** Revoking invalidates the
credentials an account holds; they can log in again immediately and carry on.
Suspending stops the account: every live token fails on its next request, and
a fresh login is refused. Reach for revoke when a token leaked, and suspend
when the person should stop.

`reconcile` reports and never deletes. It names registrations whose bytes are
absent and objects nobody references, then stops — acting on either is a
separate decision, because an outage that made healthy objects unreadable
looks exactly like a corpus of orphans. It exits non-zero when it finds a
discrepancy, so a scheduled run can gate on it.

Remember that a registration with no bytes is often just an upload still
running. Uploads are expected to be slow, so recency matters when reading that
report.
