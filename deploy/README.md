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
cp deploy/env.example deploy/.env    # then fill it in
docker compose -f deploy/docker-compose.yml up --build
```

**`.env` goes next to the compose file, not at the repository root.** Compose
reads it from the compose file's own directory rather than from wherever you are
standing, so a copy at the root is silently ignored and the required variables
turn up missing. If you keep one there anyway, name it:

```sh
docker compose --env-file .env -f deploy/docker-compose.yml up --build
```

`deploy/env.example` lists every variable with its default, including the ones
the broker reads directly — the whole file is passed through to it, so anything
in `settings.py` is settable without this compose file having to mention it.
The example is named `env.example` rather than `.env.example` because
`.gitignore` ignores `*.env*`, and an example nobody can commit is not one.

`DJ_HOST`, `DJ_USER`, and `DJ_PASS` have to be in there even though your shell
already has a DataJoint configuration: the container cannot read your
`~/.datajoint_config.json`.

Three services: a Ceph RGW object store, the broker, and an nginx edge that
publishes it. The store creates its own bucket, which is why no separate job
does — the broker verifies storage at startup and will otherwise refuse to boot.
The edge waits for the broker to report healthy — nginx resolves its
upstream when it loads its configuration, so an edge that starts first answers
502 until something restarts it.

The broker itself is not published to the host. The edge is the front door, and
it is where the login endpoints are rate limited — see below.

**The edge serves plain HTTP as configured.** That is correct only where TLS is
terminated in front of it; otherwise add the TLS overlay, described below.

The broker still does not create the bucket itself. Provisioning storage is an
operator action; a web service holding the only write credential should not also
be able to make new places to write. Against a real cluster you create the
bucket and hand the broker a scoped key.

Database configuration is DataJoint's own `DJ_HOST`, `DJ_USER`, `DJ_PASS`
rather than broker settings, so an admin who can already reach the ServerHost
instance needs nothing new.

### Surviving a reboot

All three services are `restart: unless-stopped`, so a broker that dies on a
transient fault comes back on its own. There is no one-shot job to exempt: the
store image creates its own bucket.

**A restart policy does nothing if the Docker daemon itself does not start at
boot.** On a host that has never had it enabled, every container stays down
after a reboot and the policy above gives no hint that anything is wrong:

```sh
sudo systemctl enable --now docker
systemctl is-enabled docker      # expect: enabled
```

`unless-stopped` rather than `always` is deliberate: a container you stopped by
hand stays stopped across a daemon restart, so taking the broker down for
maintenance does not fight you. The cost is that "stopped" is remembered — after
deliberately stopping something, bring it back explicitly.

Worth confirming once, on the real host, rather than discovering it after an
unplanned reboot:

```sh
sudo reboot
# then, once it is back
docker compose -f deploy/docker-compose.yml ps
```

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

## Serving HTTPS

A broker token is a bearer credential sent on every request, and a presigned URL
carries its signature in the query string. Over plain HTTP both are readable by
anything on the path, and the presign is replayable until it expires. So one of
these two has to be true:

**Something in front terminates TLS** — an institutional reverse proxy, a load
balancer, a cluster ingress. Then the base compose file is right as it stands,
and the one thing to add is `SPYGLASS_STORE_EDGE_TRUSTED_PROXY`, set to that
hop's address. Without it the rate limits key on the proxy and every caller
shares one bucket.

**Or the edge terminates it**, with the overlay:

```sh
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.tls.yml up --build
```

That publishes 80 and 443 instead of 8000, and needs a certificate you supply:

| Variable | Meaning |
| --- | --- |
| `SPYGLASS_STORE_EDGE_SERVER_NAME` | the hostname the certificate is for |
| `SPYGLASS_STORE_EDGE_TLS_DIR` | directory **on this host**, mounted read-only |
| `SPYGLASS_STORE_EDGE_TLS_CERT` | path **inside the container** to the full chain |
| `SPYGLASS_STORE_EDGE_TLS_KEY` | path inside the container to the private key |

A directory rather than two host paths, because a certificate is usually a
symlink into a renewal directory and mounting the directory keeps that working.
There is deliberately no ACME client: an institutional certificate is the common
case, and a service that renews its own needs outbound reachability and a
writable volume this container otherwise does without.

Port 80 answers 308 to the HTTPS URL — 308 rather than 301 because both login
endpoints are POSTs and the weaker codes let a client turn a POST into a GET.
Responses carry HSTS for a year, over TLS only.

**After a renewal, reload:** `docker compose ... exec edge nginx -s reload`.
nginx reads certificates once, at startup, so a renewed file on disk changes
nothing until it does.

### The object store needs its own TLS

Terminating TLS at the broker is not the whole job. The broker redirects to the
object store and steps out, so the transfer itself — and the signature in that
URL — is only as protected as the store's own endpoint. An `https://` broker
handing out `http://` presigned URLs puts every byte and every signature back in
the clear.

That is the store's configuration, not this one's. It is also why the two must be
different hostnames rather than one: see the constraint above.

## Rate limiting the login endpoints

`/auth/device` and `/auth/token` are the only routes that take no credential,
and they proxy to GitHub on the broker's own client id. Left open, one caller
exhausts the app's GitHub rate limit and nobody can log in — no account needed,
and the broker's own quota never sees it because there is no account to charge.

`deploy/nginx/` holds the limits and `docker-compose.yml` publishes that edge
instead of the broker. **Publishing the broker's port alongside it
defeats the whole arrangement**, so if you replace this proxy with your own,
keep the broker unpublished.

### Tuning the limits

Set them in `.env` with everything else. The nginx image renders the templates
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
| `SPYGLASS_STORE_EDGE_TRUSTED_PROXY` | `127.0.0.1` | whose `X-Forwarded-For` to believe |

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

### What is in `deploy/nginx/`

| File | Holds |
| --- | --- |
| `limits.conf.template` | the rate-limit zones, and the upstream |
| `proxy.inc.template` | the shared server body: headers, the limits applied, the three locations |
| `http.conf.template` | the plain-HTTP front door |
| `tls.conf.template` | the TLS front door, used only by the overlay |

The two front doors include the same body, so the limits exist once. A second
copy would eventually disagree with the first, and the copy that lost would be
the one someone was relying on.

`proxy.inc` renders to a name nginx's `conf.d/*.conf` glob does not match, which
is what keeps it an include rather than a config in its own right.

### If something else sits in front

A CDN, a load balancer, or a cluster ingress makes every request arrive from
one address, so all callers share a single bucket — the limit then throttles
everybody or nobody. Set `SPYGLASS_STORE_EDGE_TRUSTED_PROXY` to that hop's
address and nginx takes the caller from `X-Forwarded-For` instead.

Name it **exactly**. The default, `127.0.0.1`, trusts nothing and is a harmless
no-op for a directly exposed edge. A wide range lets a caller choose their own
bucket by forging the header.

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

The broker also reads `common_nwbfile.Nwbfile` and
`common_nwbfile.AnalysisNwbfile`, to learn which raw file an analysis file was
derived from. Those are **not** trust roots in the same way and must not be
locked down: writing an analysis file is what an ordinary pipeline run does. The
broker accounts for that by reading the relationship once, when a file is
registered, and never re-deriving it — so someone who later re-points a
provenance row cannot change a decision the broker has already recorded. Both
need `SELECT` for the broker's account, and startup fails naming the column if
either is missing one.

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

The broker signs **both** `x-amz-checksum-sha256` and, when the client supplies
`content_md5`, `Content-MD5`. Stores disagree about which they honour:

| Store | `x-amz-checksum-sha256` | `Content-MD5` |
| --- | --- | --- |
| MinIO | enforced | enforced |
| Cloudflare R2 | enforced | enforced |
| **Ceph RGW (Squid 19.2.0)** | **signed and ignored** | enforced |

That middle cell is the one to read twice. RGW covers the header with the
signature — dropping it gives a 403 — and then stores whatever bytes arrive. A
mismatched upload was accepted and kept in testing. So on Ceph, upload integrity
rests on `Content-MD5`, which catches corruption but not a deliberate
substitution, because MD5 collisions are constructible.

**A client that omits `content_md5` therefore gets no integrity check at all on
Ceph.** Sending it is not optional in practice.

If a backend rejects both, set
`SPYGLASS_STORE_S3_ENFORCE_UPLOAD_CHECKSUM=false` — and understand what that
costs: content can then be registered under one hash and uploaded as another,
with nothing downstream able to detect it.

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
