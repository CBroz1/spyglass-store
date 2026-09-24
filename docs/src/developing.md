# Developing

What a new contributor needs that the code cannot tell you on its own.

## Getting a test run

```sh
conda env create -f environment.yml
conda activate spyglass-store
pre-commit install

pytest --container-vol-dir=/path/on/a/roomy/disk
```

The suite starts its own containers — MySQL for the registry, MinIO for the
object store — so **Docker must be running**. MySQL wants a two gigabyte InnoDB
log before it will start, so use `--container-vol-dir` to point to a disk with
ample space, or set `SPYGLASS_STORE_DOCKER_VOL_DIR` and forget about it.

Useful flags:

| Flag                      | Why                                                     |
| ------------------------- | ------------------------------------------------------- |
| `--container-vol-dir=DIR` | keep container data off the root disk                   |
| `--keep-container`        | leave containers up between runs; skips ~30s of startup |

Coverage must stay at or above 70%: `coverage run && coverage report`.

An exited test container is **recreated, not restarted**. Restarting re-runs
MySQL's entrypoint against a half-initialized data directory, which wedges it
permanently — and because the failure happens before the fixture yields,
teardown never runs and every later run inherits the broken container. Do not
undo that.

`.env` is deliberately not read under pytest, so a stray file in the working
directory cannot make the suite machine-dependent. Tests that want configuration
construct `Settings(...)` explicitly.

Container images are pinned to specific releases, and MinIO comes from
`quay.io`. Bump the pins in `tests/container.py` and `deploy/docker-compose.yml`
together.

## Where things live

```
src/spyglass_store/
├── app.py        # the FastAPI service: all six routes, and only the routing
├── access.py     # the whole permission rule. **Start here.**
├── guards.py     # the checks a route runs, and the audit rows they write
├── models.py     # the wire shapes, mirroring openapi.yaml
├── deployment.py # what is verified at boot, and the origin comparison
├── auth.py       # bearer token -> Identity
├── github.py     # device flow; all GitHub wire format is contained here
├── registry.py   # every database read and write
├── schema.py     # the DataJoint tables
├── lab.py        # Spyglass's LabMember/LabTeam, reflected not imported
├── storage.py    # object layout, and the ObjectStore protocol
├── s3.py         # the one ObjectStore implementation
├── db.py         # connection discipline (see "One connection" below)
├── settings.py   # configuration
└── cli/          # the admin CLI
```

The split between the top three is worth knowing before you add code to any of
them. `access.py` decides *who may read what*, as a pure function over data and
with no idea that HTTP exists. `guards.py` feeds it, meters it, logs what it
decided, and turns a refusal into a status code. `app.py` reads the request,
calls the guard that owns the decision, and answers. A new rule belongs in the
first; a new thing to check before answering, in the second.

**`openapi.yaml`** is the contract, and a test asserts the running app matches
it, so changing a route means changing both.

## Invariants

These are the rules a change can break without any test failing. Each exists for
a reason that is not obvious from the code that depends on it.

### Never `import spyglass`

Reflect its tables with `dj.create_virtual_module` instead — `lab.py` shows how.
Importing `spyglass.common` pulls pynwb, spikeinterface, jax, and the `numpy<2`
/ `scipy<1.13` pins into a web service that needs none of them.

### The broker is never in the data path

It decides, signs a URL, and steps out. File contents move between the client
and the object store, never through this service — a multi-terabyte read must
not flow through the broker, and a test asserts the content endpoint never
returns 200.

The consequences follow from that constraint rather than from preference:
presigned URLs are short-lived because they cannot be revoked; volume is charged
when a URL is issued because that is the last moment the broker is involved; and
an upload's hash is verified by the *store*, via a checksum signed into the
upload URL, because the broker does not see what was uploaded.

**One bounded exception**, and it is worth stating precisely rather than letting
the rule read as absolute: proving possession reads `storage.PROOF_LENGTH` bytes
of an existing object. See "Claiming stored content requires holding it" below
for why. The distinction that matters is transfer volume, not whether a byte is
ever read — a 64-byte security check does not put the service in the data path,
and nothing else may.

### The broker and the object store must be on different origins

Every HTTP client tested keeps its `Authorization` header across a same-origin
redirect and strips it across origins. An S3 store that receives that header
drops out of presigned-URL mode and refuses the request — complaining about a
missing `x-amz-content-sha256`, which reads nothing like an auth error.

This is a deployment property, so the code can only warn. It does, at startup,
when `SPYGLASS_STORE_PUBLIC_BASE_URL` is set.

### The login endpoints are limited at the edge, not here

`/auth/device` and `/auth/token` take no credential and spend the broker's own
GitHub client id, so an unthrottled caller denies logins to everyone — and the
volume quota cannot see it, because there is no account to charge.

The limit lives in `deploy/nginx/`, and the compose file publishes that edge
instead of the broker. The numbers come from `SPYGLASS_STORE_EDGE_*` variables
rendered into those templates at startup, so tuning them is an `.env` edit
rather than an nginx one — but they are *edge* settings, and deliberately absent
from `settings.py`: the application must not appear to enforce something it
never sees. Doing it in the application would mean telling callers
apart by address, which behind a proxy means trusting `X-Forwarded-For` without
knowing how many hops to trust; `guards.client_ip` records that header for audit
and decides nothing on it. **If a rate limit ever does move into the app,
trusted-proxy handling has to come first** — otherwise a forged header buys a
fresh bucket per request, and the limit protects nothing while appearing to.

The token endpoint's allowance is deliberately loose: the device flow polls it
every few seconds until the user approves, so a tight limit breaks slow logins
rather than stopping abuse. `deploy/README.md` has the numbers.

### Claiming stored content requires holding it

Registration deduplicates: a hash already in the store needs no upload. That
makes a digest a claim on the bytes behind it, so a caller who once read a file
— or learned its hash any other way — could register it under their own name and
share it onward, and revoking the original visibility would not take it back.

So a caller who cannot already read any registration of that content must answer
a challenge over a named byte range before claiming it. Nothing is asked of
someone who can already read it (they could download and re-upload anyway), nor
when the object is absent (the upload itself proves possession, since the store
verifies the hash).

This is the **only** place the broker reads object data, and the one exception
to the data-path rule above. It is bounded to `storage.PROOF_LENGTH` bytes and
runs once per registration, not per read. If you find yourself widening it —
reading more, or reading on a hot path — that is the rule being eroded rather
than applied, and the alternative designs (re-uploading the whole file, or
dropping cross-owner deduplication) are the ones to weigh instead.

### A Spyglass name identifies content, not a registration

`spyglass_name` is the primary key of a Spyglass file table, so within one
instance it names exactly one file. Several registrations of that name are
therefore not rival answers about *which* file — they are several people's
declarations about the same one, differing in owner and visibility.

So `resolve` returns the declaration the caller is party to, and 404s when they
are party to none. That is deliberately indistinguishable from "no such file":
saying "forbidden" would confirm a file exists to someone with no right to know,
and would stop a client falling through to another backend that can serve it.
The same applies to a hash, which is also non-unique — deduplication is the
designed-for case.

### Spyglass's lab tables are trust roots

`LabMember.LabMemberInfo` decides who is a verified account and may upload.
`LabTeam.LabTeamMember` decides who can read a file shared with a team. Both
must be admin-only writable on any instance a broker serves. Nothing here can
check that — a privilege is a property of the database, not of the rows — so it
is stated in `deploy/README.md` as a deployment requirement.

### DataJoint stays below 2.0

This package is a dependency of `spyglass`, which pins `datajoint<2.0`, and it
reflects `common_lab` from a Spyglass-managed instance. Use the 0.14 spellings:
`dj.schema`, `dj.create_virtual_module`, `dj.config.update`. A test pins the
runtime version so an environment that drifts fails loudly.

### One connection, one caller at a time

DataJoint shares a single connection process-wide with no locking, and FastAPI
runs synchronous handlers on a worker threadpool. Every function in
`registry.py` and `lab.py` is therefore wrapped in `db.serialized`. If you add a
function that queries, wrap it too — the failure mode is interleaved cursors
under concurrency, which the serial test client cannot reproduce.

## Rejected alternatives

Decisions that look like oversights until you know why. Each was considered and
turned down for a reason that is not visible in the code that resulted.

### Reusing DataJoint's file hash instead of SHA-256

A natural question: DataJoint already hashes filepath-store files, and a client
uploading from another instance has one in its `~external_filepath` table. Why
compute a second digest?

Three reasons, any one of which is disqualifying.

**It is MD5.** `datajoint.hash.uuid_from_stream` is `hashlib.md5` packed into a
UUID. Here the hash *is* the object key and the store enforces it on upload, so
a forgeable digest is a forgeable address: an uploader could register one file
and upload a colliding other, and every reader would receive bytes the broker
had certified. MD5 collisions are constructible on a laptop. Content addressing
an adversary can forge is not content addressing.

**It is absent for the files that matter.** Spyglass sets
`filepath_checksum_size_limit` to 1 GB, and DataJoint skips the content hash
above it, storing `None`. Raw NWB sessions are routinely larger, so for exactly
the files this service exists to move there is no hash to reuse — we would fall
back to computing one for the expensive cases only.

**The externals primary key is not a content hash.** It is
`uuid_from_buffer(init_string=relative_filepath)` — DataJoint's own comment
reads "hash relative path, not contents." It is scoped to one store's staging
directory on one instance, so two labs holding identical bytes get different
values and one lab reorganizing directories gets a new value for unchanged data.
It cannot deduplicate or address content across instances, which is the whole
job.

The cost of computing our own is a second *local* pass, not a second upload:
reading 10 GB from disk is seconds against minutes of transfer, and only on
upload — readers never hash anything. If that ever becomes the bottleneck, the
fix is a streaming checksum during upload, not a weaker digest.

DataJoint's hash is still useful *as a client-side pre-filter*: if a file's
`contents_hash` matches what a previous upload recorded, it has not changed and
re-registration can be skipped without reading it. That is an optimization,
never a trust decision — the store still verifies SHA-256 on the bytes it
receives.

## Things that are deliberately imprecise

Worth knowing before you "fix" one.

**Volume limits are a guardrail, not a budget.** They stop a runaway script, not
a determined adversary, and a legitimate user should never approach them.
Charged at URL issue, so an abandoned download still counts; soft under
concurrency; loosened by a log outage. Every one of those errs toward letting a
real user through, which is the correct bias here. Making the meter exact would
put reads behind the availability of a write.

**The audit log is a floor, not a ledger.** A failed log write is swallowed,
because an audit outage must not become a service outage. So a missing row means
under-counting, never "no access occurred."

**A registration can exist before its bytes do.** Uploads are expected to be
slow, so a file registered but not yet uploaded is a normal state, reported as
409 rather than treated as an error to clean up.

## Conventions

- `ruff format` and `ruff check` at line length 80; `pre-commit` runs both.
- NumPy-style docstrings.
- Docstrings carry the *why*. The code says what it does; the prose should say
  what it is defending against, and is often the only place a constraint is
  recorded.
- Tests are named as claims (`test_a_refused_read_is_not_charged`), and their
  docstrings explain what would go wrong if the behaviour regressed.

## Testing shape

Most of the suite needs no database: the permission rule is a pure function, and
the routes take injected dependencies — `create_app` accepts a verifier, store,
GitHub client, registry, and settings, so a unit test supplies fakes rather than
patching modules.

What genuinely needs infrastructure gets it:

- `tests/test_db.py` — real MySQL, for anything that writes
- `tests/test_s3_integration.py` — real MinIO, because only a real store can say
  whether a signature it issued is one it accepts
- `tests/test_end_to_end.py` — both, running the whole path from registration to
  a streamed read

If you are tempted to mock an object store, read `test_s3_integration.py` first.
A fake can return a string shaped like a URL; it cannot tell you the store will
honour it.
