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
object store — so **Docker must be running**. Tests that need them skip cleanly
if it is not, which means a green run on a machine without Docker has silently
skipped everything that touches a database.

`--container-vol-dir` matters more than it looks. MySQL wants a two gigabyte
InnoDB log before it will start, and Docker's default volume root is usually on
`/`, which on a workstation is the disk with no room to spare. Point it at a
disk with space and container data goes there instead; volumes are cleared
whenever a container is removed. You can also set
`SPYGLASS_STORE_DOCKER_VOL_DIR` and forget about it.

Useful flags:

| Flag                      | Why                                                     |
| ------------------------- | ------------------------------------------------------- |
| `--container-vol-dir=DIR` | keep container data off the root disk                   |
| `--keep-container`        | leave containers up between runs; skips ~30s of startup |
| `-k name`                 | the usual pytest selection                              |

Coverage must stay at or above 70%: `coverage run && coverage report`.

## Where things live

```
src/spyglass_store/
├── app.py        # the FastAPI service: all six routes
├── access.py     # the whole permission rule. Start here.
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

`broker/` and `broker/api/` are empty packages left from an earlier plan. The
service is `app.py`.

Two files repay reading before anything else. **`access.py`** holds the entire
permission rule — if you are changing who can see what, the answer is in that
one file by design. **`openapi.yaml`** is the contract, and a test asserts the
running app matches it, so changing a route means changing both.

## Invariants

These are the rules a change can break without any test failing. Each exists for
a reason that is not obvious from the code that depends on it.

### Never `import spyglass`

Reflect its tables with `dj.create_virtual_module` instead — `lab.py` shows how.
Importing `spyglass.common` pulls pynwb, spikeinterface, jax, and the `numpy<2`
/ `scipy<1.13` pins into a web service that needs none of them. Keeping that
stack out is *the reason this is a separate repository*, and an import would
work fine on your laptop while quietly undoing it.

### The broker never touches file bytes

It decides, signs a URL, and steps out. Anything that would make the service
read or proxy object data — however convenient — changes what this is. A
multi-terabyte read must not flow through the broker, and a test asserts the
content endpoint never returns 200.

The consequences follow from that constraint rather than from preference:
presigned URLs are short-lived because they cannot be revoked; volume is charged
when a URL is issued because that is the last moment the broker is involved; and
the uploaded hash is verified by the *store*, via a checksum signed into the
upload URL, because the broker never sees the bytes.

### The broker and the object store must be on different origins

Every HTTP client tested keeps its `Authorization` header across a same-origin
redirect and strips it across origins. An S3 store that receives that header
drops out of presigned-URL mode and refuses the request — complaining about a
missing `x-amz-content-sha256`, which reads nothing like an auth error.

This is a deployment property, so the code can only warn. It does, at startup,
when `SPYGLASS_STORE_PUBLIC_BASE_URL` is set.

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
