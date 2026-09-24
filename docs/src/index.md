# spyglass-store

Permission and metering broker for shared NWB file storage.

## What it is

`spyglass-store` lets researchers share NWB files with per-file and per-team
permissions, without anyone managing cloud credentials. It sits between the
Spyglass client and a self-hosted S3-compatible object store.

The broker holds the only credentials that can write to the bucket. It
authenticates a GitHub identity, decides whether that identity may read a file,
and issues a short-lived presigned URL. **It never serves file bytes** — once
the URL is issued, the broker is out of the data path, so a multi-terabyte read
never flows through it.

```
Spyglass client  ──►  BROKER  ──►  object store
  (laptop, HPC)         │          (Ceph RGW, SeaweedFS, Garage)
                        ▼
                 ServerHost MySQL
              (broker schema + LabTeam)
```

## Why a broker, rather than bucket credentials

1. **Keys.** Users must not manage cloud keys. The bar is "run one command,
   paste a code."
2. **Permissions.** S3 bucket policies cannot express "team X may read these
   4,000 files" without exceeding policy size limits.
3. **Throttling.** Uploads and downloads need one chokepoint for metering and
   audit.

## Scope

The broker stores hashes, sizes, owners, and access rules. It does not model
sessions, subjects, or pipelines — that is Spyglass's job. Teams are read from
Spyglass's `LabTeam` rather than duplicated, so admins curate membership in one
place.

It shares the ServerHost MySQL instance with Spyglass but owns a separate
schema. That means one availability domain: a client already needs that instance
to discover which files exist, so the broker is a permission and metering
service rather than an independent identity provider.

The Spyglass-side client is **not** here. It ships inside `spyglass` as
`spyglass.sharing.store`, so researchers run one `pip install`. Only the server
lives in this repository, because its audience is database admins rather than
researchers, and because web-service dependencies have no business in a
scientific conda environment.

## Project structure

```
spyglass-store/
├── deploy/                  # Dockerfile, docker-compose, operator guide
├── docs/                    # documentation
├── openapi.yaml             # the API contract, source of truth
├── src/spyglass_store/
│   ├── app.py               # the FastAPI service: all six routes
│   ├── access.py            # the whole permission rule
│   ├── auth.py              # bearer token -> Identity
│   ├── github.py            # device flow, and all GitHub wire format
│   ├── registry.py          # every database read and write
│   ├── schema.py            # DataJoint tables
│   ├── lab.py               # Spyglass lab tables, reflected not imported
│   ├── storage.py           # object layout, ObjectStore protocol
│   ├── s3.py                # the one ObjectStore implementation
│   ├── db.py                # connection discipline
│   ├── settings.py          # environment configuration
│   └── cli/                 # admin CLI
└── tests/
```

See [Developing](developing.md) for a fuller map, the invariants a change can
break without failing a test, and how to get a test run going.

## API contract

`openapi.yaml` is the contract for both this service and the Spyglass client.
The path is versioned so a broker upgrade never breaks pinned clients, which
matters more than usual because we do not control when users upgrade Spyglass.

## Development

```sh
conda env create -f environment.yml
conda activate spyglass-store
pre-commit install

# The suite starts its own MySQL and Ceph containers, so Docker must be
# running. Point --container-vol-dir at a disk with room: MySQL wants a 2 GB
# log before it starts, and Docker's default volume root is usually on `/`.
pytest --container-vol-dir=/path/on/a/roomy/disk
```

Tests needing a database skip cleanly when Docker is unavailable — so a green
run on a machine without it has skipped most of the suite. See
[Developing](developing.md).

```sh
# serve docs with live reload
mkdocs serve -f docs/mkdocs.yml
```

## Resources

- [conda](https://docs.conda.io/) — environment and package management
- [pre-commit](https://pre-commit.com/) — Git hook framework for code quality
- [pytest](https://docs.pytest.org/) — Python testing framework
- [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) —
  documentation site generator
