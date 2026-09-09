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

Recipes land here: `docker-compose` for a single node, then helm.

## Verifying configuration

The broker checks its dependencies at startup rather than on first request:

- `spyglass_store.s3.S3ObjectStore.verify_store` confirms the bucket is
    reachable with the configured credentials, and names the endpoint, region,
    and addressing style if not.
- `spyglass_store.lab.verify_lab_schema` confirms Spyglass still exposes the
    columns the broker reads.

A misconfigured endpoint or a renamed upstream column fails the boot, not a
user's upload.

## Migrating between backends

Objects are content-addressed, so keys are derived from file hashes and carry
no backend-specific structure. Moving between buckets is a copy: the registry
keeps pointing at the same keys, and re-uploading an object that already exists
deduplicates rather than duplicating.
