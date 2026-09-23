"""Broker configuration.

Configuration is deliberately split in two, by what each value *is*:

**Database connection: DataJoint's.** The broker does not read, validate, or
re-declare `database.host` and friends. `dj.schema` connects through
`dj.config`, which DataJoint loads from `dj_local_conf.json`,
`~/.datajoint_config.json`, or `DJ_HOST` / `DJ_USER` / `DJ_PASS`. That is the
same mechanism Spyglass builds on, so an admin who can already reach the
instance needs no new configuration to point the broker at it.

**Broker secrets and tunables: this module.** A GitHub client id and object
store credentials have no DataJoint or Spyglass equivalent, and secrets do not
belong in a JSON config file that gets copied between machines. They are read
from the environment instead.

Note this module does *not* import `spyglass`. Doing so would drag a scientific
stack (spikeinterface, pynwb, jax, opencv) and its pins (`numpy<2`,
`scipy<1.13`) into a web service that needs none of it. Keeping that stack out
of the broker's environment is the reason this is a separate repository.
"""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Broker-specific configuration.

    Read from environment variables prefixed ``SPYGLASS_STORE_``, or from a
    ``.env`` file in the working directory. Database connection settings are
    *not* here; see the module docstring.
    """

    # `.env` is deliberately not read under pytest. Otherwise any code path
    # reaching `get_settings()` picks up whatever `.env` happens to sit in the
    # working directory, and the suite's behaviour becomes machine-dependent.
    # Tests that want configuration construct `Settings(...)` explicitly.
    model_config = SettingsConfigDict(
        env_prefix="SPYGLASS_STORE_",
        env_file=None if "PYTEST_CURRENT_TEST" in os.environ else ".env",
        extra="ignore",
    )

    # Identity. Registered at https://github.com/settings/developers with
    # device flow enabled and no scopes requested.
    github_client_id: str = Field(
        default="",
        description="OAuth app client id. Device flow must be enabled on it.",
    )

    #: MySQL schema for the broker's tables, kept separate from any Spyglass
    #: schema so operational traffic never touches provenance tables.
    schema_prefix: str = "store"

    # Object store. These credentials never leave the broker.
    #
    # Any S3-compatible bucket works. The three knobs below exist because
    # implementations disagree, and boto3 cannot guess: Cloudflare R2 wants
    # region "auto", Garage wants its configured region, AWS wants a real one.
    # See deploy/README.md for a profile per backend.
    s3_endpoint_url: str = ""
    s3_bucket: str = "spyglass-store"
    s3_access_key: str = ""
    s3_secret_key: str = ""

    #: R2 requires "auto". AWS requires a real region. Self-hosted stores are
    #: mostly indifferent but must be given something.
    s3_region: str = "auto"

    #: Custom endpoints generally need path style; virtual-hosted assumes the
    #: bucket is a subdomain, which only works with wildcard DNS.
    s3_addressing_style: str = "path"

    #: R2, Ceph RGW, and Garage all require SigV4.
    s3_signature_version: str = "s3v4"

    #: The broker's own externally reachable base URL, e.g.
    #: "https://store.example.org". Used only to check at startup that it does
    #: not share an origin with the object store: clients keep `Authorization`
    #: across a same-origin redirect, and an S3 store that receives one refuses
    #: the request. Leave empty to skip the check.
    public_base_url: str = ""

    #: Ask the object store to verify uploaded bytes against the registered
    #: hash, by signing an `x-amz-checksum-sha256` requirement into the upload
    #: URL. The broker never sees the bytes, so this is the only place that
    #: check can happen. Turn it off only for a backend that rejects the
    #: header outright — and accept that content can then be registered under
    #: one hash and uploaded as another.
    s3_enforce_upload_checksum: bool = True

    #: Require a caller claiming already-stored content to prove they hold
    #: the bytes, when they cannot already read any registration of it.
    #:
    #: Without this, knowing a hash is enough to claim the content behind it:
    #: registration deduplicates, so a caller who once had a file — or who
    #: learned its digest any other way — can register it under their own name
    #: and share it onward. Revocation would not take it back.
    #:
    #: Turning it off restores that hole. Only sensible where every account is
    #: already trusted with every file.
    require_possession_proof: bool = True

    #: Lifetime of a presigned URL. Short, because an issued URL cannot be
    #: revoked; see the metering notes in the design docs.
    presigned_ttl_seconds: int = 300

    #: Lifetime of a broker token, in days. Zero means it never expires.
    #: A token is a bearer credential, so a lifetime bounds what one leak
    #: costs; logging in again is a single command.
    token_ttl_days: int = 90

    #: Rolling window the volume limits are measured over.
    quota_window_hours: int = 24

    #: Volume limits per account, in terabytes over the window. None means
    #: unlimited.
    #:
    #: These are a guardrail, not a budget. They exist to stop a runaway
    #: script or a careless bulk pull, not to account for usage — a legitimate
    #: user is not expected to approach them. That is deliberate, and it is
    #: what makes the imprecision below acceptable:
    #:
    #: - Volume is charged when a URL is issued, so an abandoned download
    #:   still counts. The broker leaves the data path and cannot see the
    #:   transfer.
    #: - Two simultaneous requests can both pass the check, so the ceiling is
    #:   soft by up to one file per concurrent request.
    #: - Usage is derived from the audit log, whose writes are swallowed on
    #:   failure. A log outage loosens the limit rather than denying service.
    #:
    #: Every one of those errs toward letting a real user through. Tightening
    #: them means making the meter fail closed, which would put reads behind
    #: the availability of a write — a worse trade for a guardrail.
    download_tb_per_day: float | None = 20
    upload_tb_per_day: float | None = 5

    #: Minimum GitHub account age    #: Minimum GitHub account age before an unverified account may read.
    #: Accounts are free and instant, so a whitelist alone does not stop one
    #: person consuming the unverified allowance across many accounts.
    min_account_age_days: int = 30

    def volume_limit(self, action: str) -> int | None:
        """Return the volume allowance for an action, in bytes.

        Parameters
        ----------
        action : str
            Either "read" or "register".

        Returns
        -------
        int or None
            Allowance in bytes, or None for unlimited.
        """
        allowance = (
            self.upload_tb_per_day
            if action == "register"
            else self.download_tb_per_day
        )

        return None if allowance is None else int(allowance * 1024**4)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance.

    Returns
    -------
    Settings
        Broker configuration for this process.
    """
    return Settings()
