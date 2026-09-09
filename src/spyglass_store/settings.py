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

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Broker-specific configuration.

    Read from environment variables prefixed ``SPYGLASS_STORE_``, or from a
    ``.env`` file in the working directory. Database connection settings are
    *not* here; see the module docstring.
    """

    model_config = SettingsConfigDict(
        env_prefix="SPYGLASS_STORE_",
        env_file=".env",
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

    #: Lifetime of a presigned URL. Short, because an issued URL cannot be
    #: revoked; see the metering notes in the design docs.
    presigned_ttl_seconds: int = 300

    #: Minimum GitHub account age before an unverified account may read.
    #: Accounts are free and instant, so a whitelist alone does not stop one
    #: person consuming the unverified allowance across many accounts.
    min_account_age_days: int = 30


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance.

    Returns
    -------
    Settings
        Broker configuration for this process.
    """
    return Settings()
