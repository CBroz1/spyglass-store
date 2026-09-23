"""The wire shapes, mirroring the schemas in `openapi.yaml`.

Nothing here decides anything. These types are the boundary: what a client is
allowed to send, and what it is promised back. They live apart from the routes
because `openapi.yaml` is the contract and a test asserts the running app
matches it, so a change here is a change to a published interface — easier to
see when it is not buried among handlers.

Validation that belongs to the contract belongs here too. A hash that is not
64 hex characters, or a scope that is not one of the three, is refused as a
422 before any handler runs, so no route has to restate it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class FileOut(BaseModel):
    """A file, as the contract's `File` schema describes it."""

    file_id: str
    sha256: str = Field(pattern="^[0-9a-f]{64}$")
    size_bytes: int
    spyglass_name: str
    file_class: str
    uploaded: bool = True


class VisibilityIn(BaseModel):
    """Declared visibility, matching the contract's `Visibility` schema."""

    scope: Literal["private", "group", "public"]
    teams: list[str] = Field(default_factory=list)


class FileRegistrationIn(BaseModel):
    """A request to register an upload."""

    sha256: str = Field(pattern="^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    spyglass_name: str
    file_class: Literal["raw", "analysis"]
    visibility: VisibilityIn = Field(
        default_factory=lambda: VisibilityIn(scope="private")
    )
    possession_proof: str | None = Field(
        default=None,
        description=(
            "Digest answering the challenge from a prior 428. Required only "
            "when claiming content already stored that this identity cannot "
            "already read."
        ),
    )


class DeviceCodeOut(BaseModel):
    """What the user needs in order to approve a login."""

    device_code: str
    user_code: str
    verification_uri: str
    interval: int
    expires_in: int


class TokenRequest(BaseModel):
    """A poll for the result of an approved device code."""

    device_code: str


class TokenOut(BaseModel):
    """A broker token, and what it can do."""

    access_token: str
    tier: str
    github_login: str = ""


class VisibilityOut(BaseModel):
    """The visibility now in force, echoed back so a client can confirm it."""

    file_id: str
    scope: str
    teams: list[str]


class PossessionRequired(BaseModel):
    """What a caller must answer to claim content already in the store."""

    detail: str
    sha256: str
    offset: int
    length: int


class UploadTarget(BaseModel):
    """Where to put the bytes, if they are not already there.

    `upload_headers` must be sent verbatim with the PUT. They carry the
    checksum the store verifies the bytes against, and they are covered by the
    signature, so dropping them fails the upload rather than skipping the
    check.
    """

    file_id: str
    deduplicated: bool
    upload_url: str | None = None
    upload_headers: dict[str, str] = Field(default_factory=dict)
