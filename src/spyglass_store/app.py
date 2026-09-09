"""The broker service: HTTP in front of the permission decision.

Implements the read half of the contract in `openapi.yaml` — resolving a name
or hash to a file, and redirecting to a freshly signed object URL. Registration
and visibility (ST-1.4, ST-2.3) are not here yet.

The broker never serves bytes. It decides, signs, and redirects, which is why
`presigned_ttl_seconds` is short: once a URL is issued the broker is out of the
data path and cannot revoke it.

**The redirect target must be a different origin than the broker.** Clients
forward `Authorization` across a same-origin redirect, and an S3 store that
receives one switches out of presigned-URL mode and rejects the request. See
`.claude/ST16_REDIRECT_RESULT.md` for the measurements.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from spyglass_store import registry
from spyglass_store.access import Reader, can_read, is_public
from spyglass_store.auth import GitHubVerifier, Identity, require_identity
from spyglass_store.s3 import S3ObjectStore
from spyglass_store.settings import Settings, get_settings
from spyglass_store.storage import object_key

API_PREFIX = "/api/v1"


class FileOut(BaseModel):
    """A file, as the contract's `File` schema describes it."""

    file_id: str
    sha256: str = Field(pattern="^[0-9a-f]{64}$")
    size_bytes: int
    spyglass_name: str
    file_class: str


def current_reader(
    identity: Annotated[Identity, Depends(require_identity)],
) -> Identity:
    """Resolve a verified token into a broker account and its teams.

    Split from `require_identity` so the GitHub round trip and the database
    lookup stay separately testable.

    Parameters
    ----------
    identity : Identity
        Result of verifying the bearer token.

    Returns
    -------
    Identity
        Enriched with `account_id`, `tier`, and `teams`.
    """
    return registry.resolve_account(identity)


def _authorize(file: registry.FileRecord, identity: Identity) -> None:
    """Raise 403 unless `identity` may read `file`.

    Parameters
    ----------
    file : FileRecord
        The file being requested.
    identity : Identity
        The caller.

    Raises
    ------
    fastapi.HTTPException
        403 when the caller may not read the file.
    """
    rules = registry.rules_for_file(file.file_id)

    # An unverified account reaches public data only, whatever the grants say.
    permitted = can_read(
        rules, Reader(identity.account_id, identity.teams), file.owner
    ) and (identity.may_read_private or is_public(rules))

    if not permitted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This identity may not read this file.",
        )


def create_app(
    *,
    verifier=None,
    store=None,
    settings: Settings | None = None,
) -> FastAPI:
    """Build the broker application.

    Parameters
    ----------
    verifier : optional
        Token verifier. Defaults to `GitHubVerifier`. Injected by tests.
    store : optional
        Object store adapter. Defaults to `S3ObjectStore`. Injected by tests,
        which must not need a live bucket to check a permission decision.
    settings : Settings, optional
        Configuration. Defaults to the process settings.

    Returns
    -------
    fastapi.FastAPI
        The application, with dependencies on `app.state`.
    """
    settings = settings or get_settings()
    app = FastAPI(title="spyglass-store broker", version="1.0.0")

    app.state.settings = settings
    app.state.verifier = verifier or GitHubVerifier()
    app.state.store = store or S3ObjectStore(settings)

    @app.get(f"{API_PREFIX}/file/resolve", response_model=FileOut)
    def resolve_file(
        identity: Annotated[Identity, Depends(current_reader)],
        name: Annotated[str | None, Query()] = None,
        sha256: Annotated[str | None, Query()] = None,
    ) -> FileOut:
        """Resolve a Spyglass name or content hash to a file."""
        if not name and not sha256:
            raise HTTPException(
                status_code=422,  # spelled out; starlette renamed the constant
                detail="One of name or sha256 is required.",
            )

        file = (
            registry.file_by_sha256(sha256)
            if sha256
            else registry.file_by_name(name)
        )

        if file is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No such file."
            )

        _authorize(file, identity)

        return FileOut(**{k: getattr(file, k) for k in FileOut.model_fields})

    @app.get(f"{API_PREFIX}/file/{{file_id}}/content")
    def get_file_content(
        file_id: str,
        identity: Annotated[Identity, Depends(current_reader)],
    ) -> RedirectResponse:
        """Redirect to a freshly signed URL for the file's bytes."""
        file = registry.file_by_id(file_id)

        if file is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No such file."
            )

        _authorize(file, identity)

        url = app.state.store.presigned_get(
            object_key(file.sha256), app.state.settings.presigned_ttl_seconds
        )

        # The point of the stable URL is that each request re-signs. A cached
        # redirect would hand back a signature that outlives its TTL, so the
        # client would fail mid-session with an expiry it cannot see.
        return RedirectResponse(
            url,
            status_code=status.HTTP_302_FOUND,
            headers={"Cache-Control": "no-store"},
        )

    return app
