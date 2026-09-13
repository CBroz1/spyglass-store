"""The broker service: HTTP in front of the permission decision.

Implements the four `/file` operations of the contract in `openapi.yaml`:
resolve, register, content redirect, and visibility, plus the two `/auth`
endpoints that run GitHub's device flow.

Login is the only place a GitHub token exists. It is exchanged for one, used
once to learn who the user is, and dropped; what the client keeps is a broker
token that can read nothing on GitHub. Every other route verifies that token
against a local hash, so GitHub is not in the path of a read.

Every decision is recorded through `registry.log_access`, including refusals.
The broker leaves the data path once it signs a URL, so the log is what quota
and audit have to work from — and it is a floor, not a ledger: a failed log
write is swallowed rather than failing the request.

The broker never serves bytes. It decides, signs, and redirects, which is why
`presigned_ttl_seconds` is short: once a URL is issued the broker is out of the
data path and cannot revoke it.

**The redirect target must be a different origin than the broker.** Every
client tested strips `Authorization` when a redirect crosses origins and
forwards it when it does not, and an S3 store that receives one switches out
of presigned-URL mode and rejects the request with a complaint about
`x-amz-content-sha256` rather than anything mentioning signatures. Serving the
broker and the object store under one hostname therefore breaks reads, which
is a natural thing for a reverse proxy to do by accident.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from spyglass_store import registry
from spyglass_store.access import (
    Scope,
    may_read,
    may_upload,
    rules_for,
)
from spyglass_store.auth import Identity, TokenVerifier, require_identity
from spyglass_store.github import (
    AuthorizationPending,
    DeviceFlowError,
    GitHub,
)
from spyglass_store.lab import lab_member_for_github, verify_lab_schema
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


def same_origin(first: str, second: str) -> bool:
    """Return True if two URLs share a scheme, host, and port.

    Origin is what decides whether a client forwards `Authorization` across a
    redirect, so it is the comparison that matters — not whether the two look
    alike as strings.

    Examples
    --------
    >>> same_origin("https://a.org/api", "https://a.org/objects")
    True
    >>> same_origin("https://a.org", "https://objects.a.org")
    False
    """
    if not first or not second:
        return False

    one, two = urlsplit(first), urlsplit(second)

    return (one.scheme, one.hostname, one.port) == (
        two.scheme,
        two.hostname,
        two.port,
    )


def verify_deployment(settings: Settings, store) -> None:
    """Check at boot what would otherwise fail under the first user.

    A wrong bucket, a renamed Spyglass column, or a proxy that puts the broker
    and the object store on one hostname all produce confusing failures much
    later and to someone else. Checking here turns each into a startup error
    naming its own cause.

    Parameters
    ----------
    settings : Settings
        Broker configuration.
    store : ObjectStore
        Adapter to probe.

    Raises
    ------
    RuntimeError
        If the lab schema or the bucket cannot be reached.
    """
    verify_lab_schema()
    store.verify_store()

    # A warning, not an error: it depends on `public_base_url` being set
    # correctly, and refusing to boot on a heuristic is worse than saying so.
    if same_origin(settings.public_base_url, settings.s3_endpoint_url):
        logging.getLogger(__name__).warning(
            "The broker and the object store share an origin (%s). Clients "
            "keep Authorization across a same-origin redirect, and the store "
            "will reject those requests with a complaint about "
            "x-amz-content-sha256 rather than anything mentioning auth. Serve "
            "them from different hostnames.",
            settings.public_base_url,
        )


def client_ip(request: Request) -> str:
    """Best-effort caller address.

    Behind a reverse proxy every request appears to come from the proxy, so
    the first `X-Forwarded-For` hop is preferred when present. That header is
    caller-supplied and trivially forged — it is recorded for audit, never
    used for a decision.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host if request.client else ""


def _pick_readable(
    request: Request,
    candidates: list[registry.FileRecord],
    identity: Identity,
) -> registry.FileRecord | None:
    """Choose the registration that applies to this caller.

    A Spyglass name is the primary key of a file table, so within an instance
    it names exactly one file. Several registrations of that name are several
    people's declarations about the same content, differing in owner and
    visibility — so this is not a tie-break between rival answers, it is
    picking the declaration the caller is party to.

    Own registration first, then any readable one, in the order given (newest
    first). None when the caller is party to none of them.
    """
    readable = []

    for file in candidates:
        rules = request.app.state.registry.rules_for_file(file.file_id)
        if not may_read(rules, identity.as_reader(), file.owner):
            continue
        if file.owner == identity.account_id and identity.account_id:
            return file
        readable.append(file)

    return readable[0] if readable else None


def _authorize(
    request: Request,
    file: registry.FileRecord,
    identity: Identity,
    action: str,
) -> None:
    """Raise 403 unless `identity` may read `file`, recording either outcome.

    The decision is logged here rather than at each call site so a denial can
    never be the path that forgets to write one — a refusal is the event an
    audit is most likely to be looking for.

    Parameters
    ----------
    request : fastapi.Request
        Incoming request, for the caller address.
    file : FileRecord
        The file being requested.
    identity : Identity
        The caller.
    action : str
        Log action: resolve or read.

    Raises
    ------
    fastapi.HTTPException
        403 when the caller may not read the file.
    """
    reg = request.app.state.registry
    rules = reg.rules_for_file(file.file_id)
    permitted = may_read(rules, identity.as_reader(), file.owner)

    reg.log_access(
        identity=identity,
        action=action,
        granted=permitted,
        file_id=file.file_id,
        # Charged only when a URL is actually issued; a refusal transfers
        # nothing, and counting it would inflate quota against the wrong user.
        size_bytes=file.size_bytes if permitted and action == "read" else 0,
        source_ip=client_ip(request),
    )

    if not permitted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This identity may not read this file.",
        )


def _charged_size(store, file: registry.FileRecord) -> int:
    """Return the size to bill for a file, preferring the store's answer.

    The size on the registration is whatever the client declared, and nothing
    verifies it — the checksum binds content, not length. Metering that number
    would let an uploader register one byte for a ten gigabyte object and make
    it free to read forever.

    Falls back to the declared size if the store cannot say, so a storage
    hiccup does not hand out free reads either.
    """
    try:
        actual = store.size(object_key(file.sha256))
    except Exception:  # noqa: BLE001 - a probe failure must not deny a read
        actual = None

    return actual if actual is not None else file.size_bytes


def _enforce_quota(
    request: Request,
    identity: Identity,
    file: registry.FileRecord,
    settings: Settings,
    store,
    action: str = "read",
) -> None:
    """Raise 429 if this read would exceed the tier's allowance.

    Charged when the URL is issued, because that is the last moment the broker
    is involved. It cannot see whether the transfer happened, so the count is
    what a reader was *permitted* to move, not what they did.

    Parameters
    ----------
    request : fastapi.Request
        Incoming request, for the caller address.
    identity : Identity
        The caller.
    file : FileRecord
        The file about to be handed out.
    settings : Settings
        Broker configuration.
    store : ObjectStore
        Consulted for the object's true size.
    action : str, optional
        "read" to charge the download allowance, "register" the upload one.

    Raises
    ------
    fastapi.HTTPException
        429, with `Retry-After` set to when capacity actually frees up.
    """
    limit = settings.volume_limit(action)

    if limit is None or not identity.account_id:
        return

    reg = request.app.state.registry
    usage = reg.usage_since(
        identity.account_id, settings.quota_window_hours, action
    )

    # A file already charged in this window costs nothing more, so a streamed
    # read that re-follows the redirect hundreds of times is billed once — and
    # the size lookup below happens once per file per window rather than once
    # per range request.
    if file.file_id in usage.files:
        return

    charge = _charged_size(store, file)

    if usage.total_bytes + charge <= limit:
        return

    window = timedelta(hours=settings.quota_window_hours)

    # When the oldest counted read ages out, capacity returns. Saying so beats
    # a fixed interval that has every client retry at the same moment.
    retry = window.total_seconds()
    if usage.earliest is not None:
        retry = max(
            1, (usage.earliest + window - datetime.now()).total_seconds()
        )

    reg.log_access(
        identity=identity,
        action=action,
        granted=False,
        source_ip=client_ip(request),
    )

    moved = "Upload" if action == "register" else "Download"

    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=(
            f"{moved} allowance exhausted: "
            f"{usage.total_bytes / 1024**4:.2f} of "
            f"{limit / 1024**4:.2f} TB in the last "
            f"{settings.quota_window_hours} hours."
        ),
        headers={"Retry-After": str(int(retry))},
    )


def create_app(
    *,
    verifier=None,
    store=None,
    github=None,
    registry_module=None,
    settings: Settings | None = None,
) -> FastAPI:
    """Build the broker application.

    Parameters
    ----------
    verifier : optional
        Token verifier. Defaults to `TokenVerifier`. Injected by tests.
    github : optional
        GitHub device-flow client. Defaults to one built from settings.
    registry_module : optional
        Database access layer. Defaults to `spyglass_store.registry`. The one
        dependency that used to be reached as a module global, which meant a
        test had to patch it function by function rather than supply it once.
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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        verify_deployment(app.state.settings, app.state.store)
        yield

    app = FastAPI(
        title="spyglass-store broker", version="1.0.0", lifespan=lifespan
    )

    app.state.settings = settings
    app.state.registry = registry_module or registry
    app.state.verifier = verifier or TokenVerifier()
    app.state.store = store or S3ObjectStore(settings)
    app.state.github = github or GitHub(settings.github_client_id)

    @app.get("/healthz")
    def healthz() -> dict:
        """Liveness. Unauthenticated and deliberately cheap.

        Says the process is up and serving, nothing more. Dependencies are
        checked once at startup, so a broker that is answering here has
        already proved it can reach its bucket and the lab schema — making
        this a poor place to re-probe them on every poll.
        """
        return {"status": "ok"}

    @app.post(f"{API_PREFIX}/auth/device", response_model=DeviceCodeOut)
    def begin_device_flow() -> DeviceCodeOut:
        """Start a login. Returns a code the user types at GitHub."""
        try:
            code = app.state.github.begin()
        except DeviceFlowError as err:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(err),
            ) from err

        return DeviceCodeOut(**vars(code))

    @app.post(f"{API_PREFIX}/auth/token", response_model=TokenOut)
    def exchange_device_code(request: Request, body: TokenRequest) -> TokenOut:
        """Exchange an approved device code for a broker token."""
        try:
            github_token = app.state.github.poll(body.device_code)
        except AuthorizationPending as pending:
            # 428, not an error: the user simply has not finished yet. The
            # interval is echoed because GitHub asks for a slower poll rather
            # than refusing outright.
            raise HTTPException(
                status_code=status.HTTP_428_PRECONDITION_REQUIRED,
                detail="Authorization pending.",
                headers={"Retry-After": str(pending.interval)},
            ) from pending
        except DeviceFlowError as err:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=str(err)
            ) from err

        user = app.state.github.user(github_token)
        # The GitHub token has done its whole job. Nothing below stores it.

        age = user.age_days()
        if age < settings.min_account_age_days:
            app.state.registry.log_access(
                identity=Identity(github_id=user.github_id),
                action="login",
                granted=False,
                source_ip=client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This GitHub account is {age} days old; "
                    f"{settings.min_account_age_days} are required."
                ),
            )

        account_id, tier = app.state.registry.upsert_account(
            user, lab_member_for_github(user.github_login)
        )

        existing = app.state.registry.account_by_login(user.github_login)
        if existing is not None and existing.suspended:
            app.state.registry.log_access(
                identity=Identity(github_id=user.github_id),
                action="login",
                granted=False,
                source_ip=client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account is suspended.",
            )
        token = app.state.registry.issue_token(account_id)

        app.state.registry.log_access(
            identity=Identity(
                github_id=user.github_id,
                github_login=user.github_login,
                account_id=account_id,
                tier=tier,
            ),
            action="login",
            granted=True,
            source_ip=client_ip(request),
        )

        return TokenOut(
            access_token=token, tier=tier, github_login=user.github_login
        )

    @app.get(f"{API_PREFIX}/file/resolve", response_model=FileOut)
    def resolve_file(
        request: Request,
        identity: Annotated[Identity, Depends(require_identity)],
        name: Annotated[str | None, Query()] = None,
        sha256: Annotated[str | None, Query()] = None,
    ) -> FileOut:
        """Resolve a Spyglass name or content hash to a file."""
        if not name and not sha256:
            raise HTTPException(
                status_code=422,  # spelled out; starlette renamed the constant
                detail="One of name or sha256 is required.",
            )

        candidates = (
            [app.state.registry.file_by_sha256(sha256)]
            if sha256
            else list(app.state.registry.files_by_name(name))
        )
        candidates = [c for c in candidates if c is not None]

        file = _pick_readable(request, candidates, identity)

        if file is None:
            # Also the answer when a registration exists but this caller may
            # not read it. Saying "forbidden" would confirm the file exists to
            # someone with no right to know, and would stop a client falling
            # through to another backend that can serve it.
            app.state.registry.log_access(
                identity=identity,
                action="resolve",
                granted=False,
                file_id=candidates[0].file_id if candidates else None,
                source_ip=client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No such file."
            )

        _authorize(request, file, identity, "resolve")

        return FileOut(
            uploaded=app.state.store.exists(object_key(file.sha256)),
            **{
                k: getattr(file, k)
                for k in FileOut.model_fields
                if k != "uploaded"
            },
        )

    @app.post(
        f"{API_PREFIX}/file",
        response_model=UploadTarget,
        status_code=status.HTTP_201_CREATED,
    )
    def register_file(
        request: Request,
        body: FileRegistrationIn,
        identity: Annotated[Identity, Depends(require_identity)],
    ) -> UploadTarget:
        """Register an upload and return where to write the bytes."""
        if not may_upload(identity.as_reader()):
            app.state.registry.log_access(
                identity=identity,
                action="register",
                granted=False,
                source_ip=client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This identity may not upload.",
            )

        try:
            rules = rules_for(
                Scope(body.visibility.scope), body.visibility.teams
            )
        except ValueError as err:  # group with no teams names nobody
            raise HTTPException(status_code=422, detail=str(err)) from err

        _enforce_quota(
            request,
            identity,
            registry.FileRecord(
                "",
                body.sha256,
                body.size_bytes,
                body.spyglass_name,
                body.file_class,
                identity.account_id,
            ),
            settings,
            app.state.store,
            action="register",
        )

        key = object_key(body.sha256)

        # Retrying a dropped response must not register the file twice, so an
        # identical prior registration by this owner is returned as-is.
        existing = app.state.registry.registration_for(
            body.sha256, body.spyglass_name, identity.account_id
        )

        file = existing or app.state.registry.register_file(
            sha256=body.sha256,
            size_bytes=body.size_bytes,
            spyglass_name=body.spyglass_name,
            file_class=body.file_class,
            owner=identity.account_id,
            rules=rules,
        )

        # Content addressing means the object may already be present from
        # someone else's upload. That is the deduplication: the registration is
        # per owner, the object is shared.
        stored = app.state.store.exists(key)

        app.state.registry.log_access(
            identity=identity,
            action="register",
            granted=True,
            file_id=file.file_id,
            size_bytes=body.size_bytes,
            source_ip=client_ip(request),
        )

        if stored:
            return UploadTarget(file_id=file.file_id, deduplicated=True)

        # The hash is signed into the upload URL, so the store rejects bytes
        # that do not match what was registered. The broker cannot check this
        # itself without standing in the data path it exists to stay out of.
        upload = app.state.store.presigned_put(
            key,
            settings.presigned_ttl_seconds,
            sha256=body.sha256,
        )

        return UploadTarget(
            file_id=file.file_id,
            deduplicated=False,
            upload_url=upload.url,
            upload_headers=upload.headers,
        )

    @app.get(
        f"{API_PREFIX}/file/{{file_id}}/content",
        status_code=status.HTTP_302_FOUND,
        response_class=RedirectResponse,
    )
    def get_file_content(
        request: Request,
        file_id: str,
        identity: Annotated[Identity, Depends(require_identity)],
    ) -> RedirectResponse:
        """Redirect to a freshly signed URL for the file's bytes."""
        file = app.state.registry.file_by_id(file_id)

        if file is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No such file."
            )

        if not app.state.store.exists(object_key(file.sha256)):
            # Registered, but the bytes have not arrived. Distinct from "no
            # such file": the declaration is real and the upload may still be
            # running. Uploads are expected to be slow, so this is a normal
            # transient state rather than something to clean up.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Registered, but the upload has not completed.",
            )

        # Before `_authorize`, which is what charges the read. Checking after
        # would count this file against itself, and would charge an account
        # for a request the next line then refuses.
        _enforce_quota(request, identity, file, settings, app.state.store)
        _authorize(request, file, identity, "read")

        url = app.state.store.presigned_get(
            object_key(file.sha256), settings.presigned_ttl_seconds
        )

        # The point of the stable URL is that each request re-signs. A cached
        # redirect would hand back a signature that outlives its TTL, so the
        # client would fail mid-session with an expiry it cannot see.
        return RedirectResponse(
            url,
            status_code=status.HTTP_302_FOUND,
            headers={"Cache-Control": "no-store"},
        )

    @app.patch(
        f"{API_PREFIX}/file/{{file_id}}/visibility",
        response_model=VisibilityOut,
    )
    def set_visibility(
        request: Request,
        file_id: str,
        body: VisibilityIn,
        identity: Annotated[Identity, Depends(require_identity)],
    ) -> VisibilityOut:
        """Change who may read a file. Owner only."""
        file = app.state.registry.file_by_id(file_id)

        if file is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No such file."
            )

        # Ownership, not readability. A team member may read a file without
        # being allowed to widen who else can.
        if not identity.account_id or identity.account_id != file.owner:
            app.state.registry.log_access(
                identity=identity,
                action="visibility",
                granted=False,
                file_id=file_id,
                source_ip=client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the owner may change visibility.",
            )

        try:
            rules = rules_for(Scope(body.scope), body.teams)
        except ValueError as err:  # group with no teams names nobody
            raise HTTPException(status_code=422, detail=str(err)) from err

        app.state.registry.replace_rules(file_id, rules)

        app.state.registry.log_access(
            identity=identity,
            action="visibility",
            granted=True,
            file_id=file_id,
            source_ip=client_ip(request),
        )

        return VisibilityOut(
            file_id=file_id, scope=body.scope, teams=body.teams
        )

    return app
