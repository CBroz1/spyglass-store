"""The broker service: HTTP in front of the permission decision.

Implements the four `/file` operations of the contract in `openapi.yaml`:
resolve, register, content redirect, and visibility, plus the two `/auth`
endpoints that run GitHub's device flow.

What is left here is the routing: read the request, call the check that owns
the decision, answer. The parts that are not routing live next door —
`models.py` holds the wire shapes, `guards.py` the checks each route runs and
the audit rows they write, `deployment.py` what is verified at boot.

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

Three things this module deliberately does not do, because the edge in front
of it does them — rate limit the unauthenticated `/auth` endpoints, terminate
TLS, and keep the object store on a different hostname. `client_ip` is
audit-only for the first of those: behind a proxy, telling callers apart by
address means trusting `X-Forwarded-For` without a trusted-hop count. See
`deploy/README.md`.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from spyglass_store import registry
from spyglass_store.access import Scope, may_upload, rules_for
from spyglass_store.auth import Identity, TokenVerifier, require_identity
from spyglass_store.deployment import (
    same_origin,  # noqa: F401 - re-exported for callers that import it here
    verify_deployment,
)
from spyglass_store.github import (
    AuthorizationPending,
    DeviceFlowError,
    GitHub,
)
from spyglass_store.guards import (
    _authorize,
    _charged_size,  # noqa: F401 - re-exported for callers that import it here
    _enforce_quota,
    _pick_readable,
    _require_possession,
    client_ip,
)
from spyglass_store.lab import lab_member_for_github
from spyglass_store.models import (
    DeviceCodeOut,
    FileOut,
    FileRegistrationIn,
    ServerInfo,
    TokenOut,
    TokenRequest,
    UploadTarget,
    VisibilityIn,
    VisibilityOut,
)
from spyglass_store.s3 import S3ObjectStore
from spyglass_store.settings import Settings, get_settings
from spyglass_store.storage import object_key

API_PREFIX = "/api/v1"


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
        Database access layer. Defaults to `spyglass_store.registry`.
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

    @app.get(f"{API_PREFIX}/info", response_model=ServerInfo)
    def server_info(
        identity: Annotated[Identity, Depends(require_identity)],
    ) -> ServerInfo:
        """What this deployment expects of a client.

        One fact today: which digests to send when registering a file. The
        broker signs whatever it is given, but only the operator knows whether
        the store behind the endpoint verifies the SHA-256 checksum or ignores
        it — Ceph RGW ignores it — so the client would otherwise have to
        compute an MD5 on every multi-gigabyte upload on the chance that it
        matters.

        Authenticated, like everything but login: it describes the deployment,
        and an unauthenticated caller has no file to upload.

        Cacheable for the life of a session. It changes when an operator
        changes backends, which is not something that happens mid-upload.
        """
        digests = ["sha256"]

        if not settings.s3_store_verifies_sha256:
            # The store will not check the address digest, so send the one it
            # will check. See `settings.s3_store_verifies_sha256`.
            digests.append("md5")

        return ServerInfo(
            api_version=API_PREFIX.rsplit("/", 1)[-1], upload_digests=digests
        )

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

        # Both lookups return every registration, not one: a name and a hash
        # are each non-unique, and the caller is party to at most one of them.
        candidates = list(
            app.state.registry.files_by_sha256(sha256)
            if sha256
            else app.state.registry.files_by_name(name)
        )

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

        # No visibility declared means "decide for me": public for a raw file,
        # and the raw's own audience for an analysis file that has one. A
        # declared visibility is honoured as given, wider or narrower.
        declared = body.visibility or VisibilityIn(scope="public")

        try:
            rules = rules_for(Scope(declared.scope), declared.teams)
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

        _require_possession(request, body, identity, settings, app.state.store)

        key = object_key(body.sha256)

        # Retrying a dropped response must not register the file twice, so an
        # identical prior registration by this owner is returned as-is.
        existing = app.state.registry.registration_for(
            body.sha256, body.spyglass_name, identity.account_id
        )

        try:
            file = existing or app.state.registry.register_file(
                sha256=body.sha256,
                size_bytes=body.size_bytes,
                spyglass_name=body.spyglass_name,
                file_class=body.file_class,
                owner=identity.account_id,
                rules=rules,
                inherit_if_parent=body.visibility is None,
            )
        except registry.ContentConflict as err:
            # One raw name, one file. Refused rather than accepted because an
            # analysis file inherits its raw's visibility *by name*, so a second
            # raw registration holding different bytes would be a way to
            # publish someone else's derivatives. 409 rather than 422: the
            # request is well-formed and would have been fine yesterday.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(err)
            ) from err

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
            content_md5=body.content_md5,
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
            #
            # Logged as a refused read, for two reasons. It is the only record
            # that anyone *wanted* this file — `reconcile` can say which
            # registrations have no bytes, but not which of those someone is
            # waiting for, and that is what tells an operator what to upload
            # first. And without a row, an authenticated caller holding a
            # file_id could probe whether an object exists and leave no trace.
            #
            # Charges nothing: no URL was issued and nothing was transferred.
            #
            # This runs before `_authorize`, so the row is written for a caller
            # whose permission has not been checked. That ordering is older
            # than this log and is deliberate — see the note below on why the
            # quota check precedes authorization — but it does mean existence
            # is disclosed to anyone with a valid token and a file_id. The id
            # is a 128-bit random, so guessing one is not the concern; the
            # untraced probe was, and this closes it.
            app.state.registry.log_access(
                identity=identity,
                action="read",
                granted=False,
                file_id=file_id,
                source_ip=client_ip(request),
            )
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
