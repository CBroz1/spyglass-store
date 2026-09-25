"""The checks a route runs before it answers.

Each one decides, records the decision, and raises the HTTP answer when the
decision is no. That pairing is the point of keeping them together and out of
the handlers: a refusal is the event an audit is most likely to be looking for,
so denial must never be the path that forgets to write a log row. Every
function here that can refuse also logs — on both outcomes where there is
something to charge, and on the refusal where there is not.

`access.py` holds the permission rule as a pure function over data. This module
is the layer that feeds it, meters it, and turns its answer into a status code;
nothing here decides *who may read what*, and nothing in `access.py` knows
about HTTP.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi import HTTPException, Request, status

from spyglass_store import registry
from spyglass_store.access import may_read
from spyglass_store.auth import Identity
from spyglass_store.models import FileRegistrationIn
from spyglass_store.settings import Settings
from spyglass_store.storage import object_key, proof_answer, proof_challenge


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


def _readable(request: Request, file: registry.FileRecord, identity: Identity):
    """Return True if `identity` may read `file`, directly or by inheritance.

    **An analysis file that declared no visibility is readable by whoever may
    read the raw it came from**, and follows that raw as it changes. That is the
    point of recording `File.parent`: a derivative produced on a shared compute
    host is registered by that host's account, so without inheritance the person
    whose raw it came from — the one who has every reason to read it — would be
    locked out of a private result, while the compute account that happened to
    upload it would not.

    **A declared visibility is honoured exactly**, wider or narrower than the
    raw, because that was somebody's choice. `File.inherits` is what separates
    the two cases, and `replace_rules` clears it: a file whose visibility has
    been set does not quietly go back to following its parent.

    One hop, always. Spyglass's `AnalysisNwbfile` points at `Nwbfile`, so a
    parent is always a raw file and a raw file never has one — there is no chain
    to walk and no cycle to guard against.

    The parent is a name, so what counts as "the raw" has to be something a
    stranger cannot arrange: `registrations_of_parent` takes only *raw*
    registrations that predate this file, and `registry.ContentConflict` keeps
    them agreeing about content. Relax any of the three and this becomes a way
    to read other people's results — claim the name, declare it public,
    inherit.

    Costs an extra query, and only when the direct check has already failed and
    the file has a parent.
    """
    reg = request.app.state.registry
    reader = identity.as_reader()

    if may_read(reg.rules_for_file(file.file_id), reader, file.owner):
        return True

    parent = getattr(file, "parent", None)

    if not (parent and getattr(file, "inherits", False)):
        return False

    return any(
        may_read(reg.rules_for_file(raw.file_id), reader, raw.owner)
        for raw in reg.registrations_of_parent(
            parent, before=getattr(file, "registered", None)
        )
    )


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
        if not _readable(request, file, identity):
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
    store=None,
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
    store : ObjectStore, optional
        Consulted for the object's true size when a read is granted. Required
        for `read`: quota is summed from these rows, so logging the declared
        size would let an uploader register one byte for a huge object and make
        every later read of it nearly free.

    Raises
    ------
    fastapi.HTTPException
        403 when the caller may not read the file.
    """
    reg = request.app.state.registry
    permitted = _readable(request, file, identity)

    # Charged only when a URL is actually issued; a refusal transfers nothing,
    # and counting it would inflate quota against the wrong user. The size is
    # the store's, not the uploader's: `usage_since` totals these rows, so a
    # declared size here would be a quota the uploader sets themselves.
    charged = 0
    if permitted and action == "read":
        charged = _charged_size(store, file) if store else file.size_bytes

    reg.log_access(
        identity=identity,
        action=action,
        granted=permitted,
        file_id=file.file_id,
        size_bytes=charged,
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
    if usage.earliest is not None and usage.asof is not None:
        # Both timestamps come from the database, in one reading. The broker's
        # own clock is naive and local, so mixing the two would slide
        # Retry-After by whatever the hosts disagree by — and asking the
        # database here would mean reaching past the registry this layer is
        # given, which is the seam the whole route layer is tested through.
        retry = max(1, (usage.earliest + window - usage.asof).total_seconds())

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


def _require_possession(
    request: Request,
    body: FileRegistrationIn,
    identity: Identity,
    settings: Settings,
    store,
) -> None:
    """Make a caller prove they hold content they cannot already read.

    Registration deduplicates, so without this a caller who knows a digest can
    register the content behind it under their own name and share it onward —
    including content someone else keeps private. Prior access would become
    permanent access, and revoking visibility would not take it back.

    Nothing is asked when the caller can already read some registration of
    this content: they could download it and upload it again, so a proof would
    only cost them a round trip. Nothing is asked when the object is absent
    either, because the upload itself proves possession — the store verifies
    the bytes against the declared hash before accepting them.

    Parameters
    ----------
    request : fastapi.Request
        Incoming request, for audit.
    body : FileRegistrationIn
        The registration being attempted.
    identity : Identity
        The caller.
    settings : Settings
        Broker configuration.
    store : ObjectStore
        Where the challenged bytes are read from.

    Raises
    ------
    fastapi.HTTPException
        428 carrying the challenge when no proof was supplied, or 403 when
        the answer is wrong.
    """
    if not settings.require_possession_proof:
        return

    key = object_key(body.sha256)

    if not store.exists(key):
        return  # they must upload, and the store checks the hash

    readable = _pick_readable(
        request,
        list(request.app.state.registry.files_by_sha256(body.sha256)),
        identity,
    )

    if readable is not None:
        return  # they can already have these bytes

    size = store.size(key) or 0

    if size == 0:
        # Nothing to sample, and nothing to prove: empty content is held by
        # anyone who can name it. Challenging it would ask for `bytes=0-0` of a
        # zero-length object, which the store refuses — so a second owner could
        # never deduplicate empty content at all.
        return

    challenge = proof_challenge(identity.account_id, body.sha256, size)

    if not body.possession_proof:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail={
                "detail": (
                    "This content is already stored and you cannot read it. "
                    "Answer the challenge to show you hold the file: digest "
                    "the named byte range as "
                    "sha256(f'{offset}:'.encode() + data)."
                ),
                "sha256": body.sha256,
                "offset": challenge.offset,
                "length": challenge.length,
            },
        )

    actual = store.read_range(key, challenge.offset, challenge.length)
    expected = proof_answer(actual or b"", challenge.offset)

    if not secrets.compare_digest(body.possession_proof, expected):
        request.app.state.registry.log_access(
            identity=identity,
            action="register",
            granted=False,
            source_ip=client_ip(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Possession proof did not match. You do not hold this file.",
        )
