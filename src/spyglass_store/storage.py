"""Object layout and the storage adapter interface.

Objects are content-addressed: the key is derived from the file's SHA-256, so
identical bytes occupy one object no matter how many times they are registered.
That gives deduplication, integrity checking, and immutability for free, and it
means a regenerated analysis file that hashes identically is *proven* identical
rather than assumed.

Human-readable names live in the registry (see `schema.py`), not in the key, so
naming conventions can be reorganized without moving a single object.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import NamedTuple, Protocol, runtime_checkable

#: Layout version. Bump only for a change that would strand existing objects.
LAYOUT_VERSION = "v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def object_key(sha256: str) -> str:
    """Return the object-store key for a content hash.

    Two levels of fan-out keep any single prefix from accumulating the whole
    corpus, which matters for stores that shard or list by prefix.

    Parameters
    ----------
    sha256 : str
        Lowercase hex digest, 64 characters.

    Returns
    -------
    str
        Key of the form ``spyglass/v1/ab/cd/abcd...``.

    Raises
    ------
    ValueError
        If the digest is not 64 lowercase hex characters.

    Examples
    --------
    >>> object_key("a" * 64)
    'spyglass/v1/aa/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    """
    if not _SHA256_RE.match(sha256):
        raise ValueError(
            f"Expected a 64-character lowercase hex digest, got: {sha256!r}"
        )

    return "/".join(
        ["spyglass", LAYOUT_VERSION, sha256[:2], sha256[2:4], sha256]
    )


class PresignedUpload(NamedTuple):
    """Where to write an object, and what must accompany the write.

    The headers are not advisory. They are covered by the signature, so a
    client that drops them gets a refusal rather than an unverified upload.

    Attributes
    ----------
    url : str
        Presigned PUT URL.
    headers : dict of str
        Headers the client must send verbatim.
    """

    url: str
    headers: dict[str, str]


#: A hex MD5, as a client reports it.
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")


def checksum_header(sha256: str) -> str:
    """Return the value S3 expects in `x-amz-checksum-sha256`.

    S3 carries checksums base64 encoded, while the registry addresses objects
    by hex digest, so the two representations have to be converted rather than
    compared.

    Parameters
    ----------
    sha256 : str
        Lowercase hex digest, 64 characters.

    Returns
    -------
    str
        Base64 of the same digest.

    Raises
    ------
    ValueError
        If the digest is not 64 lowercase hex characters.

    Examples
    --------
    >>> checksum_header("0" * 64)
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    """
    if not _SHA256_RE.match(sha256):
        raise ValueError(
            f"Expected a 64-character lowercase hex digest, got: {sha256!r}"
        )

    return base64.b64encode(bytes.fromhex(sha256)).decode()


def md5_header(md5: str) -> str:
    """Return the value S3 expects in `Content-MD5`.

    The older integrity header, and the only one some stores honour — Ceph RGW
    ignores the SHA-256 checksum and enforces this. So the broker sends both
    when it can, and each store enforces the strongest check it understands.

    **MD5 is a corruption check, not a security control.** Collisions are
    constructible, so it catches a truncated or corrupted transfer and not a
    deliberate substitution. Where the store honours the SHA-256 checksum, that
    stronger check still applies.

    Parameters
    ----------
    md5 : str
        Lowercase hex digest, 32 characters.

    Returns
    -------
    str
        Base64 of the same digest.

    Raises
    ------
    ValueError
        If the digest is not 32 lowercase hex characters.

    Examples
    --------
    >>> md5_header("0" * 32)
    'AAAAAAAAAAAAAAAAAAAAAA=='
    """
    if not _MD5_RE.match(md5):
        raise ValueError(
            f"Expected a 32-character lowercase hex digest, got: {md5!r}"
        )

    return base64.b64encode(bytes.fromhex(md5)).decode()


#: Bytes sampled for a possession challenge. Small on purpose: the point is
#: to prove the caller holds the file, and reading more proves nothing extra
#: while making the broker's own read less trivially bounded.
PROOF_LENGTH = 64


class PossessionChallenge(NamedTuple):
    """A range of a file that only its holder can answer for.

    Attributes
    ----------
    offset : int
        Byte offset into the object.
    length : int
        Number of bytes to digest.
    """

    offset: int
    length: int


def proof_challenge(
    account_id: str, sha256: str, size_bytes: int
) -> PossessionChallenge:
    """Return the byte range this account must digest to claim this content.

    Derived from the account and the hash rather than stored, so a challenge
    survives a restart and needs no table. The offset is not a secret — the
    security comes from needing the bytes, which a caller holding only a hash
    does not have.

    Deterministic per account so a retry asks the same question. Different per
    account so one person's answer cannot be forwarded to another.

    Parameters
    ----------
    account_id : str
        Account being challenged.
    sha256 : str
        Content hash being claimed.
    size_bytes : int
        Size of the stored object.

    Returns
    -------
    PossessionChallenge
    """
    length = min(PROOF_LENGTH, max(size_bytes, 1))
    span = max(size_bytes - length, 0)

    if span == 0:
        return PossessionChallenge(0, length)

    seed = hashlib.sha256(f"{account_id}:{sha256}".encode()).digest()

    return PossessionChallenge(int.from_bytes(seed[:8], "big") % span, length)


def proof_answer(data: bytes, offset: int) -> str:
    """Return the expected answer for a challenge over `data`.

    The offset is folded in so an answer for one range cannot be replayed as
    the answer for another over the same file.

    Parameters
    ----------
    data : bytes
        The challenged bytes.
    offset : int
        Where they came from.

    Returns
    -------
    str
        Hex digest.
    """
    return hashlib.sha256(f"{offset}:".encode() + data).hexdigest()


@runtime_checkable
class ObjectStore(Protocol):
    """An S3-compatible object store.

    Kept deliberately small: the broker only needs to know whether an object
    exists, hand out time-limited URLs for it, and accept an upload. Anything
    richer would tie us to one implementation, and the choice among Ceph RGW,
    SeaweedFS, and Garage is meant to stay reversible.
    """

    def exists(self, key: str) -> bool:
        """Return True if an object is present at `key`."""
        ...

    def presigned_get(self, key: str, ttl_seconds: int) -> str:
        """Return a time-limited URL for reading `key`."""
        ...

    def read_range(self, key: str, offset: int, length: int) -> bytes | None:
        """Return `length` bytes of `key` from `offset`, or None if absent.

        The one place the broker reads object data, and deliberately bounded
        to `PROOF_LENGTH` bytes by its only caller. It exists so a caller
        claiming content they cannot already read has to prove they hold it;
        without it, knowing a hash would be enough to claim the bytes behind
        it. That is a different thing from standing in the data path, which
        remains something this service never does.
        """
        ...

    def size(self, key: str) -> int | None:
        """Return the stored size of `key` in bytes, or None if absent.

        The size a client declared at registration is not evidence of
        anything. Metering against it lets an uploader register one byte for
        a ten gigabyte object and make it free to read forever.
        """
        ...

    def presigned_put(
        self, key: str, ttl_seconds: int, sha256: str | None = None
    ) -> PresignedUpload:
        """Return a time-limited target for writing `key`.

        When `sha256` is given, the store is asked to verify the uploaded
        bytes against it, so content cannot be registered under one hash and
        uploaded as another.
        """
        ...
