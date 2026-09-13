"""Turning a bearer token into the identity a decision is made about.

The token a client presents is issued by the broker, not by GitHub. Device
flow (see `github.py`) establishes who someone is once; `registry.issue_token`
then mints a credential that means nothing outside this service. Verifying it
is a hash lookup against `ClientToken` — no network call, so GitHub being slow
or down cannot stall a read.

That indirection is the point of registering an OAuth app. The GitHub token is
used once to learn a username and then dropped, so the credential the broker
stores, logs near, and hands back can read nothing on GitHub at all. A leaked
broker token costs its owner access to this service; a leaked `gh` token would
have cost them their repositories.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status

from spyglass_store.access import Reader, Tier


@dataclass(frozen=True)
class Identity:
    """An authenticated caller.

    Attributes
    ----------
    github_id : int
        Immutable GitHub user id. Logins are renameable; this is not.
    github_login : str
        GitHub username, for display and audit.
    account_id : str
        Broker account id. Empty until the account is looked up or created.
    tier : str
        One of unverified, verified, trusted, admin. Stored as the string the
        database holds; `access.Tier` is the vocabulary.
    teams : frozenset of str
        `LabTeam` names this identity reads through, resolved once per request
        so `access.can_read` stays a pure function over data. Empty for an
        unaffiliated reader, which is a valid account rather than an error.
    """

    github_id: int
    github_login: str = ""
    account_id: str = ""
    tier: str = "unverified"
    teams: frozenset[str] = field(default_factory=frozenset)

    def as_reader(self) -> Reader:
        """Return this identity as the subject of a permission decision.

        The whole permission rule lives in `access`; this is the only place
        that converts an authenticated caller into its input.
        """
        return Reader(
            account_id=self.account_id,
            teams=self.teams,
            tier=Tier.parse(self.tier),
        )


class TokenVerifier:
    """Resolves a broker token through the stored hashes.

    A thin wrapper so the application has something injectable on
    `app.state`; the work is `registry.identity_for_token`.
    """

    def verify(self, token: str) -> Identity | None:
        """Return the identity holding `token`, or None."""
        from spyglass_store import registry

        return registry.identity_for_token(token)


def bearer_token(header: str | None) -> str | None:
    """Extract a bearer token from an Authorization header.

    Parameters
    ----------
    header : str or None
        Raw `Authorization` header value.

    Returns
    -------
    str or None
        The token, or None if the header is absent or not a bearer scheme.

    Examples
    --------
    >>> bearer_token("Bearer abc123")
    'abc123'
    >>> bearer_token("Basic abc123") is None
    True
    """
    if not header:
        return None

    scheme, _, token = header.partition(" ")

    if scheme.lower() != "bearer" or not token.strip():
        return None

    return token.strip()


def require_identity(request: Request) -> Identity:
    """FastAPI dependency resolving the caller's identity.

    Parameters
    ----------
    request : fastapi.Request
        Incoming request. The verifier is read from `app.state`, so it is
        chosen per application instance rather than per import.

    Returns
    -------
    Identity
        The authenticated caller.

    Raises
    ------
    fastapi.HTTPException
        401 when the header is missing, malformed, or names no valid identity.
        Authentication failure is 401; *authorization* failure is 403 and is
        decided later by `access.can_read`.
    """
    token = bearer_token(request.headers.get("Authorization"))
    identity = (
        request.app.state.verifier.verify(token) if token is not None else None
    )

    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return identity
