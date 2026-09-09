"""Turning a bearer token into the identity a decision is made about.

A token is verified by asking GitHub who it belongs to: `GET /user` returns the
id, login, and creation date, which is everything `schema.Account` records. No
scopes are needed, so the token a developer already has from `gh auth token`
works, and so does the unscoped token device flow will hand out later.

That makes ST-1.2 an ergonomics feature rather than a prerequisite. Device flow
exists so a user on a headless machine can *obtain* a token without a browser;
it is not how a token is *checked*.

**The token is never stored.** It is a GitHub credential that may carry broad
scopes, and the broker has no business holding one. Only the resulting account
is persisted, which is what ST-1.2 means by "store the internal account, not
the GitHub token". When the broker mints its own tokens, the routes here do not
change: `bearerAuth` is opaque to the client either way.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx
from fastapi import HTTPException, Request, status

#: GitHub's identity endpoint. An unscoped token still answers it.
GITHUB_USER_URL = "https://api.github.com/user"

#: How long a verified token is trusted before GitHub is asked again. Short,
#: because a revoked token should stop working promptly; long enough that a
#: range-request storm does not become a GitHub rate-limit problem.
VERIFY_TTL_SECONDS = 300

#: Tiers that may read beyond public files. An unverified account is limited to
#: public data; see `min_account_age_days` in `settings.py` for why.
READ_TIERS = frozenset({"verified", "trusted", "admin"})


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
        One of unverified, verified, trusted, admin.
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

    @property
    def may_read_private(self) -> bool:
        """True if this tier may read anything beyond public files."""
        return self.tier in READ_TIERS


class GitHubVerifier:
    """Verifies a bearer token by asking GitHub who holds it.

    Results are cached for `VERIFY_TTL_SECONDS` keyed on the token, so a client
    issuing many range requests costs one GitHub call per five minutes rather
    than one per request.
    """

    def __init__(
        self, client: httpx.Client | None = None, ttl: int | None = None
    ):
        """Build a verifier.

        Parameters
        ----------
        client : httpx.Client, optional
            HTTP client. Supplied by tests; a default one is built when
            omitted.
        ttl : int, optional
            Cache lifetime in seconds. Defaults to `VERIFY_TTL_SECONDS`.
        """
        self._client = client or httpx.Client(timeout=10.0)
        self._ttl = VERIFY_TTL_SECONDS if ttl is None else ttl
        self._cache: dict[str, tuple[float, Identity]] = {}

    def verify(self, token: str) -> Identity | None:
        """Return the identity holding `token`, or None if it is not valid.

        Parameters
        ----------
        token : str
            Bearer token presented by the caller.

        Returns
        -------
        Identity or None
            None when GitHub rejects the token or cannot be reached. A
            verifier that cannot check a token must not accept it.
        """
        now = time.monotonic()
        cached = self._cache.get(token)

        if cached and cached[0] > now:
            return cached[1]

        try:
            response = self._client.get(
                GITHUB_USER_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except httpx.HTTPError:
            return None  # unreachable GitHub is a failure to verify, not a pass

        if response.status_code != httpx.codes.OK:
            return None

        user = response.json()
        identity = Identity(
            github_id=user["id"], github_login=user.get("login", "")
        )
        self._cache[token] = (now + self._ttl, identity)

        return identity


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
