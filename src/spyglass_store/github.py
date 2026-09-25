"""Talking to GitHub: device flow and identity lookup.

All knowledge of GitHub's wire format lives here, so the routes deal in
`Identity` and the rest of the broker never learns what an OAuth error code
looks like.

Device flow exists because a user on a cluster node or inside a container has
no browser and no callback port. They get a short code, type it at github.com
on whatever device they do have, and the client polls until it is approved.

**The app requests no scopes.** An unscoped token still answers `GET /user`,
which is the only thing identity needs. That is the entire security argument
for registering an app rather than accepting a token from `gh`: the token the
broker handles can read a username and do nothing else, so a broker compromise
cannot reach a user's repositories.

The GitHub token is used once, to learn who the caller is, and then dropped.
What the client receives back is a broker token (see `registry.issue_token`),
which is meaningless to GitHub and revocable here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

import httpx

DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"

#: GitHub's grant type for device flow, spelled out by RFC 8628.
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

#: Poll responses that mean "not yet" rather than "no". Everything else is
#: terminal, and the client should stop rather than hammer the endpoint.
PENDING_ERRORS = frozenset({"authorization_pending", "slow_down"})


@dataclass(frozen=True)
class DeviceCode:
    """What the user needs in order to approve a login."""

    device_code: str
    user_code: str
    verification_uri: str
    interval: int
    expires_in: int


@dataclass(frozen=True)
class GitHubUser:
    """The three facts the broker keeps about a GitHub identity."""

    github_id: int
    github_login: str
    created: date

    def age_days(self, today: date | None = None) -> int:
        """Return the account's age in days."""
        return ((today or date.today()) - self.created).days


class DeviceFlowError(Exception):
    """A terminal device-flow failure: denied, expired, or misconfigured."""


class AuthorizationPending(Exception):
    """Not an error — the user has not finished approving yet.

    Carries `interval` because GitHub answers `slow_down` when a client polls
    too fast, and the correct response is to wait longer, not to give up.
    """

    def __init__(self, interval: int = 5):
        super().__init__("authorization pending")
        self.interval = interval


class GitHub:
    """Client for the device flow and the identity endpoint."""

    def __init__(self, client_id: str = "", client: httpx.Client | None = None):
        """Build a client.

        Parameters
        ----------
        client_id : str
            OAuth app client id, from settings. Device flow must be enabled
            on the app.
        client : httpx.Client, optional
            HTTP client. Supplied by tests.
        """
        self.client_id = client_id
        self._http = client or httpx.Client(timeout=15.0)

    def begin(self) -> DeviceCode:
        """Ask GitHub for a device and user code.

        Returns
        -------
        DeviceCode

        Raises
        ------
        DeviceFlowError
            If no client id is configured, or GitHub refuses.
        """
        if not self.client_id:
            raise DeviceFlowError(
                "No GitHub client id configured. Register an OAuth app with "
                "device flow enabled and set SPYGLASS_STORE_GITHUB_CLIENT_ID; "
                "see the deployment docs."
            )

        payload = self._post(DEVICE_CODE_URL, {"client_id": self.client_id})

        if "device_code" not in payload:
            raise DeviceFlowError(
                f"GitHub refused the device request: {payload.get('error')}"
            )

        return DeviceCode(
            device_code=payload["device_code"],
            user_code=payload["user_code"],
            verification_uri=payload["verification_uri"],
            interval=int(payload.get("interval", 5)),
            expires_in=int(payload.get("expires_in", 900)),
        )

    def poll(self, device_code: str, interval: int = 5) -> str:
        """Exchange an approved device code for a GitHub token.

        Parameters
        ----------
        device_code : str
            The code from `begin`.
        interval : int, optional
            The interval `begin` returned. Carried so a `slow_down` can raise
            it: the spec says to add five seconds and keep the new cadence,
            and GitHub does not reliably echo a replacement interval.
            From `begin`.

        Returns
        -------
        str
            A GitHub access token. Used once to identify the user, then
            discarded.

        Raises
        ------
        AuthorizationPending
            The user has not approved yet. Keep polling.
        DeviceFlowError
            Denied, expired, or otherwise terminal.
        """
        payload = self._post(
            ACCESS_TOKEN_URL,
            {
                "client_id": self.client_id,
                "device_code": device_code,
                "grant_type": DEVICE_GRANT,
            },
        )

        if token := payload.get("access_token"):
            return token

        error = payload.get("error", "unknown_error")

        if error in PENDING_ERRORS:
            # `slow_down` is an instruction to poll five seconds slower from
            # here on, not a one-off delay. Echoing back the same interval
            # would keep an already-too-fast client at the cadence that earned
            # the warning.
            slower = interval + 5 if error == "slow_down" else interval

            # The new cadence reaches the client as `Retry-After` on the
            # broker's 428. It does not compound across polls: the broker holds
            # no state between them, so a second `slow_down` raises the default
            # again rather than the raised value. Enough to back off, not
            # enough to satisfy the spec's "and subsequent requests".
            raise AuthorizationPending(
                int(payload.get("interval", slower) or slower)
            )

        raise DeviceFlowError(f"Device flow failed: {error}")

    def user(self, token: str) -> GitHubUser:
        """Return the identity holding `token`.

        Parameters
        ----------
        token : str
            A GitHub access token.

        Returns
        -------
        GitHubUser

        Raises
        ------
        DeviceFlowError
            If GitHub does not recognize the token.
        """
        try:
            response = self._http.get(
                USER_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except httpx.HTTPError as err:
            # Same translation `_post` does. Without it an unreachable GitHub
            # escapes the login route as a 500, which reads like a broker fault
            # and tells the user nothing about what to retry.
            raise DeviceFlowError(f"Could not reach GitHub: {err}") from err

        if response.status_code != httpx.codes.OK:
            raise DeviceFlowError("GitHub did not recognize the token.")

        try:
            body = response.json()
        except ValueError as err:
            raise DeviceFlowError(
                "GitHub returned a response that was not JSON."
            ) from err

        return GitHubUser(
            github_id=body["id"],
            github_login=body.get("login", ""),
            created=_as_date(body.get("created_at")),
        )

    def _post(self, url: str, data: dict) -> dict:
        """POST form data, asking for JSON back.

        GitHub answers these endpoints with form encoding unless asked
        otherwise, and returns errors as 200 with an `error` key rather than
        an HTTP status — so the caller has to read the body either way.
        """
        try:
            response = self._http.post(
                url, data=data, headers={"Accept": "application/json"}
            )
        except httpx.HTTPError as err:
            raise DeviceFlowError(f"Could not reach GitHub: {err}") from err

        try:
            return response.json()
        except ValueError as err:
            raise DeviceFlowError("GitHub returned a non-JSON body.") from err


def _as_date(value) -> date:
    """Parse GitHub's ISO timestamp into a date.

    An unparseable value yields today, which fails the minimum-age check
    closed rather than admitting an account whose age is unknown.
    """
    if not value:
        return date.today()

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except (AttributeError, ValueError):
        return date.today()
