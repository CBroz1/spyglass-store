"""Tests for the GitHub device-flow client.

No network. `httpx.MockTransport` answers at the transport layer, so the real
request construction, form encoding, and JSON handling all run — only the wire
is replaced.
"""

from __future__ import annotations

from datetime import date, timedelta

import httpx
import pytest

from spyglass_store.github import (
    ACCESS_TOKEN_URL,
    DEVICE_CODE_URL,
    USER_URL,
    AuthorizationPending,
    DeviceFlowError,
    GitHub,
)


def _github(routes: dict, status_by_url: dict | None = None) -> GitHub:
    """Build a client whose responses come from `routes`, keyed by URL."""
    status_by_url = status_by_url or {}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url not in routes:  # pragma: no cover - a miss is a test bug
            raise AssertionError(f"unexpected request to {url}")
        return httpx.Response(status_by_url.get(url, 200), json=routes[url])

    return GitHub(
        client_id="cid",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_begin_returns_what_the_user_needs():
    """The user needs a code and somewhere to type it."""
    gh = _github(
        {
            DEVICE_CODE_URL: {
                "device_code": "dev-123",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://github.com/login/device",
                "interval": 5,
                "expires_in": 900,
            }
        }
    )

    code = gh.begin()

    assert code.user_code == "ABCD-EFGH"
    assert code.verification_uri == "https://github.com/login/device"
    assert code.interval == 5


def test_begin_without_a_client_id_says_what_to_do():
    """The likeliest misconfiguration should name its own fix."""
    with pytest.raises(DeviceFlowError, match="Register an OAuth app"):
        GitHub(client_id="").begin()


def test_begin_surfaces_a_github_refusal():
    """An app without device flow enabled fails here, not mysteriously later."""
    gh = _github({DEVICE_CODE_URL: {"error": "device_flow_disabled"}})

    with pytest.raises(DeviceFlowError, match="device_flow_disabled"):
        gh.begin()


@pytest.mark.parametrize("error", ["authorization_pending", "slow_down"])
def test_pending_is_not_a_failure(error):
    """Both mean keep waiting, so neither may look like a refusal."""
    gh = _github({ACCESS_TOKEN_URL: {"error": error, "interval": 10}})

    with pytest.raises(AuthorizationPending) as caught:
        gh.poll("dev-123")

    assert caught.value.interval == 10


@pytest.mark.parametrize("error", ["access_denied", "expired_token"])
def test_terminal_errors_stop_the_client(error):
    """A denial must not be retried forever."""
    gh = _github({ACCESS_TOKEN_URL: {"error": error}})

    with pytest.raises(DeviceFlowError, match=error):
        gh.poll("dev-123")


def test_poll_returns_the_token_once_approved():
    gh = _github({ACCESS_TOKEN_URL: {"access_token": "gho_abc"}})

    assert gh.poll("dev-123") == "gho_abc"


def test_user_reads_the_three_facts_we_keep():
    gh = _github(
        {
            USER_URL: {
                "id": 9404707,
                "login": "CBroz1",
                "created_at": "2014-10-26T14:47:52Z",
            }
        }
    )

    user = gh.user("gho_abc")

    assert user.github_id == 9404707
    assert user.github_login == "CBroz1"
    assert user.created == date(2014, 10, 26)


def test_unrecognized_token_is_an_error():
    gh = _github({USER_URL: {"message": "Bad credentials"}}, {USER_URL: 401})

    with pytest.raises(DeviceFlowError, match="did not recognize"):
        gh.user("gho_bad")


def test_age_is_measured_from_the_creation_date():
    gh = _github(
        {
            USER_URL: {
                "id": 1,
                "login": "new",
                "created_at": "2026-09-01T00:00:00Z",
            }
        }
    )

    user = gh.user("gho_abc")

    assert user.age_days(date(2026, 9, 11)) == 10


def test_an_unparseable_creation_date_fails_closed():
    """An unknown age must not slip past a minimum-age check.

    Treating it as brand new is the conservative direction: a real account
    gets asked to try again, where a fake one would have been admitted.
    """
    gh = _github({USER_URL: {"id": 1, "login": "x", "created_at": None}})

    user = gh.user("gho_abc")

    assert user.age_days() == 0
    assert user.created == date.today()


def test_unreachable_github_is_reported_not_swallowed():
    def handler(request):
        raise httpx.ConnectError("no route to host")

    gh = GitHub(
        client_id="cid",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(DeviceFlowError, match="Could not reach GitHub"):
        gh.begin()


def test_recent_account_is_young_enough_to_be_refused():
    """Sanity check on the comparison the login route makes."""
    gh = _github(
        {
            USER_URL: {
                "id": 1,
                "login": "x",
                "created_at": (date.today() - timedelta(days=3)).isoformat(),
            }
        }
    )

    assert gh.user("gho_abc").age_days() == 3
