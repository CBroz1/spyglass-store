"""Checks on the deployment recipe.

Two of this service's defences do not live in the code at all: the login
endpoints are rate limited at the edge, and the object store must answer on a
different origin than the broker. Nothing in the application can fail when
either is undone — the broker serves happily either way, and what breaks is a
GitHub rate limit shared by everyone, or every read at once.

So they are asserted here, against the files that carry them. These are drift
guards on intent, not a substitute for running the stack: `nginx -t` validates
the syntax, and only a real request shows a 429.
"""

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
COMPOSE_PATH = DEPLOY / "docker-compose.yml"
NGINX_PATH = DEPLOY / "nginx.conf.template"

#: Every route that takes no credential. Each one spends the broker's own
#: GitHub client id, so each one needs a ceiling.
UNAUTHENTICATED_ROUTES = ("/api/v1/auth/device", "/api/v1/auth/token")


@pytest.fixture(scope="module")
def compose() -> dict:
    """The parsed compose file."""
    return yaml.safe_load(COMPOSE_PATH.read_text())


@pytest.fixture(scope="module")
def nginx() -> str:
    """The edge configuration template, as text."""
    return NGINX_PATH.read_text()


@pytest.fixture(scope="module")
def edge_env(compose: dict) -> dict:
    """The environment the compose file renders the template with."""
    return compose["services"]["edge"]["environment"]


def test_the_broker_is_only_reachable_through_the_edge(compose: dict) -> None:
    """A published broker port is a way around every limit at the edge.

    The rate limit on the login endpoints is the edge's whole reason for
    existing. Publishing the broker alongside it would leave the limit in
    place and the hole open, which is worse than not having one: it looks
    protected.
    """
    services = compose["services"]

    assert not services["broker"].get("ports"), (
        "the broker must not be published to the host; the edge is the front "
        "door, and a direct port bypasses the login rate limit"
    )
    assert services["edge"]["ports"], "the edge has to be published instead"


def test_the_edge_serves_the_config_in_this_directory(compose: dict) -> None:
    """A config that is not mounted limits nothing.

    It has to land under `/etc/nginx/templates` specifically. Mounted straight
    into `conf.d` the file is served verbatim, `${...}` and all, and nginx
    refuses to start.
    """
    mounts = compose["services"]["edge"]["volumes"]

    assert any(
        mount.startswith(f"./{NGINX_PATH.name}:")
        and "/etc/nginx/templates/" in mount
        for mount in mounts
    )


def test_every_limit_in_the_template_has_a_default(
    nginx: str, edge_env: dict
) -> None:
    """A placeholder nothing sets renders empty, and nginx will not start.

    The point of the template is that a maintainer tunes limits in `.env`
    rather than in nginx syntax. That only holds if the deployment works with
    an empty `.env`, so every variable needs a default here — and a typo in
    either file is exactly the drift this catches.
    """
    used = set(re.findall(r"\$\{(SPYGLASS_STORE_EDGE_[A-Z_]+)\}", nginx))
    provided = {
        key for key in edge_env if key.startswith("SPYGLASS_STORE_EDGE_")
    }

    assert used, "the template no longer parameterizes anything"
    assert used == provided, (
        "template and compose disagree; unset renders empty and nginx refuses "
        f"to start. Only in the template: {sorted(used - provided)}. Only in "
        f"compose: {sorted(provided - used)}"
    )
    missing = [key for key in provided if ":-" not in str(edge_env[key])]
    assert not missing, f"no default, so an empty .env breaks: {missing}"


def test_rendering_leaves_nginx_own_variables_alone(
    nginx: str, edge_env: dict
) -> None:
    """envsubst substitutes every name it is given, and nginx is full of them.

    Unfiltered, `$host` or `$remote_addr` would be replaced by whatever happens
    to be in the container's environment — most likely nothing, which silently
    guts `proxy_set_header` and the limiter's key.
    """
    assert edge_env.get("NGINX_ENVSUBST_FILTER") == "^SPYGLASS_STORE_EDGE_"
    assert "$binary_remote_addr" in nginx, "the limiter still keys on the peer"


def test_every_unauthenticated_route_is_rate_limited(nginx: str) -> None:
    """These are the routes that need no account, so quota cannot see them.

    An authenticated caller is metered per account by the broker's own volume
    quota. A caller who has not logged in is metered by nothing, and the login
    endpoints are exactly what they can reach — on the broker's GitHub client
    id, which is shared by every user of the deployment.
    """
    for route in UNAUTHENTICATED_ROUTES:
        location = nginx.split(f"location = {route}")
        assert len(location) == 2, f"{route} has no location block"
        assert "limit_req zone=" in location[1].split("}")[0], (
            f"{route} is proxied without a rate limit"
        )


def test_throttling_answers_429_rather_than_503(nginx: str) -> None:
    """503 tells a client to retry a service that is not down.

    `openapi.yaml` documents 429 with `Retry-After` for throttling, so a
    client that already backs off correctly needs no special case for this
    one. nginx's default would give it one.
    """
    assert "limit_req_status 429;" in nginx
    assert "add_header Retry-After" in nginx


def test_the_edge_does_not_rewrite_the_content_redirect(nginx: str) -> None:
    """The 302 points at another origin on purpose.

    `proxy_redirect` rewriting that Location to the broker's own origin would
    make clients keep `Authorization` across it, and the object store answers
    those with a complaint about a missing `x-amz-content-sha256` — which
    names a checksum rather than the authentication it is really about.
    """
    assert "proxy_redirect off;" in nginx


def test_the_edge_does_not_serve_the_object_store(nginx: str) -> None:
    """Same constraint, from the other direction.

    Putting the store behind this proxy would give the two one origin, which
    is the natural thing to reach for on a single host and breaks every read.
    """
    assert "location /objects" not in nginx
    assert "proxy_pass" in nginx
    assert all(
        target.strip().startswith("http://broker")
        for target in nginx.split("proxy_pass ")[1:]
    )
