"""Checks on the deployment recipe.

Three of this service's defences do not live in the code at all: the login
endpoints are rate limited at the edge, the object store must answer on a
different origin than the broker, and credentials must not cross the network in
the clear. Nothing in the application can fail when any of them is undone — the
broker serves happily either way, and what breaks is a GitHub rate limit shared
by everyone, every read at once, or nothing visible whatsoever.

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
TLS_COMPOSE_PATH = DEPLOY / "docker-compose.tls.yml"
NGINX_DIR = DEPLOY / "nginx"
ENV_EXAMPLE_PATH = DEPLOY / "env.example"

#: Every route that takes no credential. Each one spends the broker's own
#: GitHub client id, so each one needs a ceiling.
UNAUTHENTICATED_ROUTES = ("/api/v1/auth/device", "/api/v1/auth/token")


class _TagTolerantLoader(yaml.SafeLoader):
    """Parse compose files that use compose's own merge tags.

    `docker-compose.tls.yml` marks its port list `!override`, without which
    compose appends to the base file's list and leaves a plain-HTTP listener
    published beside the TLS one. `yaml.safe_load` refuses unknown tags, so the
    tag is kept and its value read through.
    """


def _drop_tag(loader, suffix, node):
    """Return a tagged node's value, ignoring the tag itself."""
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)

    return loader.construct_scalar(node)


_TagTolerantLoader.add_multi_constructor("", _drop_tag)


def _load(path: Path) -> dict:
    """Parse one compose file."""
    return yaml.load(path.read_text(), Loader=_TagTolerantLoader)


@pytest.fixture(scope="module")
def compose() -> dict:
    """The base compose file: broker, edge, and the bundled object store."""
    return _load(COMPOSE_PATH)


@pytest.fixture(scope="module")
def tls_compose() -> dict:
    """The TLS overlay."""
    return _load(TLS_COMPOSE_PATH)


@pytest.fixture(scope="module")
def templates() -> dict:
    """Every nginx template, keyed by file name."""
    return {
        path.name: path.read_text() for path in NGINX_DIR.glob("*.template")
    }


@pytest.fixture(scope="module")
def proxy(templates: dict) -> str:
    """The shared server body, where the limits are applied."""
    return templates["proxy.inc.template"]


@pytest.fixture(scope="module")
def edge_env(compose: dict) -> dict:
    """The environment the compose file renders the templates with."""
    return compose["services"]["edge"]["environment"]


#: Anchored at the start of a line, so the word "location" inside a comment
#: does not swallow the block that follows it.
_LOCATION = re.compile(r"^location ([^{]+)\{(.*?)\n\}", re.S | re.M)


def _locations(proxy: str) -> dict:
    """Return each `location` block in the shared body, keyed by its match."""
    return {header.strip(): body for header, body in _LOCATION.findall(proxy)}


# --------------------------- the rate limit ---------------------------


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


def test_every_unauthenticated_route_is_rate_limited(proxy: str) -> None:
    """These are the routes that need no account, so quota cannot see them.

    An authenticated caller is metered per account by the broker's own volume
    quota. A caller who has not logged in is metered by nothing, and the login
    endpoints are exactly what they can reach — on the broker's GitHub client
    id, which is shared by every user of the deployment.
    """
    blocks = _locations(proxy)

    for route in UNAUTHENTICATED_ROUTES:
        body = blocks.get(f"= {route}")
        assert body is not None, f"{route} has no location block"
        assert "limit_req zone=" in body, f"{route} is proxied without a limit"


def test_throttling_answers_429_rather_than_503(
    templates: dict, proxy: str
) -> None:
    """503 tells a client to retry a service that is not down.

    `openapi.yaml` documents 429 with `Retry-After` for throttling, so a
    client that already backs off correctly needs no special case for this
    one. nginx's default would give it one.
    """
    assert "limit_req_status 429;" in templates["limits.conf.template"]
    assert "add_header Retry-After" in proxy


def test_the_limits_are_written_once(templates: dict) -> None:
    """Two front doors, one set of limits.

    The plain and TLS server blocks both include the same body. Copying it per
    variant would eventually leave them disagreeing, and the copy that lost
    would be the one someone was relying on.
    """
    front_doors = ["http.conf.template", "tls.conf.template"]

    for name in front_doors:
        assert "limit_req " not in templates[name], (
            f"{name} applies its own limits instead of including the shared "
            "body; that is the copy that will drift"
        )
        assert "proxy.inc" in templates[name], f"{name} includes nothing"


# --------------------------- configuration ---------------------------


def test_every_variable_in_a_template_has_a_default(
    templates: dict, edge_env: dict, tls_compose: dict
) -> None:
    """A placeholder nothing sets renders empty, and nginx will not start.

    The point of the templates is that a maintainer tunes limits in `.env`
    rather than in nginx syntax. That only holds if the deployment works with an
    empty `.env`, so every variable needs a default — except the TLS ones, which
    are required, because there is no sensible default for someone else's
    certificate.
    """
    used = set()
    for text in templates.values():
        used |= set(re.findall(r"\$\{(SPYGLASS_STORE_EDGE_[A-Z_]+)\}", text))

    provided = {**edge_env, **tls_compose["services"]["edge"]["environment"]}
    missing = sorted(used - set(provided))

    assert not missing, (
        f"rendered empty, so nginx refuses to start: {missing}. Add them to "
        "the edge service's environment."
    )

    for name, value in provided.items():
        if not name.startswith("SPYGLASS_STORE_EDGE_"):
            continue
        assert ":-" in str(value) or ":?" in str(value), (
            f"{name} has neither a default nor a required check, so an empty "
            ".env renders it blank and nginx fails with a syntax error"
        )


def test_rendering_leaves_nginx_own_variables_alone(
    edge_env: dict, proxy: str
) -> None:
    """envsubst substitutes every name it is given, and nginx is full of them.

    Unfiltered, `$host` or `$remote_addr` would be replaced by whatever happens
    to be in the container's environment — most likely nothing, which silently
    guts `proxy_set_header` and the limiter's key.
    """
    assert edge_env.get("NGINX_ENVSUBST_FILTER") == "^SPYGLASS_STORE_EDGE_"
    assert "$binary_remote_addr" in proxy or "$binary_remote_addr" in str(proxy)


def test_the_example_env_file_can_be_committed() -> None:
    """`.gitignore` ignores `*.env*`, and an example nobody can commit is not
    one.

    Hence `env.example` rather than `.env.example`. If this file is ever
    renamed to the conventional spelling it will vanish from the repository and
    every operator will be guessing at the variable list.
    """
    assert ENV_EXAMPLE_PATH.exists()
    assert not ENV_EXAMPLE_PATH.name.startswith("."), (
        "a dotted name matches .gitignore's *.env* and cannot be committed"
    )


def test_the_example_env_file_covers_the_broker_settings() -> None:
    """An operator sets what they can see.

    The volume allowances and the account-age floor are the settings a
    deployment has to choose deliberately, so leaving them out of the example
    means shipping someone else's placeholders by default.
    """
    text = ENV_EXAMPLE_PATH.read_text()

    for name in (
        "DJ_HOST",
        "SPYGLASS_STORE_GITHUB_CLIENT_ID",
        "SPYGLASS_STORE_S3_ENDPOINT_URL",
        "SPYGLASS_STORE_DOWNLOAD_TB_PER_DAY",
        "SPYGLASS_STORE_UPLOAD_TB_PER_DAY",
        "SPYGLASS_STORE_MIN_ACCOUNT_AGE_DAYS",
        "SPYGLASS_STORE_TOKEN_TTL_DAYS",
    ):
        assert f"{name}=" in text, f"{name} is not in {ENV_EXAMPLE_PATH.name}"


def test_the_broker_reads_the_env_file_whole(compose: dict) -> None:
    """Otherwise a setting is only reachable if this file happens to list it.

    Enumerating them here would duplicate every default from `settings.py` and
    silently drop whatever nobody remembered to add — which is how the quota
    and account-age settings came to be unreachable from `.env` at all.
    """
    env_files = compose["services"]["broker"].get("env_file", [])
    paths = [
        entry if isinstance(entry, str) else entry.get("path")
        for entry in env_files
    ]

    assert ".env" in paths

    assert "env_file" not in compose["services"]["edge"], (
        "the edge would receive the database password and the object-store "
        "credentials, and it needs neither"
    )


# --------------------------- transport security ---------------------------


def test_the_tls_overlay_replaces_the_published_ports(
    tls_compose: dict,
) -> None:
    """Compose appends port lists when it merges files.

    Without `!override` the base file's plain 8000 stays published beside 443,
    so every token can still be sent in the clear and nothing about the
    deployment looks wrong.
    """
    ports = tls_compose["services"]["edge"]["ports"]
    published = [str(entry).split(":")[0] for entry in ports]

    assert "8000" not in published
    assert {"80", "443"} <= set(published)
    assert "!override" in TLS_COMPOSE_PATH.read_text(), (
        "without the tag compose merges rather than replaces, and 8000 stays "
        "published"
    )


def test_tls_certificates_are_required_rather_than_defaulted(
    tls_compose: dict,
) -> None:
    """A default certificate path is a deployment that starts without TLS.

    Both the hostname and the directory have to come from the operator: nginx
    fails to start on a missing certificate, which is the right failure, but
    only if nothing quietly substitutes a path that happens to exist.
    """
    edge = tls_compose["services"]["edge"]
    required = str(edge["environment"]["SPYGLASS_STORE_EDGE_SERVER_NAME"])

    assert ":?" in required
    assert any(":?" in str(volume) for volume in edge["volumes"])


def test_plain_http_redirects_without_losing_the_request(
    templates: dict,
) -> None:
    """Both login endpoints are POSTs.

    A 301 or 302 lets a client turn the POST into a GET, and the failure
    surfaces as an endpoint that does not work rather than as a redirect. 308
    preserves the method and body.
    """
    tls = templates["tls.conf.template"]

    assert "return 308 https://" in tls
    assert "listen 80 default_server;" in tls, (
        "the image's own stock server answers port 80 for any other hostname; "
        "without default_server it serves a welcome page where this redirect "
        "belongs"
    )


def test_hsts_survives_the_headers_each_location_sets(proxy: str) -> None:
    """nginx does not inherit `add_header` into a location that sets its own.

    Both rate-limited locations set `Retry-After`, so a server-level HSTS
    header silently disappears from exactly the endpoints a client talks to
    first. Every location has to set it, and the value is a map on `$scheme` so
    the plain listener sends nothing.
    """
    blocks = _locations(proxy)

    assert blocks, "no location blocks found; the parser or the file moved"

    for match, body in blocks.items():
        assert "Strict-Transport-Security $hsts_header" in body, (
            f"location {match} would answer over TLS without HSTS"
        )


def test_hsts_is_not_claimed_over_plain_http(templates: dict) -> None:
    """An HSTS header on an http:// response is a promise nothing keeps.

    The map returns an empty value off TLS, and `add_header` with an empty
    value emits nothing.
    """
    limits = templates["limits.conf.template"]

    assert "map $scheme $hsts_header" in limits
    assert 'default ""' in limits


# --------------------------- the origin constraint ---------------------------


def test_the_edge_does_not_rewrite_the_content_redirect(proxy: str) -> None:
    """The 302 points at another origin on purpose.

    `proxy_redirect` rewriting that Location to the broker's own origin would
    make clients keep `Authorization` across it, and the object store answers
    those with a complaint about a missing `x-amz-content-sha256` — which
    names a checksum rather than the authentication it is really about.
    """
    assert "proxy_redirect off;" in proxy


def test_the_edge_does_not_serve_the_object_store(proxy: str) -> None:
    """Same constraint, from the other direction.

    Putting the store behind this proxy would give the two one origin, which
    is the natural thing to reach for on a single host and breaks every read.
    """
    assert "location /objects" not in proxy
    assert "proxy_pass" in proxy
    assert all(
        target.strip().startswith("http://broker")
        for target in proxy.split("proxy_pass ")[1:]
    )


def test_the_object_store_console_is_not_published_broadly(
    compose: dict,
) -> None:
    """It administers the credential that can write every object.

    The store's data port is published on purpose — clients follow presigned
    URLs to it. Its console is not the same thing.
    """
    for entry in compose["services"]["store"]["ports"]:
        if str(entry).endswith("9001"):
            assert str(entry).startswith("127.0.0.1:"), (
                f"the MinIO console is published as {entry}; bind it to "
                "loopback"
            )


# --------------------------- staying up ---------------------------


def test_the_edge_waits_for_a_broker_that_works(compose: dict) -> None:
    """nginx resolves its upstream when it loads its configuration.

    An edge that starts first answers 502 until something restarts it, and
    `depends_on` without a condition only waits for the container to exist.
    """
    depends = compose["services"]["edge"]["depends_on"]

    assert depends["broker"]["condition"] == "service_healthy"
    assert "healthcheck" in compose["services"]["broker"], (
        "the condition above is only as good as the check behind it"
    )


def test_long_running_services_restart(compose: dict) -> None:
    """A broker that exits on a transient fault should come back.

    Not the bucket-creation job, though: it exits 0 by design, and restarting
    it forever would leave the deployment looking permanently unhealthy.
    """
    services = compose["services"]

    for name in ("broker", "edge", "store"):
        assert services[name].get("restart") == "unless-stopped", name

    assert services["createbucket"].get("restart") == "no"
