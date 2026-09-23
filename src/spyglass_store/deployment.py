"""Checks that run once, at boot, so a user is not the one who finds out.

A wrong bucket, a renamed Spyglass column, or a proxy that puts the broker and
the object store on one hostname all produce confusing failures much later and
to someone else. Every one of them is knowable at startup, and a service that
answers `/healthz` should already have proved it can do its job — which is why
the health endpoint does not re-probe any of this.

The origin comparison is here rather than with the routes because it is a
property of the deployment, not of a request: nothing at runtime can fix it,
and the only thing the code can do is say so loudly while someone is still
watching the logs.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from spyglass_store.lab import verify_lab_schema
from spyglass_store.settings import Settings


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
