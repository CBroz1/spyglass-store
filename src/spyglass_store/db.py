"""Database access discipline: one connection, one caller at a time.

DataJoint hands out a single `Connection` shared by every module — `dj.conn()`
caches it on the function itself, with no thread-local and no lock anywhere in
the class. FastAPI runs synchronous route handlers on AnyIO's worker threadpool
(forty threads by default), so without something here, concurrent requests
interleave on one MySQL cursor.

That failure does not show up in tests: `TestClient` drives requests serially.
It shows up in production as intermittent, unreproducible corruption of
whichever query lost the race, which is the worst way to find out.

Serializing is the conservative fix, and the right one at this scale: the
broker's queries are small and indexed, the object bytes never pass through it,
and a request spends most of its life waiting on GitHub or S3 rather than on
MySQL. A connection pool is the answer if that stops being true — the lock is
the thing to measure against, not a permanent ceiling.
"""

from __future__ import annotations

import functools
import threading
from datetime import datetime, timedelta

#: Reentrant: `identity_for_token` resolves teams through `lab`, which queries
#: again while the outer call still holds it.
_DB_LOCK = threading.RLock()


def serialized(func):
    """Run `func` with exclusive use of the shared DataJoint connection.

    Parameters
    ----------
    func : callable
        A function that queries the database.

    Returns
    -------
    callable
        The same function, guarded.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with _DB_LOCK:
            return func(*args, **kwargs)

    return wrapper


@serialized
def db_now() -> datetime:
    """Return the database server's current time.

    The broker compares against `timestamp` columns that MySQL writes itself.
    Asking the broker's own host instead mixes two clocks: `datetime.now()` is
    naive and local, MySQL stores UTC and returns the session time zone, and a
    UTC container against a non-UTC server slides every window by hours — in
    the permissive direction half the time.

    One clock, and it is the one that wrote the rows.

    Returns
    -------
    datetime
        Server time, naive, in the session time zone — directly comparable to
        the timestamps stored in the broker's tables.
    """
    import datajoint as dj

    cursor = dj.conn().query("SELECT CURRENT_TIMESTAMP")

    return cursor.fetchone()[0]


def window_start(hours: int) -> datetime:
    """Return the start of a rolling window, on the database's clock.

    Parameters
    ----------
    hours : int
        Length of the window.

    Returns
    -------
    datetime
    """
    return db_now() - timedelta(hours=hours)
