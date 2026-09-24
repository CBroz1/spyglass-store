"""Admin CLI: accounts, files, audit queries, reconciliation.

The point of this tool is that routine operations need no direct SQL. Every
command here wraps a `registry` function that the service itself uses, so the
CLI and the running broker cannot disagree about what an operation means.

Two deliberate limits:

- **Reconciliation reports; it never deletes.** Comparing a registry against a
  store is a diagnosis, and acting on it is a separate reviewed decision. A
  tool that cleaned up automatically would eventually delete something during
  an outage that made a healthy object look orphaned.
- **It talks to the database directly, not to the HTTP API.** An admin is not
  a broker client and has no broker token; the database is the system of
  record, and an operator needs to reach it when the service is down.

Configuration is the same as the service's: DataJoint's own connection
settings, and `SPYGLASS_STORE_*` for everything else.
"""

from __future__ import annotations

import argparse
import sys

from spyglass_store.access import Tier


def _store(args):
    """Return the object store to inspect.

    Built from settings unless one was injected. Constructed lazily, so
    commands that only read the database still work on a host with no object
    store credentials — which is the common case for an admin shell.
    """
    if getattr(args, "store", None) is not None:
        return args.store

    from spyglass_store.s3 import S3ObjectStore

    return S3ObjectStore()


def _accounts_list(args) -> int:
    """Print every account."""
    from spyglass_store import registry

    rows = registry.accounts()

    if not rows:
        print("No accounts.")
        return 0

    print(f"{'ID':>4}  {'LOGIN':<20} {'TIER':<11} {'MEMBER':<20} STATUS")
    for account in rows:
        print(
            f"{account.account_id:>4}  {account.github_login:<20} "
            f"{account.tier:<11} {account.lab_member_name or '-':<20} "
            f"{'suspended' if account.suspended else 'active'}"
        )

    return 0


def _require_account(login: str):
    """Return the account for a login, or exit with a message."""
    from spyglass_store import registry

    account = registry.account_by_login(login)

    if account is None:
        sys.exit(f"No account for GitHub login {login!r}.")

    return account


def _account_show(args) -> int:
    """Print one account with its teams and recent volume."""
    from spyglass_store import registry
    from spyglass_store.lab import teams_for_github
    from spyglass_store.settings import get_settings

    account = _require_account(args.login)
    window = get_settings().quota_window_hours
    teams = sorted(teams_for_github(account.github_login))

    print(f"account_id   {account.account_id}")
    print(f"github       {account.github_login} (id {account.github_id})")
    print(f"lab member   {account.lab_member_name or '-'}")
    print(f"tier         {account.tier}")
    print(f"status       {'suspended' if account.suspended else 'active'}")
    print(f"teams        {', '.join(teams) if teams else '-'}")

    for action, label in (("read", "downloaded"), ("register", "uploaded")):
        usage = registry.usage_since(account.account_id, window, action)
        gb = usage.total_bytes / 1024**3
        print(f"{label:<12} {gb:.2f} GB in the last {window}h")

    print(f"files        {len(registry.files_for_owner(account.account_id))}")

    return 0


def _account_set_tier(args) -> int:
    """Change what an account is trusted to do."""
    from spyglass_store import registry

    account = _require_account(args.login)
    registry.set_tier(account.account_id, args.tier)
    print(f"{args.login}: {account.tier} -> {args.tier}")

    return 0


def _account_suspend(args) -> int:
    """Suspend or reinstate an account."""
    from spyglass_store import registry

    account = _require_account(args.login)
    registry.set_suspended(account.account_id, not args.undo)

    if args.undo:
        print(f"{args.login} reinstated; existing tokens work again.")
    else:
        print(
            f"{args.login} suspended. Every live token stops working on its "
            "next request, and logging in again is refused."
        )

    return 0


def _account_revoke(args) -> int:
    """Invalidate every token an account holds."""
    from spyglass_store import registry

    account = _require_account(args.login)
    count = registry.revoke_tokens(account.account_id)
    print(f"{args.login}: revoked {count} token(s). They can log in again.")

    return 0


def _files_list(args) -> int:
    """Print files, optionally restricted to one owner."""
    from spyglass_store import registry

    if args.owner:
        account = _require_account(args.owner)
        files = registry.files_for_owner(account.account_id)
    else:
        files = registry.all_files()

    if not files:
        print("No files.")
        return 0

    print(f"{'FILE_ID':<34}{'CLASS':<10}{'SIZE':>12}  NAME")
    for file in files:
        mb = file.size_bytes / 1024**2
        print(
            f"{file.file_id:<34}{file.file_class:<10}{mb:>10.1f}MB  "
            f"{file.spyglass_name}"
        )

    return 0


def _file_show(args) -> int:
    """Print one file's grants and whether its bytes have arrived."""
    from spyglass_store import registry
    from spyglass_store.storage import object_key

    file = registry.file_by_id(args.file_id)

    if file is None:
        sys.exit(f"No file {args.file_id!r}.")

    rules = registry.rules_for_file(file.file_id)
    present = _store(args).exists(object_key(file.sha256))

    print(f"file_id      {file.file_id}")
    print(f"name         {file.spyglass_name}")
    print(f"class        {file.file_class}")
    print(f"sha256       {file.sha256}")
    if file.parent:
        print(f"derived from {file.parent}")
    print(f"size         {file.size_bytes / 1024**2:.1f} MB (declared)")
    print(f"owner        account {file.owner}")
    print(f"uploaded     {'yes' if present else 'no — bytes not in the store'}")

    if not rules:
        print("visibility   private (no grants)")
    else:
        for rule in rules:
            target = rule.principal or "everyone"
            print(f"grant        {rule.principal_type.value}: {target}")

    return 0


def _audit(args) -> int:
    """Print recent permission decisions."""
    from spyglass_store import registry

    account_id = None
    if args.login:
        account_id = _require_account(args.login).account_id

    rows = registry.recent_access(account_id, args.hours)

    if not rows:
        print(f"No activity in the last {args.hours}h.")
        return 0

    print(f"{'WHEN':<20}{'ACCT':>5}  {'ACTION':<10}{'OK':<4}{'SIZE':>10}  IP")
    for row in rows[: args.limit]:
        size = f"{int(row['size_bytes']) / 1024**2:.1f}MB"
        print(
            f"{str(row['timestamp']):<20}"
            f"{row['account_id'] or '-':>5}  "
            f"{row['action']:<10}"
            f"{'yes' if row['granted'] else 'NO':<4}"
            f"{size:>10}  {row['source_ip']}"
        )

    if len(rows) > args.limit:
        print(f"... {len(rows) - args.limit} more; raise --limit to see them.")

    return 0


def _top(args) -> int:
    """Print the accounts that moved the most data."""
    from spyglass_store import registry

    totals: dict[str, int] = {}
    for row in registry.recent_access(None, args.hours):
        if row["action"] != "read" or not row["granted"]:
            continue
        if row["account_id"] is None:
            continue
        key = str(row["account_id"])
        totals[key] = totals.get(key, 0) + int(row["size_bytes"])

    if not totals:
        print(f"No reads in the last {args.hours}h.")
        return 0

    by_id = {a.account_id: a.github_login for a in registry.accounts()}

    print(f"{'LOGIN':<20}{'GB':>10}")
    for account_id, total in sorted(
        totals.items(), key=lambda kv: kv[1], reverse=True
    )[: args.limit]:
        print(
            f"{by_id.get(account_id, account_id):<20}{total / 1024**3:>10.2f}"
        )

    return 0


def _reconcile(args) -> int:
    """Compare the registry against the object store.

    Reports only. Cleanup is a separate, reviewed operation — an outage that
    made healthy objects unreadable would otherwise look like a corpus of
    orphans to delete.
    """
    from spyglass_store import registry
    from spyglass_store.storage import object_key

    store = _store(args)
    files = registry.all_files()
    expected = {object_key(f.sha256): f for f in files}

    missing = [file for key, file in expected.items() if not store.exists(key)]

    print(
        f"{len(files)} registered file(s), {len(expected)} distinct object(s)"
    )

    if missing:
        print(f"\n{len(missing)} registration(s) with no bytes in the store:")
        for file in missing:
            print(f"  {file.file_id}  {file.spyglass_name}")
        print(
            "\n  An upload that never finished, or one still running. Uploads "
            "are expected to be slow, so a recent one is not a fault."
        )

    try:
        present = set(store.iter_keys("spyglass/"))
    except Exception as err:  # noqa: BLE001 - a listing is best effort
        print(f"\nCould not list the store, so orphans are unknown: {err}")
        return 1 if missing else 0

    orphans = sorted(present - set(expected))

    if orphans:
        print(f"\n{len(orphans)} object(s) with no registration:")
        for key in orphans[:20]:
            print(f"  {key}")
        if len(orphans) > 20:
            print(f"  ... and {len(orphans) - 20} more")
        print(
            "\n  Storage nobody references. Verify before removing anything: "
            "a registration deleted by mistake looks exactly like this."
        )

    if not missing and not orphans:
        print("\nRegistry and store agree.")

    return 1 if (missing or orphans) else 0


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for the admin CLI."""
    parser = argparse.ArgumentParser(
        prog="spyglass-store",
        description="Administer a spyglass-store broker.",
    )
    sub = parser.add_subparsers(dest="group", required=True)

    account = sub.add_parser("account", help="accounts and tiers")
    account_sub = account.add_subparsers(dest="command", required=True)

    account_sub.add_parser("list", help="list accounts").set_defaults(
        func=_accounts_list
    )

    show = account_sub.add_parser("show", help="one account in detail")
    show.add_argument("login", help="GitHub login")
    show.set_defaults(func=_account_show)

    tier = account_sub.add_parser("set-tier", help="change trust level")
    tier.add_argument("login")
    tier.add_argument("tier", choices=[t.value for t in Tier])
    tier.set_defaults(func=_account_set_tier)

    suspend = account_sub.add_parser(
        "suspend", help="stop an account using the broker"
    )
    suspend.add_argument("login")
    suspend.add_argument(
        "--undo", action="store_true", help="reinstate instead"
    )
    suspend.set_defaults(func=_account_suspend)

    revoke = account_sub.add_parser(
        "revoke-tokens", help="invalidate an account's credentials"
    )
    revoke.add_argument("login")
    revoke.set_defaults(func=_account_revoke)

    file_group = sub.add_parser("file", help="registered files")
    file_sub = file_group.add_subparsers(dest="command", required=True)

    listing = file_sub.add_parser("list", help="list files")
    listing.add_argument("--owner", help="restrict to one GitHub login")
    listing.set_defaults(func=_files_list)

    inspect = file_sub.add_parser("show", help="one file and its grants")
    inspect.add_argument("file_id")
    inspect.set_defaults(func=_file_show)

    audit = sub.add_parser("audit", help="recent permission decisions")
    audit.add_argument("--login", help="restrict to one account")
    audit.add_argument("--hours", type=int, default=24)
    audit.add_argument("--limit", type=int, default=50)
    audit.set_defaults(func=_audit)

    top = sub.add_parser("top", help="accounts that moved the most data")
    top.add_argument("--hours", type=int, default=24)
    top.add_argument("--limit", type=int, default=10)
    top.set_defaults(func=_top)

    reconcile = sub.add_parser(
        "reconcile",
        help="compare the registry against the store (reports only)",
    )
    reconcile.set_defaults(func=_reconcile)

    return parser


def main(argv: list[str] | None = None, store=None) -> int:
    """Entry point.

    Parameters
    ----------
    argv : list of str, optional
        Arguments. Defaults to the process arguments.
    store : ObjectStore, optional
        Injected by tests. Built from settings when omitted, and only for the
        commands that need it.

    Returns
    -------
    int
        Process exit status. `reconcile` returns 1 when it found a
        discrepancy, so it can gate a scheduled check.
    """
    args = build_parser().parse_args(argv)
    args.store = store

    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
