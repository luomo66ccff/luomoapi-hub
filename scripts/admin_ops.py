#!/usr/bin/env python3
import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DB_PATH = os.getenv("DATABASE_PATH", "data/luomoapi.db")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect():
    if not Path(DB_PATH).exists():
        raise SystemExit(f"Database not found: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def print_row(row, fields):
    for key in fields:
        value = row[key] if key in row.keys() else None
        if value is None or value == "":
            value = "—"
        print(f"  {key}: {value}")


def cmd_stats(args):
    conn = connect()
    try:
        if not table_exists(conn, "public_gateway_routes"):
            print("public_gateway_routes table not found.")
            return

        documented = conn.execute(
            "SELECT COUNT(*) AS c FROM public_gateway_routes WHERE public_docs=1"
        ).fetchone()["c"]

        enabled = conn.execute(
            "SELECT COUNT(*) AS c FROM public_gateway_routes WHERE public_docs=1 AND enabled=1"
        ).fetchone()["c"]

        total = conn.execute(
            "SELECT COUNT(*) AS c FROM public_gateway_routes"
        ).fetchone()["c"]

        print("Public Route Stats")
        print(f"- total routes: {total}")
        print(f"- documented routes: {documented}")
        print(f"- enabled documented routes: {enabled}")
        print(f"- pending documented routes: {max(documented - enabled, 0)}")
    finally:
        conn.close()


def cmd_routes(args):
    conn = connect()
    try:
        if not table_exists(conn, "public_gateway_routes"):
            print("public_gateway_routes table not found.")
            return

        rows = conn.execute(
            """
            SELECT
                id,
                name,
                public_path,
                target_method,
                target_path,
                required_scope,
                enabled,
                public_docs,
                allow_anonymous,
                updated_at
            FROM public_gateway_routes
            ORDER BY id ASC
            """
        ).fetchall()

        if not rows:
            print("No public gateway routes found.")
            return

        for row in rows:
            status = "enabled" if row["enabled"] else "disabled"
            docs = "docs" if row["public_docs"] else "hidden"
            anonymous = "anonymous" if row["allow_anonymous"] else "key-required"

            print(f"[{row['id']}] {row['name']}")
            print(f"  status: {status} · {docs} · {anonymous}")
            print(f"  method: {row['target_method']}")
            print(f"  public_path: {row['public_path']}")
            print(f"  target_path: {row['target_path']}")
            print(f"  required_scope: {row['required_scope'] or '—'}")
            print(f"  updated_at: {row['updated_at'] or '—'}")
            print()
    finally:
        conn.close()


def cmd_enable_route(args):
    conn = connect()
    try:
        if not table_exists(conn, "public_gateway_routes"):
            print("public_gateway_routes table not found.")
            return

        row = conn.execute(
            "SELECT * FROM public_gateway_routes WHERE id=?",
            (args.route_id,),
        ).fetchone()

        if not row:
            print(f"Route not found: {args.route_id}")
            return

        print("About to enable route:")
        print_row(
            row,
            [
                "id",
                "name",
                "public_path",
                "target_method",
                "target_path",
                "required_scope",
                "enabled",
                "public_docs",
                "allow_anonymous",
            ],
        )

        if not args.yes:
            print()
            print("Dry run only. Re-run with --yes to enable this route.")
            return

        conn.execute(
            "UPDATE public_gateway_routes SET enabled=1, updated_at=? WHERE id=?",
            (now_iso(), args.route_id),
        )
        conn.commit()
        print(f"Route enabled: {args.route_id}")
    finally:
        conn.close()


def cmd_disable_route(args):
    conn = connect()
    try:
        if not table_exists(conn, "public_gateway_routes"):
            print("public_gateway_routes table not found.")
            return

        row = conn.execute(
            "SELECT * FROM public_gateway_routes WHERE id=?",
            (args.route_id,),
        ).fetchone()

        if not row:
            print(f"Route not found: {args.route_id}")
            return

        print("About to disable route:")
        print_row(
            row,
            [
                "id",
                "name",
                "public_path",
                "target_method",
                "target_path",
                "required_scope",
                "enabled",
            ],
        )

        if not args.yes:
            print()
            print("Dry run only. Re-run with --yes to disable this route.")
            return

        conn.execute(
            "UPDATE public_gateway_routes SET enabled=0, updated_at=? WHERE id=?",
            (now_iso(), args.route_id),
        )
        conn.commit()
        print(f"Route disabled: {args.route_id}")
    finally:
        conn.close()


def cmd_users(args):
    conn = connect()
    try:
        if not table_exists(conn, "users"):
            print("users table not found.")
            return

        rows = conn.execute(
            """
            SELECT id, username, email, role, status, usage_reason, created_at, last_login_at
            FROM users
            ORDER BY id ASC
            """
        ).fetchall()

        if not rows:
            print("No users found.")
            return

        for row in rows:
            print(f"[{row['id']}] {row['username']} <{row['email']}>")
            print(f"  role: {row['role']}")
            print(f"  status: {row['status']}")
            print(f"  usage_reason: {row['usage_reason'] or '—'}")
            print(f"  created_at: {row['created_at']}")
            print(f"  last_login_at: {row['last_login_at'] or '—'}")
            print()
    finally:
        conn.close()


def cmd_approve_user(args):
    conn = connect()
    try:
        if not table_exists(conn, "users"):
            print("users table not found.")
            return

        row = conn.execute(
            "SELECT id, username, email, role, status, usage_reason FROM users WHERE id=?",
            (args.user_id,),
        ).fetchone()

        if not row:
            print(f"User not found: {args.user_id}")
            return

        print("About to approve user:")
        print_row(row, ["id", "username", "email", "role", "status", "usage_reason"])

        if not args.yes:
            print()
            print("Dry run only. Re-run with --yes to approve this user.")
            return

        conn.execute(
            """
            UPDATE users
            SET status='active', updated_at=?
            WHERE id=?
            """,
            (now_iso(), args.user_id),
        )
        conn.commit()
        print(f"User approved: {args.user_id}")
    finally:
        conn.close()


def cmd_suspend_user(args):
    conn = connect()
    try:
        if not table_exists(conn, "users"):
            print("users table not found.")
            return

        row = conn.execute(
            "SELECT id, username, email, role, status FROM users WHERE id=?",
            (args.user_id,),
        ).fetchone()

        if not row:
            print(f"User not found: {args.user_id}")
            return

        print("About to suspend user:")
        print_row(row, ["id", "username", "email", "role", "status"])

        if not args.yes:
            print()
            print("Dry run only. Re-run with --yes to suspend this user.")
            return

        conn.execute(
            """
            UPDATE users
            SET status='suspended', updated_at=?
            WHERE id=?
            """,
            (now_iso(), args.user_id),
        )
        conn.commit()
        print(f"User suspended: {args.user_id}")
    finally:
        conn.close()


def cmd_key_requests(args):
    conn = connect()
    try:
        if not table_exists(conn, "api_key_requests"):
            print("api_key_requests table not found.")
            return

        rows = conn.execute(
            """
            SELECT
                r.id,
                r.user_id,
                u.username,
                r.name,
                r.requested_scopes,
                r.requested_reason,
                r.status,
                r.created_at,
                r.reviewed_at
            FROM api_key_requests r
            LEFT JOIN users u ON u.id = r.user_id
            ORDER BY r.id ASC
            """
        ).fetchall()

        if not rows:
            print("No API key requests found.")
            return

        for row in rows:
            print(f"[{row['id']}] {row['name']}")
            print(f"  user: {row['username'] or '—'} #{row['user_id']}")
            print(f"  status: {row['status']}")
            print(f"  requested_scopes: {row['requested_scopes'] or '—'}")
            print(f"  requested_reason: {row['requested_reason'] or '—'}")
            print(f"  created_at: {row['created_at']}")
            print(f"  reviewed_at: {row['reviewed_at'] or '—'}")
            print()
    finally:
        conn.close()



def cmd_api_keys(args):
    conn = connect()
    try:
        if not table_exists(conn, "api_keys"):
            print("api_keys table not found.")
            return

        rows = conn.execute(
            """
            SELECT
                k.id,
                k.user_id,
                u.username,
                k.name,
                k.key_prefix,
                k.status,
                k.scopes,
                k.allowed_routes,
                k.rate_limit_per_minute,
                k.daily_quota,
                k.monthly_quota,
                k.created_at,
                k.approved_at,
                k.revoked_at,
                k.last_used_at
            FROM api_keys k
            LEFT JOIN users u ON u.id = k.user_id
            ORDER BY k.id ASC
            """
        ).fetchall()

        if not rows:
            print("No API keys found.")
            return

        for row in rows:
            print(f"[{row['id']}] {row['name']}")
            print(f"  user: {row['username'] or '—'} #{row['user_id']}")
            print(f"  prefix: {row['key_prefix']}")
            print(f"  status: {row['status']}")
            print(f"  scopes: {row['scopes'] or '—'}")
            print(f"  allowed_routes: {row['allowed_routes'] or '—'}")
            print(f"  rate_limit_per_minute: {row['rate_limit_per_minute']}")
            print(f"  daily_quota: {row['daily_quota']}")
            print(f"  monthly_quota: {row['monthly_quota']}")
            print(f"  created_at: {row['created_at']}")
            print(f"  approved_at: {row['approved_at'] or '—'}")
            print(f"  revoked_at: {row['revoked_at'] or '—'}")
            print(f"  last_used_at: {row['last_used_at'] or '—'}")
            print()
    finally:
        conn.close()


def cmd_revoke_key(args):
    conn = connect()
    try:
        if not table_exists(conn, "api_keys"):
            print("api_keys table not found.")
            return

        row = conn.execute(
            """
            SELECT
                k.id,
                k.user_id,
                u.username,
                k.name,
                k.key_prefix,
                k.status,
                k.scopes,
                k.allowed_routes
            FROM api_keys k
            LEFT JOIN users u ON u.id = k.user_id
            WHERE k.id=?
            """,
            (args.key_id,),
        ).fetchone()

        if not row:
            print(f"API key not found: {args.key_id}")
            return

        print("About to revoke API key:")
        print_row(row, ["id", "username", "name", "key_prefix", "status", "scopes", "allowed_routes"])

        if not args.yes:
            print()
            print("Dry run only. Re-run with --yes to revoke this key.")
            return

        conn.execute(
            """
            UPDATE api_keys
            SET status='revoked', revoked_at=?
            WHERE id=?
            """,
            (now_iso(), args.key_id),
        )
        conn.commit()
        print(f"API key revoked: {args.key_id}")
    finally:
        conn.close()


def cmd_usage_logs(args):
    conn = connect()
    try:
        if not table_exists(conn, "api_usage_logs"):
            print("api_usage_logs table not found.")
            return

        rows = conn.execute(
            """
            SELECT
                id,
                created_at,
                user_id,
                api_key_id,
                public_path,
                status_code,
                success,
                error_summary
            FROM api_usage_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (args.limit,),
        ).fetchall()

        if not rows:
            print("No usage logs found.")
            return

        for row in rows:
            print(f"[{row['id']}] {row['created_at']}")
            print(f"  user_id: {row['user_id'] or '—'}")
            print(f"  api_key_id: {row['api_key_id'] or '—'}")
            print(f"  public_path: {row['public_path']}")
            print(f"  status_code: {row['status_code']}")
            print(f"  success: {row['success']}")
            print(f"  error_summary: {row['error_summary'] or '—'}")
            print()
    finally:
        conn.close()


def build_parser():
    parser = argparse.ArgumentParser(
        description="LuomoAPI Hub safe admin operations"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("stats", help="Show public route stats")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("routes", help="List public gateway routes")
    p.set_defaults(func=cmd_routes)

    p = sub.add_parser("enable-route", help="Enable a public route")
    p.add_argument("route_id", type=int)
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_enable_route)

    p = sub.add_parser("disable-route", help="Disable a public route")
    p.add_argument("route_id", type=int)
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_disable_route)

    p = sub.add_parser("users", help="List users")
    p.set_defaults(func=cmd_users)

    p = sub.add_parser("approve-user", help="Approve a pending user")
    p.add_argument("user_id", type=int)
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_approve_user)

    p = sub.add_parser("suspend-user", help="Suspend a user")
    p.add_argument("user_id", type=int)
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_suspend_user)

    p = sub.add_parser("key-requests", help="List API key requests")
    p.set_defaults(func=cmd_key_requests)

    p = sub.add_parser("api-keys", help="List API keys")
    p.set_defaults(func=cmd_api_keys)

    p = sub.add_parser("revoke-key", help="Revoke an API key")
    p.add_argument("key_id", type=int)
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_revoke_key)

    p = sub.add_parser("usage-logs", help="List recent API usage logs")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_usage_logs)


    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
