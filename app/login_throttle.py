"""Persistent login throttling per verified source address and per (address, username).

Each attempt reserves a slot atomically before the password is checked, so concurrent requests cannot exceed the
limit.  The reservation records which window it counted in; settling it (success hands the slot back, an internal
error cancels it) only touches that same window.  Password hashing never runs under the write lock.

When the visitor address cannot be established (an unexpected proxy hop), the shared source bucket is skipped so
one attacker cannot lock every visitor out; the per-account bucket still applies.
"""
from __future__ import annotations

import hashlib
import time
from contextlib import closing
from dataclasses import dataclass

from app.db import connect

WINDOW_SECONDS = 15 * 60
MAX_FAILURES_PER_ACCOUNT = 8
MAX_FAILURES_PER_SOURCE = 40


def init_login_throttle_schema(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS login_throttle (
            bucket_hash TEXT PRIMARY KEY,
            window_started_at INTEGER NOT NULL,
            failures INTEGER NOT NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_login_throttle_window ON login_throttle(window_started_at)")


@dataclass(frozen=True)
class Reservation:
    source: tuple[str, int] | None  # (bucket, window_started_at)
    account: tuple[str, int]


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(("login",) + parts).encode("utf-8")).hexdigest()


def _buckets(username: str, source_ip: str | None, verified: bool) -> list[tuple[str, int, str]]:
    source = source_ip or "-"
    buckets = [(_digest("account", source, username.strip().lower()), MAX_FAILURES_PER_ACCOUNT, "account")]
    if verified:
        buckets.insert(0, (_digest("source", source), MAX_FAILURES_PER_SOURCE, "source"))
    return buckets


def reserve_login_attempt(username: str, source_ip: str | None, verified: bool = True) -> Reservation | None:
    """Atomically check the buckets and count this attempt; None means the caller must refuse it."""
    now = int(time.time())
    windows: dict[str, tuple[str, int]] = {}
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        plan = []
        for bucket, limit, kind in _buckets(username, source_ip, verified):
            row = conn.execute("SELECT window_started_at, failures FROM login_throttle WHERE bucket_hash=?", (bucket,)).fetchone()
            live = row is not None and now - row["window_started_at"] < WINDOW_SECONDS
            if live and row["failures"] >= limit:
                conn.rollback()
                return None
            plan.append((bucket, kind, row["window_started_at"] if live else now, live))
        for bucket, kind, window, live in plan:
            if live:
                conn.execute("UPDATE login_throttle SET failures = failures + 1 WHERE bucket_hash=? AND window_started_at=?", (bucket, window))
            else:
                conn.execute("INSERT OR REPLACE INTO login_throttle(bucket_hash, window_started_at, failures) VALUES (?,?,1)", (bucket, window))
            windows[kind] = (bucket, window)
        conn.execute("DELETE FROM login_throttle WHERE window_started_at < ?", (now - WINDOW_SECONDS,))
        conn.commit()
    return Reservation(source=windows.get("source"), account=windows["account"])


def _decrement(conn, slot: tuple[str, int] | None) -> None:
    if slot:
        conn.execute("UPDATE login_throttle SET failures = MAX(failures - 1, 0) WHERE bucket_hash=? AND window_started_at=?", slot)


def release_login_attempt(reservation: Reservation) -> None:
    """Successful sign-in: clear the account's failures in the reserved window and return the source slot."""
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM login_throttle WHERE bucket_hash=? AND window_started_at=?", reservation.account)
        _decrement(conn, reservation.source)
        conn.commit()


def cancel_login_attempt(reservation: Reservation) -> None:
    """Internal error during authentication: undo only this attempt's increments, keep earlier failures."""
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        _decrement(conn, reservation.account)
        _decrement(conn, reservation.source)
        conn.commit()
