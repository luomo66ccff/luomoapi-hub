"""Integer credit accounting. Mutations join the caller's IMMEDIATE transaction.

No function in this module begins, commits, or rolls back a transaction. Gateway
callers must reserve usage and credits together, close the connection before
network I/O, then complete usage and settle credits together on a new connection.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any

UNITS_PER_CREDIT = 1_000_000
CREDITS_PER_CNY = 100
CREDITS_PER_USD = 720
MAX_UNITS = 9_223_372_036_854_775_807
REDEEM_LIMIT = 5
REDEEM_WINDOW_SECONDS = 900


class CreditError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status
        self.status_code = status


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def amount_to_units(value: str | Decimal | int, currency: str = "credits") -> int:
    """Reject floats, non-finite values, rounding and SQLite integer overflow."""
    if isinstance(value, bool) or not isinstance(value, (str, Decimal, int)):
        raise CreditError("invalid_amount", "金额必须是精确的十进制字符串。")
    if isinstance(value, str):
        value = value.strip()
        if len(value) > 40 or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
            raise CreditError("invalid_amount", "请输入非负十进制金额，不支持科学计数法。")
    multiplier = {"credits": UNITS_PER_CREDIT, "cny": CREDITS_PER_CNY * UNITS_PER_CREDIT,
                  "usd": CREDITS_PER_USD * UNITS_PER_CREDIT}.get(currency.lower())
    if multiplier is None:
        raise CreditError("invalid_currency", "不支持的金额单位。")
    try:
        with localcontext() as context:
            context.prec = 80
            amount = Decimal(value)
            if not amount.is_finite() or amount < 0 or amount > Decimal(MAX_UNITS) / multiplier:
                raise CreditError("invalid_amount", "金额超出允许范围。")
            if amount.as_tuple().exponent < -40 or len(amount.as_tuple().digits) > 40:
                raise CreditError("invalid_amount", "金额精度超出允许范围。")
            units = amount * multiplier
            if units != units.to_integral_value():
                raise CreditError("invalid_amount", "金额精度不能小于 0.000001 积分。")
            return int(units)
    except (InvalidOperation, OverflowError, ValueError):
        raise CreditError("invalid_amount", "金额格式不正确。") from None


def credits_to_units(value: str | Decimal | int) -> int:
    return amount_to_units(value)


def cny_to_units(value: str | Decimal | int) -> int:
    return amount_to_units(value, "cny")


def usd_to_units(value: str | Decimal | int) -> int:
    return amount_to_units(value, "usd")


def units_to_credits(units: int) -> str:
    sign = "-" if units < 0 else ""
    whole, fraction = divmod(abs(units), UNITS_PER_CREDIT)
    return sign + str(whole) + ("." + f"{fraction:06d}".rstrip("0") if fraction else "")


def _units(value: int, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (1 if positive else 0) or value > MAX_UNITS:
        raise CreditError("invalid_amount", "金额必须是允许范围内的整数最小单位。")
    return value


def _tx(conn: sqlite3.Connection) -> None:
    if not conn.in_transaction:
        raise CreditError("transaction_required", "积分写入必须使用调用方的 BEGIN IMMEDIATE 事务。", 500)


def _one(conn: sqlite3.Connection, query: str, params: tuple = ()) -> dict | None:
    cursor = conn.execute(query, params)
    row = cursor.fetchone()
    return dict(zip((column[0] for column in cursor.description), row)) if row is not None else None


def _text(value: str, label: str, *, limit: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise CreditError("invalid_argument", f"{label}不能为空且长度不能超过 {limit}。")
    return value.strip()


def _json(value: str | None, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    def reject_constant(_value):
        raise ValueError("non-finite JSON number")
    try:
        if not isinstance(value, str) or len(value) > 65536 or not isinstance(json.loads(value,parse_float=Decimal,parse_constant=reject_constant), dict):
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise CreditError("invalid_snapshot", "计价或用量快照必须是有效的 JSON 对象。") from None
    return value


_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS credit_wallets (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        balance_units INTEGER NOT NULL DEFAULT 0 CHECK(typeof(balance_units)='integer' AND balance_units>=0),
        reserved_units INTEGER NOT NULL DEFAULT 0 CHECK(typeof(reserved_units)='integer' AND reserved_units>=0 AND reserved_units<=balance_units),
        updated_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS credit_holds (
        usage_id INTEGER PRIMARY KEY REFERENCES api_usage_logs(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        amount_units INTEGER NOT NULL CHECK(typeof(amount_units)='integer' AND amount_units>=0),
        status TEXT NOT NULL CHECK(status IN ('held','reconciliation_required','settled','released')),
        dispatch_state TEXT NOT NULL DEFAULT 'reserved' CHECK(dispatch_state IN ('reserved','dispatched')),
        dispatched_at TEXT,
        actual_units INTEGER CHECK(actual_units IS NULL OR (typeof(actual_units)='integer' AND actual_units>=0)),
        pricing_snapshot TEXT NOT NULL, usage_json TEXT, reason TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS credit_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
        reference TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
        delta_units INTEGER NOT NULL CHECK(typeof(delta_units)='integer'),
        delta_reserved_units INTEGER NOT NULL DEFAULT 0 CHECK(typeof(delta_reserved_units)='integer'),
        balance_after_units INTEGER NOT NULL CHECK(typeof(balance_after_units)='integer' AND balance_after_units>=0),
        reserved_after_units INTEGER NOT NULL CHECK(typeof(reserved_after_units)='integer' AND reserved_after_units>=0 AND reserved_after_units<=balance_after_units),
        usage_id INTEGER REFERENCES api_usage_logs(id), actor_id INTEGER REFERENCES users(id),
        note TEXT NOT NULL, created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS credit_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL UNIQUE, code_tail TEXT NOT NULL,
        amount_units INTEGER NOT NULL CHECK(typeof(amount_units)='integer' AND amount_units>0),
        status TEXT NOT NULL CHECK(status IN ('active','redeemed','revoked')),
        expires_at TEXT, created_at TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id),
        note TEXT NOT NULL, issue_reference TEXT NOT NULL UNIQUE,
        redeemed_by INTEGER REFERENCES users(id), redeemed_at TEXT, revoked_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS credit_code_attempts (
        user_id INTEGER PRIMARY KEY REFERENCES users(id), window_started_at TEXT NOT NULL,
        attempt_count INTEGER NOT NULL CHECK(attempt_count>=0))""",
    """CREATE TABLE IF NOT EXISTS credit_admin_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL UNIQUE,
        actor_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id), usage_id INTEGER REFERENCES api_usage_logs(id),
        code_id INTEGER REFERENCES credit_codes(id), amount_units INTEGER,
        reason TEXT NOT NULL, created_at TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_credit_holds_user_status ON credit_holds(user_id,status)",
    "CREATE INDEX IF NOT EXISTS idx_credit_holds_status_created ON credit_holds(status,created_at)",
    "CREATE INDEX IF NOT EXISTS idx_credit_ledger_user_id ON credit_ledger(user_id,id)",
    """CREATE TRIGGER IF NOT EXISTS credit_ledger_no_update BEFORE UPDATE ON credit_ledger
        BEGIN SELECT RAISE(ABORT, 'credit ledger is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS credit_ledger_no_delete BEFORE DELETE ON credit_ledger
        BEGIN SELECT RAISE(ABORT, 'credit ledger is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS credit_audit_no_update BEFORE UPDATE ON credit_admin_audit
        BEGIN SELECT RAISE(ABORT, 'credit audit is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS credit_audit_no_delete BEFORE DELETE ON credit_admin_audit
        BEGIN SELECT RAISE(ABORT, 'credit audit is immutable'); END""",
)


def initialize_credit_schema(conn: sqlite3.Connection) -> None:
    """Additive migration; old usage stays unbilled and old wallets start at zero."""
    for statement in _SCHEMA:
        conn.execute(statement)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(api_usage_logs)")}
    additions = {
        "credit_status": "TEXT NOT NULL DEFAULT 'legacy_unbilled'",
        "credit_reserved_units": "INTEGER NOT NULL DEFAULT 0 CHECK(credit_reserved_units>=0)",
        "credit_charged_units": "INTEGER NOT NULL DEFAULT 0 CHECK(credit_charged_units>=0)",
        "credit_pricing_snapshot": "TEXT", "credit_usage_json": "TEXT", "credit_reason": "TEXT",
    }
    for name, declaration in additions.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE api_usage_logs ADD COLUMN {name} {declaration}")
    hold_columns={row[1] for row in conn.execute("PRAGMA table_info(credit_holds)")}
    for name,declaration in {"dispatch_state":"TEXT NOT NULL DEFAULT 'reserved' CHECK(dispatch_state IN ('reserved','dispatched'))","dispatched_at":"TEXT"}.items():
        if name not in hold_columns:
            conn.execute(f"ALTER TABLE credit_holds ADD COLUMN {name} {declaration}")
    conn.execute("INSERT OR IGNORE INTO credit_wallets(user_id,balance_units,reserved_units,updated_at) SELECT id,0,0,? FROM users", (now_iso(),))


def _wallet(conn: sqlite3.Connection, user_id: int) -> dict:
    if not _one(conn, "SELECT id FROM users WHERE id=?", (user_id,)):
        raise CreditError("user_not_found", "用户不存在。", 404)
    conn.execute("INSERT OR IGNORE INTO credit_wallets(user_id,updated_at) VALUES (?,?)", (user_id, now_iso()))
    return _one(conn, "SELECT * FROM credit_wallets WHERE user_id=?", (user_id,))


def wallet_snapshot(conn: sqlite3.Connection, user_id: int) -> dict:
    wallet = _one(conn, "SELECT * FROM credit_wallets WHERE user_id=?", (user_id,))
    balance = wallet["balance_units"] if wallet else 0
    reserved = wallet["reserved_units"] if wallet else 0
    risk = pending_overrun_units(conn,user_id)
    available = balance-reserved-risk
    return {"balance_units": balance, "reserved_units": reserved, "risk_units": risk, "available_units": available,
            "balance_credits": units_to_credits(balance), "reserved_credits": units_to_credits(reserved),
            "risk_credits": units_to_credits(risk), "available_credits": units_to_credits(available)}


def _audit(conn, *, reference, actor_id, action, reason, user_id=None, usage_id=None, code_id=None, amount_units=None):
    conn.execute("""INSERT INTO credit_admin_audit(reference,actor_id,action,user_id,usage_id,code_id,amount_units,reason,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""", (reference,actor_id,action,user_id,usage_id,code_id,amount_units,reason,now_iso()))


def add_credit(conn: sqlite3.Connection, user_id: int, amount_units: int, *, reference: str,
               actor_id: int | None, kind: str, note: str) -> dict:
    _tx(conn)
    _units(amount_units, positive=True)
    reference, kind, note = _text(reference, "reference", limit=200), _text(kind, "资金类型", limit=40), _text(note, "理由")
    previous = _one(conn, "SELECT * FROM credit_ledger WHERE reference=?", (reference,))
    if previous:
        if (previous["user_id"],previous["delta_units"],previous["actor_id"],previous["kind"],previous["note"]) != (user_id,amount_units,actor_id,kind,note):
            raise CreditError("reference_conflict", "此操作编号已用于不同的加分内容。", 409)
        return previous
    wallet = _wallet(conn, user_id)
    if wallet["balance_units"] > MAX_UNITS-amount_units:
        raise CreditError("balance_overflow", "余额超出允许范围。", 409)
    conn.execute("UPDATE credit_wallets SET balance_units=balance_units+?,updated_at=? WHERE user_id=?", (amount_units,now_iso(),user_id))
    cursor = conn.execute("""INSERT INTO credit_ledger(user_id,reference,kind,delta_units,balance_after_units,reserved_after_units,actor_id,note,created_at)
                           VALUES (?,?,?,?,?,?,?,?,?)""", (user_id,reference,kind,amount_units,wallet["balance_units"]+amount_units,wallet["reserved_units"],actor_id,note,now_iso()))
    if actor_id is not None:
        _audit(conn, reference=f"funding:{reference}",actor_id=actor_id,action=kind,user_id=user_id,amount_units=amount_units,reason=note)
    return _one(conn, "SELECT * FROM credit_ledger WHERE id=?", (cursor.lastrowid,))


def _usage_state(conn, usage_id, status, *, reserved, charged=0, snapshot=None, usage_json=None, reason=""):
    conn.execute("""UPDATE api_usage_logs SET credit_status=?,credit_reserved_units=?,credit_charged_units=?,
                    credit_pricing_snapshot=COALESCE(?,credit_pricing_snapshot),credit_usage_json=?,credit_reason=? WHERE id=?""",
                 (status,reserved,charged,snapshot,usage_json,reason,usage_id))


def recover_stale_holds(conn: sqlite3.Connection) -> int:
    _tx(conn)
    stale = conn.execute("SELECT usage_id,amount_units FROM credit_holds WHERE status='held' AND julianday(created_at)<=julianday(?)", ((datetime.now(timezone.utc)-timedelta(minutes=15)).isoformat(),)).fetchall()
    for usage_id, amount in stale:
        conn.execute("UPDATE credit_holds SET status='reconciliation_required',reason='stale_hold',updated_at=? WHERE usage_id=? AND status='held'", (now_iso(),usage_id))
        _usage_state(conn,usage_id,"reconciliation_required",reserved=amount,reason="stale_hold")
    return len(stale)


def pending_overrun_units(conn: sqlite3.Connection, user_id: int, *, exclude_usage_id: int | None = None) -> int:
    """Known pending costs outside their freezes, summed without SQLite overflow."""
    rows = conn.execute("""SELECT usage_id,amount_units,actual_units FROM credit_holds
                           WHERE user_id=? AND status='reconciliation_required' AND actual_units>amount_units""",
                        (user_id,))
    return sum(row[2]-row[1] for row in rows if row[0] != exclude_usage_id)


def reserve_credit(conn: sqlite3.Connection, usage_id: int, user_id: int, amount_units: int, pricing_snapshot: str) -> None:
    _tx(conn)
    _units(amount_units)
    _json(pricing_snapshot, required=True)
    previous = _one(conn, "SELECT * FROM credit_holds WHERE usage_id=?", (usage_id,))
    if previous:
        if (previous["user_id"],previous["amount_units"],previous["pricing_snapshot"]) != (user_id,amount_units,pricing_snapshot):
            raise CreditError("reservation_conflict", "此请求已有不同的积分预留。", 409)
        return
    usage = _one(conn,"SELECT user_id FROM api_usage_logs WHERE id=?",(usage_id,))
    if not usage or usage["user_id"] != user_id:
        raise CreditError("usage_not_found", "调用记录不存在或不属于该用户。", 409)
    recover_stale_holds(conn)
    if _one(conn,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='credit_payment_reviews'") and _one(conn,
            "SELECT 1 FROM credit_payment_reviews r JOIN credit_payment_orders o ON o.id=r.order_id WHERE o.user_id=? AND r.state='open' LIMIT 1",(user_id,)):
        raise CreditError("payment_reconciliation_required", "账户存在支付待核记录，请联系管理员核实后继续生成。", 409)
    if pending_overrun_units(conn,user_id):
        raise CreditError("credit_reconciliation_required", "账户存在超出冻结金额的已知待核费用，请联系管理员处理后继续生成。", 409)
    _wallet(conn,user_id)
    changed = conn.execute("UPDATE credit_wallets SET reserved_units=reserved_units+?,updated_at=? WHERE user_id=? AND balance_units-reserved_units>=?",(amount_units,now_iso(),user_id,amount_units)).rowcount
    if not changed:
        raise CreditError("insufficient_credits", "可用积分不足，请先充值或兑换积分。", 402)
    now=now_iso()
    conn.execute("INSERT INTO credit_holds(usage_id,user_id,amount_units,status,pricing_snapshot,reason,created_at,updated_at) VALUES (?,?,?,'held',?,'reserved',?,?)",(usage_id,user_id,amount_units,pricing_snapshot,now,now))
    wallet=wallet_snapshot(conn,user_id)
    conn.execute("""INSERT INTO credit_ledger(user_id,reference,kind,delta_units,delta_reserved_units,balance_after_units,reserved_after_units,usage_id,note,created_at)
                    VALUES (?,?,?,0,?,?,?,?,?,?)""",(user_id,f"usage:{usage_id}:freeze","credit_freeze",amount_units,wallet["balance_units"],wallet["reserved_units"],usage_id,"生成请求积分预留",now))
    _usage_state(conn,usage_id,"held",reserved=amount_units,snapshot=pricing_snapshot,reason="reserved")


def mark_credit_dispatched(conn: sqlite3.Connection, usage_id: int) -> None:
    """Persist dispatch admission before the caller starts upstream I/O."""
    _tx(conn)
    hold=_one(conn,"SELECT * FROM credit_holds WHERE usage_id=?",(usage_id,))
    if not hold or hold["status"] != "held":
        raise CreditError("dispatch_conflict","积分预留已结束或需要人工核账，不能继续发送。",409)
    if hold["dispatch_state"] == "dispatched":
        return
    conn.execute("UPDATE credit_holds SET dispatch_state='dispatched',dispatched_at=?,updated_at=? WHERE usage_id=? AND status='held' AND dispatch_state='reserved'",(now_iso(),now_iso(),usage_id))


def _result(hold: dict) -> dict:
    return {"usage_id":hold["usage_id"],"status":hold["status"],"charged_units":hold["actual_units"] if hold["status"] == "settled" else 0,
            "reserved_units":hold["amount_units"] if hold["status"] in {"held","reconciliation_required"} else 0,
            "actual_units":hold["actual_units"],"reason":hold["reason"]}


def _can_cover_charge(conn, hold, actual_units, wallet):
    if wallet["balance_units"]-wallet["reserved_units"]+hold["amount_units"] < actual_units:
        return False
    # An overrun must not consume funds needed for other known pending costs.
    # Charges covered by their own freeze (and explicit releases) free funds.
    extra = max(actual_units-hold["amount_units"],0)
    return not extra or wallet["balance_units"]-wallet["reserved_units"] >= extra+pending_overrun_units(
        conn,hold["user_id"],exclude_usage_id=hold["usage_id"])


def _finalize(conn,hold,actual_units,reason,usage_json,actor_id=None):
    status = "settled" if actual_units else "released"
    wallet = _wallet(conn,hold["user_id"])
    if not _can_cover_charge(conn,hold,actual_units,wallet):
        raise CreditError("insufficient_credits", "可用余额不足以支付确认的金额并覆盖其他已知待核费用。",402)
    changed = conn.execute("UPDATE credit_holds SET status=?,actual_units=?,usage_json=?,reason=?,updated_at=? WHERE usage_id=? AND status=?",
                           (status,actual_units,usage_json,reason,now_iso(),hold["usage_id"],hold["status"])).rowcount
    if not changed:
        raise CreditError("settlement_conflict", "积分结算状态已改变。",409)
    changed = conn.execute("UPDATE credit_wallets SET balance_units=balance_units-?,reserved_units=reserved_units-?,updated_at=? WHERE user_id=? AND reserved_units>=? AND balance_units-reserved_units+?>=?",
                           (actual_units,hold["amount_units"],now_iso(),hold["user_id"],hold["amount_units"],hold["amount_units"],actual_units)).rowcount
    if not changed:
        raise CreditError("wallet_conflict", "余额与冻结记录不一致。",409)
    conn.execute("""INSERT INTO credit_ledger(user_id,reference,kind,delta_units,delta_reserved_units,balance_after_units,reserved_after_units,usage_id,actor_id,note,created_at)
                    VALUES (?,?,?,0,?,?,?,?,?,?,?)""",(hold["user_id"],f"usage:{hold['usage_id']}:release","credit_release",-hold["amount_units"],wallet["balance_units"],wallet["reserved_units"]-hold["amount_units"],hold["usage_id"],actor_id,reason,now_iso()))
    if actual_units:
        conn.execute("""INSERT INTO credit_ledger(user_id,reference,kind,delta_units,balance_after_units,reserved_after_units,usage_id,actor_id,note,created_at)
                        VALUES (?,?,? ,?,?,?,?,?,?,?)""",(hold["user_id"],f"usage:{hold['usage_id']}:charge","usage_charge",-actual_units,wallet["balance_units"]-actual_units,wallet["reserved_units"]-hold["amount_units"],hold["usage_id"],actor_id,reason,now_iso()))
    _usage_state(conn,hold["usage_id"],status,reserved=0,charged=actual_units,usage_json=usage_json,reason=reason)
    return _result(_one(conn,"SELECT * FROM credit_holds WHERE usage_id=?",(hold["usage_id"],)))


def settle_credit(conn: sqlite3.Connection, usage_id: int, actual_units: int | None, *, reason: str, usage_json: str | None = None) -> dict:
    """Settle authoritative costs; a pending hold needs a reliable late receipt.

    A zero cost without a receipt only releases a newly held request through the
    caller's explicit non-billing path. It never releases an unknown pending hold.
    """
    _tx(conn)
    if actual_units is not None:
        _units(actual_units)
    reason = _text(reason,"结算理由")
    _json(usage_json)
    hold = _one(conn,"SELECT * FROM credit_holds WHERE usage_id=?",(usage_id,))
    if not hold:
        raise CreditError("hold_not_found","积分预留不存在。",404)
    if hold["status"] in {"settled","released"}:
        return _result(hold)
    if hold["status"] == "reconciliation_required":
        if actual_units is None or usage_json is None:
            return _result(hold)
        if _one(conn,"SELECT 1 FROM credit_ledger WHERE reference=?",(f"usage:{usage_id}:receipt_conflict",)):
            return _result(hold)
        if hold["actual_units"] is not None:
            # The first known receipt remains authoritative. A conflicting late
            # callback cannot replace it or turn a known cost into a release.
            if actual_units != hold["actual_units"] or (hold["usage_json"] is not None
                    and json.loads(usage_json,parse_float=Decimal) != json.loads(hold["usage_json"],parse_float=Decimal)):
                wallet = _wallet(conn,hold["user_id"])
                conn.execute("""INSERT INTO credit_ledger(user_id,reference,kind,delta_units,balance_after_units,
                                reserved_after_units,usage_id,note,created_at) VALUES (?,?,?,0,?,?,?,?,?)""",
                             (hold["user_id"],f"usage:{usage_id}:receipt_conflict","usage_receipt_conflict",
                              wallet["balance_units"],wallet["reserved_units"],usage_id,
                              json.dumps({"reason":"Conflicting authoritative receipts require manual reconciliation.",
                                          "original_actual_units":hold["actual_units"],"incoming_actual_units":actual_units,
                                          "incoming_usage_json":usage_json},separators=(",",":")),now_iso()))
                return _result(hold)
    if actual_units is None or not _can_cover_charge(conn,hold,actual_units,_wallet(conn,hold["user_id"])):
        conn.execute("UPDATE credit_holds SET status='reconciliation_required',actual_units=?,usage_json=?,reason=?,updated_at=? WHERE usage_id=? AND status=?",
                     (actual_units,usage_json,reason,now_iso(),usage_id,hold["status"]))
        _usage_state(conn,usage_id,"reconciliation_required",reserved=hold["amount_units"],usage_json=usage_json,reason=reason)
        return _result(_one(conn,"SELECT * FROM credit_holds WHERE usage_id=?",(usage_id,)))
    return _finalize(conn,hold,actual_units,reason,usage_json)


def resolve_credit_hold(conn: sqlite3.Connection, usage_id: int, actual_units: int, *, actor_id: int, reason: str) -> dict:
    """An explicit, audited admin decision may fund an overrun from available credit."""
    _tx(conn)
    _units(actual_units)
    reason=_text(reason,"人工处理理由")
    hold=_one(conn,"SELECT * FROM credit_holds WHERE usage_id=?",(usage_id,))
    if not hold:
        raise CreditError("hold_not_found","待核记录不存在。",404)
    if hold["status"] in {"settled","released"}:
        if hold["actual_units"] != actual_units:
            raise CreditError("settlement_conflict","该记录已按不同金额处理。",409)
        return _result(hold)
    if hold["status"] != "reconciliation_required":
        raise CreditError("hold_not_pending","仅能人工处理待核记录。",409)
    result=_finalize(conn,hold,actual_units,reason,hold["usage_json"],actor_id)
    _audit(conn,reference=f"resolve:{usage_id}",actor_id=actor_id,action="resolve_hold",user_id=hold["user_id"],usage_id=usage_id,amount_units=actual_units,reason=reason)
    return result


def create_credit_code(conn: sqlite3.Connection, amount_units: int, *, actor_id: int, note: str, reference: str, expires_at: str | None = None) -> dict:
    _tx(conn)
    _units(amount_units,positive=True)
    note,reference=_text(note,"发行理由"),_text(reference,"操作编号",limit=200)
    if expires_at:
        try:
            expiry=datetime.fromisoformat(expires_at.replace("Z","+00:00"))
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                raise ValueError
            expires_at=expiry.astimezone(timezone.utc).isoformat()
        except (ValueError,TypeError,OverflowError):
            raise CreditError("invalid_expiry","过期时间必须是将来的时间，且包含时区。") from None
    previous=_one(conn,"SELECT * FROM credit_codes WHERE issue_reference=?",(reference,))
    if previous:
        if (previous["amount_units"],previous["created_by"],previous["note"],previous["expires_at"]) != (amount_units,actor_id,note,expires_at):
            raise CreditError("reference_conflict","此操作编号已用于不同的兑换码。",409)
        return {"id":previous["id"],"code_tail":previous["code_tail"],"raw_code":None,"replayed":True}
    raw="LM-"+secrets.token_hex(24).upper()
    cursor=conn.execute("""INSERT INTO credit_codes(code_hash,code_tail,amount_units,status,expires_at,created_at,created_by,note,issue_reference)
                           VALUES (?,?,?,'active',?,?,?,?,?)""",(hashlib.sha256(raw.encode("ascii")).hexdigest(),raw[-8:],amount_units,expires_at,now_iso(),actor_id,note,reference))
    _audit(conn,reference=f"issue:{reference}",actor_id=actor_id,action="issue_code",code_id=cursor.lastrowid,amount_units=amount_units,reason=note)
    return {"id":cursor.lastrowid,"code_tail":raw[-8:],"raw_code":raw,"replayed":False}


def revoke_credit_code(conn: sqlite3.Connection, code_id: int, *, actor_id: int, reason: str) -> None:
    _tx(conn)
    reason=_text(reason,"作废理由")
    code=_one(conn,"SELECT * FROM credit_codes WHERE id=?",(code_id,))
    if not code:
        raise CreditError("code_not_found","兑换码不存在。",404)
    if code["status"] == "revoked":
        return
    if code["status"] != "active":
        raise CreditError("code_unavailable","已兑换的兑换码不能作废。",409)
    conn.execute("UPDATE credit_codes SET status='revoked',revoked_at=? WHERE id=? AND status='active'",(now_iso(),code_id))
    _audit(conn,reference=f"revoke:{code_id}",actor_id=actor_id,action="revoke_code",code_id=code_id,reason=reason)


def redeem_credit_code(conn: sqlite3.Connection, user_id: int, code: str) -> dict:
    """Caller MUST commit CreditError too: rejected attempts persist for throttling.

    No wallet/code mutation precedes an invalid-code error. Unexpected database
    errors must instead roll back the transaction.
    """
    _tx(conn)
    _wallet(conn,user_id)
    now=datetime.now(timezone.utc)
    attempts=_one(conn,"SELECT * FROM credit_code_attempts WHERE user_id=?",(user_id,))
    if attempts and datetime.fromisoformat(attempts["window_started_at"]) > now-timedelta(seconds=REDEEM_WINDOW_SECONDS):
        if attempts["attempt_count"] >= REDEEM_LIMIT:
            raise CreditError("redeem_rate_limited","兑换尝试过于频繁，请在 15 分钟后重试。",429)
        conn.execute("UPDATE credit_code_attempts SET attempt_count=attempt_count+1 WHERE user_id=?",(user_id,))
    else:
        conn.execute("INSERT INTO credit_code_attempts(user_id,window_started_at,attempt_count) VALUES (?,?,1) ON CONFLICT(user_id) DO UPDATE SET window_started_at=excluded.window_started_at,attempt_count=1",(user_id,now.isoformat()))
    normalized=code.strip().upper() if isinstance(code,str) and len(code)<=100 else ""
    if not re.fullmatch(r"LM-[0-9A-F]{48}",normalized):
        raise CreditError("invalid_code","兑换码无效、已使用、已作废或已过期。")
    digest=hashlib.sha256(normalized.encode("ascii")).hexdigest()
    row=_one(conn,"SELECT * FROM credit_codes WHERE code_hash=?",(digest,))
    if not row or row["status"] != "active" or (row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= now):
        raise CreditError("invalid_code","兑换码无效、已使用、已作废或已过期。")
    wallet=_wallet(conn,user_id)
    if wallet["balance_units"] > MAX_UNITS-row["amount_units"]:
        raise CreditError("balance_overflow","兑换后余额超出允许范围。",409)
    changed=conn.execute("UPDATE credit_codes SET status='redeemed',redeemed_by=?,redeemed_at=? WHERE id=? AND status='active'",(user_id,now.isoformat(),row["id"])).rowcount
    if not changed:
        raise CreditError("invalid_code","兑换码已使用。",409)
    return add_credit(conn,user_id,row["amount_units"],reference=f"redeem:{row['id']}",actor_id=None,kind="code_redemption",note=f"兑换码 …{row['code_tail']}")
