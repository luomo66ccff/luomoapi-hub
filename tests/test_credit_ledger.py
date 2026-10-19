"""No network or production data: isolated SQLite accounting and HTTP tests."""
import json
import re
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth, credit_console, db
from app.credit_ledger import (MAX_UNITS, CreditError, add_credit, amount_to_units,
    cny_to_units, create_credit_code, credits_to_units, initialize_credit_schema,
    mark_credit_dispatched, now_iso, pending_overrun_units, recover_stale_holds, redeem_credit_code,
    reserve_credit, resolve_credit_hold, revoke_credit_code, settle_credit,
    units_to_credits, usd_to_units, wallet_snapshot)
from app.security import security_headers

SNAPSHOT=json.dumps({"version":"test","model":"test-model","card":{"input":"1","output":"2"}})


class LedgerCase(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.path=Path(self.directory.name)/"credits.sqlite"
        self.conn=self.connect()
        self.conn.executescript(db.SCHEMA)
        now=now_iso()
        for user_id,name,role,status in ((1,"admin","admin","active"),(2,"pending","developer","pending"),(3,"active","developer","active"),(4,"disabled","developer","disabled")):
            self.conn.execute("INSERT INTO users(id,username,email,password_hash,role,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",(user_id,name,f"{name}@example.test","unused",role,status,now,now))
        initialize_credit_schema(self.conn)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.directory.cleanup()

    def connect(self):
        conn=sqlite3.connect(self.path,timeout=5)
        conn.row_factory=sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def begin(self):
        self.conn.execute("BEGIN IMMEDIATE")

    def fund(self,amount=100,user_id=2,reference="fund"):
        self.begin()
        entry=add_credit(self.conn,user_id,amount,reference=reference,actor_id=1,kind="admin_credit",note="test funding")
        self.conn.commit()
        return entry

    def usage(self,user_id=2):
        cursor=self.conn.execute("INSERT INTO api_usage_logs(created_at,user_id,method,public_path,model,request_id) VALUES (?,?,'POST','v1/responses','test-model',?)",(now_iso(),user_id,f"test-{user_id}"))
        self.conn.commit()
        return cursor.lastrowid

    def hold(self,amount=80,user_id=2):
        usage_id=self.usage(user_id)
        self.begin()
        reserve_credit(self.conn,usage_id,user_id,amount,SNAPSHOT)
        self.conn.commit()
        return usage_id

    def test_exact_decimal_amount_and_fixed_currency(self):
        self.assertEqual(credits_to_units("0.000001"),1)
        self.assertEqual(cny_to_units("1"),100_000_000)
        self.assertEqual(usd_to_units("1"),720_000_000)
        self.assertEqual(credits_to_units(Decimal("1.234567")),1_234_567)
        self.assertEqual(units_to_credits(1_234_567),"1.234567")
        self.assertEqual(units_to_credits(-1),"-0.000001")
        for value in (0.1,True,"NaN","Infinity","-1","1e2","1.0000001",Decimal("NaN"),Decimal("Infinity"),Decimal("1E-1000000"),str(MAX_UNITS)):
            with self.subTest(value=value),self.assertRaises(CreditError):
                credits_to_units(value)
        with self.assertRaises(CreditError):
            amount_to_units("1","eur")

    def test_additive_migration_preserves_history_and_zero_wallets(self):
        usage_id=self.usage()
        self.conn.execute("UPDATE api_usage_logs SET input_tokens=42,output_tokens=7,total_tokens=49,usage_reported=1 WHERE id=?",(usage_id,))
        initialize_credit_schema(self.conn)
        self.conn.commit()
        row=self.conn.execute("SELECT * FROM api_usage_logs WHERE id=?",(usage_id,)).fetchone()
        self.assertEqual((row["total_tokens"],row["credit_status"],row["credit_charged_units"]),(49,"legacy_unbilled",0))
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],0)

    def test_new_user_wallet_is_created_lazily(self):
        self.conn.execute("INSERT INTO users(id,username,email,password_hash,created_at,updated_at) VALUES (9,'new','new@example.test','unused',?,?)",(now_iso(),now_iso()))
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,9)["available_units"],0)
        self.assertIsNone(self.conn.execute("SELECT * FROM credit_wallets WHERE user_id=9").fetchone())
        self.fund(user_id=9)
        self.assertEqual(wallet_snapshot(self.conn,9)["available_units"],100)

    def test_writes_require_existing_transaction(self):
        usage_id=self.usage()
        for operation in (lambda:add_credit(self.conn,2,1,reference="x",actor_id=1,kind="admin_credit",note="x"),lambda:reserve_credit(self.conn,usage_id,2,1,SNAPSHOT),lambda:settle_credit(self.conn,usage_id,0,reason="x"),lambda:recover_stale_holds(self.conn),lambda:mark_credit_dispatched(self.conn,usage_id),lambda:redeem_credit_code(self.conn,2,"bad")):
            with self.assertRaises(CreditError) as caught:
                operation()
            self.assertEqual(caught.exception.code,"transaction_required")

    def test_credit_add_reference_replay_and_conflict(self):
        original=self.fund()
        self.begin()
        replay=add_credit(self.conn,2,100,reference="fund",actor_id=1,kind="admin_credit",note="test funding")
        self.assertEqual(original["id"],replay["id"])
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],100)
        for amount,note in ((101,"test funding"),(100,"changed reason")):
            self.begin()
            with self.assertRaises(CreditError) as caught:
                add_credit(self.conn,2,amount,reference="fund",actor_id=1,kind="admin_credit",note=note)
            self.assertEqual(caught.exception.status,409)
            self.conn.rollback()
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_admin_audit").fetchone()[0],1)

    def test_invalid_admin_add_and_overflow(self):
        for amount,note in ((0,"reason"),(-1,"reason"),(1," "),(True,"reason"),(1.5,"reason")):
            self.begin()
            with self.assertRaises(CreditError):
                add_credit(self.conn,2,amount,reference="bad",actor_id=1,kind="admin_credit",note=note)
            self.conn.rollback()
        self.fund(MAX_UNITS)
        self.begin()
        with self.assertRaises(CreditError) as caught:
            add_credit(self.conn,2,1,reference="overflow",actor_id=1,kind="admin_credit",note="reason")
        self.assertEqual(caught.exception.code,"balance_overflow")
        self.conn.rollback()

    def test_database_checks_and_immutable_ledger_audit(self):
        self.fund()
        for statement in ("UPDATE credit_wallets SET balance_units=-1 WHERE user_id=2","UPDATE credit_wallets SET reserved_units=101 WHERE user_id=2","UPDATE credit_wallets SET balance_units=1.5 WHERE user_id=2","UPDATE credit_ledger SET note='changed'","DELETE FROM credit_ledger","UPDATE credit_admin_audit SET reason='changed'","DELETE FROM credit_admin_audit"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(statement)
            self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],100)

    def test_reservation_and_replay_leave_balance_total(self):
        self.fund()
        usage_id=self.hold()
        self.assertEqual(wallet_snapshot(self.conn,2),{"balance_units":100,"reserved_units":80,"risk_units":0,"available_units":20,"balance_credits":"0.0001","reserved_credits":"0.00008","risk_credits":"0","available_credits":"0.00002"})
        self.begin()
        reserve_credit(self.conn,usage_id,2,80,SNAPSHOT)
        self.conn.commit()
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='credit_freeze'").fetchone()[0],1)
        self.begin()
        with self.assertRaises(CreditError):
            reserve_credit(self.conn,usage_id,2,81,SNAPSHOT)
        self.conn.rollback()

    def test_reservation_requires_usage_ownership(self):
        self.fund()
        usage_id=self.usage(user_id=3)
        self.begin()
        with self.assertRaises(CreditError):
            reserve_credit(self.conn,usage_id,2,1,SNAPSHOT)
        self.conn.rollback()

    def test_invalid_snapshots_cannot_freeze_or_settle(self):
        self.fund()
        usage_id=self.usage()
        for snapshot in ("[]","null",'{"price":NaN}',"malformed"):
            self.begin()
            with self.assertRaises(CreditError):
                reserve_credit(self.conn,usage_id,2,80,snapshot)
            self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],0)
        self.begin()
        reserve_credit(self.conn,usage_id,2,80,SNAPSHOT)
        self.conn.commit()
        self.begin()
        with self.assertRaises(CreditError):
            settle_credit(self.conn,usage_id,30,reason="invalid usage",usage_json='{"tokens":Infinity}')
        self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],80)

    def test_concurrent_reservations_cannot_overspend(self):
        self.fund()
        ids=[self.usage(),self.usage()]
        barrier=threading.Barrier(2)
        def reserve(usage_id):
            conn=self.connect()
            try:
                barrier.wait()
                conn.execute("BEGIN IMMEDIATE")
                try:
                    reserve_credit(conn,usage_id,2,80,SNAPSHOT)
                except CreditError as exc:
                    conn.rollback()
                    return exc.code
                conn.commit()
                return "ok"
            finally:
                conn.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(reserve,ids))
        self.assertCountEqual(results,["ok","insufficient_credits"])
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],80)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_holds").fetchone()[0],1)

    def test_rollback_undoes_wallet_hold_and_ledger_together(self):
        self.fund()
        usage_id=self.usage()
        self.begin()
        reserve_credit(self.conn,usage_id,2,80,SNAPSHOT)
        self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_holds").fetchone()[0],0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],1)

    def test_settlement_charges_once_releases_surplus_and_writes_usage(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        result=settle_credit(self.conn,usage_id,30,reason="reported usage",usage_json='{"input_tokens":2}')
        self.conn.commit()
        self.assertEqual((result["status"],result["charged_units"],result["reserved_units"]),("settled",30,0))
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],70)
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],0)
        self.begin()
        replay=settle_credit(self.conn,usage_id,99,reason="duplicate callback")
        self.conn.commit()
        self.assertEqual(replay["charged_units"],30)
        row=self.conn.execute("SELECT * FROM api_usage_logs WHERE id=?",(usage_id,)).fetchone()
        self.assertEqual((row["credit_status"],row["credit_charged_units"],row["credit_reserved_units"]),("settled",30,0))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],1)
        self.assertEqual(self.conn.execute("SELECT SUM(delta_units),SUM(delta_reserved_units) FROM credit_ledger WHERE user_id=2").fetchone()[:],(70,0))

    def test_settlement_zero_releases_without_charge(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        result=settle_credit(self.conn,usage_id,0,reason="not forwarded")
        self.conn.commit()
        self.assertEqual(result["status"],"released")
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],100)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],0)

    def test_concurrent_settlement_callbacks_charge_once(self):
        self.fund()
        usage_id=self.hold()
        barrier=threading.Barrier(2)
        def settle(_):
            with closing(self.connect()) as conn:
                barrier.wait()
                conn.execute("BEGIN IMMEDIATE")
                result=settle_credit(conn,usage_id,30,reason="concurrent completion")
                conn.commit()
                return result["charged_units"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(settle,(1,2))),[30,30])
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],70)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='credit_release'").fetchone()[0],1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],1)

    def test_failed_charge_rolls_back_release_and_hold_transition(self):
        self.fund()
        usage_id=self.hold()
        self.conn.execute("CREATE TRIGGER fail_charge BEFORE INSERT ON credit_ledger WHEN NEW.kind='usage_charge' BEGIN SELECT RAISE(ABORT,'injected failure'); END")
        self.begin()
        with self.assertRaises(sqlite3.IntegrityError):
            settle_credit(self.conn,usage_id,30,reason="injected failure")
        self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],100)
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],80)
        self.assertEqual(self.conn.execute("SELECT status FROM credit_holds WHERE usage_id=?",(usage_id,)).fetchone()[0],"held")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='credit_release'").fetchone()[0],0)

    def test_unknown_usage_retains_freeze_and_allows_only_remaining_balance(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        result=settle_credit(self.conn,usage_id,None,reason="usage missing")
        self.conn.commit()
        self.assertEqual(result["status"],"reconciliation_required")
        self.assertEqual(pending_overrun_units(self.conn,2),0)
        next_id=self.usage()
        self.begin()
        with self.assertRaises(CreditError) as caught:
            reserve_credit(self.conn,next_id,2,21,SNAPSHOT)
        self.assertEqual((caught.exception.code,caught.exception.status),("insufficient_credits",402))
        self.conn.rollback()
        new_id=self.hold(20)
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],100)
        self.assertEqual(self.conn.execute("SELECT status FROM credit_holds WHERE usage_id=?",(usage_id,)).fetchone()[0],"reconciliation_required")
        self.assertEqual(self.conn.execute("SELECT status FROM credit_holds WHERE usage_id=?",(new_id,)).fetchone()[0],"held")
        self.begin()
        self.assertEqual(settle_credit(self.conn,usage_id,0,reason="late no-usage rejection")["status"],"reconciliation_required")
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],100)

    def test_overrun_settles_when_other_freezes_remain_fully_covered(self):
        self.fund()
        usage_id=self.hold()
        other_id=self.hold(10)
        self.begin()
        result=settle_credit(self.conn,usage_id,90,reason="authoritative overrun",usage_json='{"tokens":90}')
        self.conn.commit()
        self.assertEqual((result["status"],result["charged_units"]),("settled",90))
        wallet=wallet_snapshot(self.conn,2)
        self.assertEqual((wallet["balance_units"],wallet["reserved_units"],wallet["available_units"]),(10,10,0))
        self.assertEqual(self.conn.execute("SELECT status FROM credit_holds WHERE usage_id=?",(other_id,)).fetchone()[0],"held")
        self.assertEqual(self.conn.execute("SELECT SUM(delta_units),SUM(delta_reserved_units) FROM credit_ledger WHERE user_id=2").fetchone()[:],(10,10))

    def test_unfunded_known_overrun_preserves_freeze_and_blocks_admission(self):
        self.fund()
        usage_id=self.hold()
        self.hold(10)
        self.begin()
        result=settle_credit(self.conn,usage_id,91,reason="known cost exceeds coverage",usage_json='{"tokens":91}')
        self.conn.commit()
        self.assertEqual((result["status"],result["actual_units"]),("reconciliation_required",91))
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],90)
        self.assertEqual(pending_overrun_units(self.conn,2),11)
        self.assertEqual((wallet_snapshot(self.conn,2)["risk_units"],wallet_snapshot(self.conn,2)["available_units"]),(11,-1))
        # Funding alone cannot silently clear a known unresolved invoice.
        self.fund(100,reference="extra")
        next_id=self.usage()
        self.begin()
        with self.assertRaises(CreditError) as caught:
            reserve_credit(self.conn,next_id,2,1,SNAPSHOT)
        self.assertEqual((caught.exception.code,caught.exception.status),("credit_reconciliation_required",409))
        self.conn.rollback()
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],0)

    def test_overruns_preserve_other_known_risk_and_recover_from_matching_receipts(self):
        self.fund(150)
        first,second=self.hold(40),self.hold(40)
        self.begin()
        self.assertEqual(settle_credit(self.conn,first,120,reason="first invoice",usage_json='{"tokens":120}')["status"],"reconciliation_required")
        # 80 is individually payable, but would consume the first invoice's gap.
        self.assertEqual(settle_credit(self.conn,second,80,reason="second invoice",usage_json='{"tokens":80}')["status"],"reconciliation_required")
        self.conn.commit()
        self.assertEqual(pending_overrun_units(self.conn,2),120)
        self.assertEqual(pending_overrun_units(self.conn,2,exclude_usage_id=first),40)
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],80)
        self.fund(50,reference="cover-both")
        self.begin()
        self.assertEqual(settle_credit(self.conn,first,120,reason="matching late invoice",usage_json='{ "tokens": 120 }')["status"],"settled")
        self.assertEqual(settle_credit(self.conn,second,80,reason="matching late invoice",usage_json='{"tokens":80}')["status"],"settled")
        self.conn.commit()
        self.assertEqual((wallet_snapshot(self.conn,2)["balance_units"],wallet_snapshot(self.conn,2)["reserved_units"]),(0,0))
        self.assertEqual(pending_overrun_units(self.conn,2),0)
        self.assertEqual(self.conn.execute("SELECT SUM(delta_units),SUM(delta_reserved_units) FROM credit_ledger WHERE user_id=2").fetchone()[:],(0,0))

    def test_late_authoritative_receipt_replaces_unknown_partial_usage_and_settles_once(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        settle_credit(self.conn,usage_id,None,reason="incomplete receipt",usage_json='{"input_tokens":2}')
        result=settle_credit(self.conn,usage_id,81,reason="complete late receipt",usage_json='{"input_tokens":2,"output_tokens":3}')
        self.assertEqual((result["status"],result["charged_units"]),("settled",81))
        replay=settle_credit(self.conn,usage_id,81,reason="duplicate late receipt",usage_json='{"input_tokens":2,"output_tokens":3}')
        self.assertEqual(replay,result)
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],19)
        row=self.conn.execute("SELECT * FROM api_usage_logs WHERE id=?",(usage_id,)).fetchone()
        self.assertEqual((row["credit_status"],row["credit_charged_units"],row["credit_reserved_units"]),("settled",81,0))
        self.assertEqual(json.loads(row["credit_usage_json"]),{"input_tokens":2,"output_tokens":3})
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],1)

    def test_conflicting_pending_receipts_cannot_replace_known_cost_or_release(self):
        self.fund()
        usage_id=self.hold()
        receipt='{"tokens":110}'
        self.begin()
        settle_credit(self.conn,usage_id,110,reason="first known invoice",usage_json=receipt)
        self.conn.commit()
        self.fund(20,reference="extra")
        self.begin()
        for actual,usage in ((0,'{"tokens":0}'),(30,'{"tokens":30}'),(110,'{"tokens":111}'),(110,None)):
            result=settle_credit(self.conn,usage_id,actual,reason="conflicting callback",usage_json=usage)
            self.assertEqual((result["status"],result["actual_units"]),("reconciliation_required",110))
        self.conn.commit()
        hold=self.conn.execute("SELECT * FROM credit_holds WHERE usage_id=?",(usage_id,)).fetchone()
        self.assertEqual((hold["usage_json"],hold["reason"]),(receipt,"first known invoice"))
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],10)
        self.begin()
        self.assertEqual(settle_credit(self.conn,usage_id,110,reason="same late receipt after conflict",usage_json=receipt)["status"],"reconciliation_required")
        self.assertEqual(resolve_credit_hold(self.conn,usage_id,110,actor_id=1,reason="checked conflicting invoices")["status"],"settled")
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],10)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_receipt_conflict'").fetchone()[0],1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_admin_audit WHERE action='resolve_hold'").fetchone()[0],1)

    def test_complete_zero_receipt_can_release_pending_unknown_hold(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        settle_credit(self.conn,usage_id,None,reason="missing receipt")
        self.assertEqual(settle_credit(self.conn,usage_id,0,reason="verified zero tokens",usage_json='{"input_tokens":0,"output_tokens":0}')["status"],"released")
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],100)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],0)

    def test_manual_terminal_decisions_are_preserved_after_late_receipts(self):
        self.fund()
        released,settled=self.hold(40),self.hold(40)
        self.begin()
        for usage_id,actual in ((released,0),(settled,30)):
            settle_credit(self.conn,usage_id,None,reason="missing receipt")
            resolve_credit_hold(self.conn,usage_id,actual,actor_id=1,reason="audited manual decision")
        self.conn.commit()
        before=[dict(row) for row in self.conn.execute("SELECT * FROM credit_holds ORDER BY usage_id")]
        self.begin()
        for usage_id in (released,settled):
            settle_credit(self.conn,usage_id,90,reason="late authoritative invoice",usage_json='{"tokens":90}')
        self.conn.commit()
        self.assertEqual([dict(row) for row in self.conn.execute("SELECT * FROM credit_holds ORDER BY usage_id")],before)
        self.assertEqual((wallet_snapshot(self.conn,2)["balance_units"],wallet_snapshot(self.conn,2)["reserved_units"]),(70,0))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_admin_audit WHERE action='resolve_hold'").fetchone()[0],2)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],1)

    def test_concurrent_late_receipts_atomically_charge_once(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        settle_credit(self.conn,usage_id,None,reason="missing receipt")
        self.conn.commit()
        barrier=threading.Barrier(2)
        def late_receipt(_):
            with closing(self.connect()) as conn:
                barrier.wait()
                conn.execute("BEGIN IMMEDIATE")
                result=settle_credit(conn,usage_id,81,reason="late invoice",usage_json='{"tokens":81}')
                conn.commit()
                return result["charged_units"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(late_receipt,(1,2))),[81,81])
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],19)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='usage_charge'").fetchone()[0],1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='credit_release'").fetchone()[0],1)

    def test_stale_recovery_retains_dispatch_state_and_freeze(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        mark_credit_dispatched(self.conn,usage_id)
        mark_credit_dispatched(self.conn,usage_id)
        old=(datetime.now(timezone.utc)-timedelta(minutes=16)).isoformat()
        self.conn.execute("UPDATE credit_holds SET created_at=? WHERE usage_id=?",(old,usage_id))
        self.assertEqual(recover_stale_holds(self.conn),1)
        self.assertEqual(recover_stale_holds(self.conn),0)
        self.conn.commit()
        row=self.conn.execute("SELECT * FROM credit_holds WHERE usage_id=?",(usage_id,)).fetchone()
        self.assertEqual((row["status"],row["dispatch_state"]),("reconciliation_required","dispatched"))
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],80)
        self.begin()
        with self.assertRaises(CreditError):
            mark_credit_dispatched(self.conn,usage_id)
        self.conn.rollback()

    def test_manual_resolution_overrun_requires_available_balance_and_audits(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        settle_credit(self.conn,usage_id,110,reason="overrun")
        self.conn.commit()
        self.begin()
        with self.assertRaises(CreditError):
            resolve_credit_hold(self.conn,usage_id,110,actor_id=1,reason="confirmed invoice")
        self.conn.rollback()
        self.fund(20,reference="extra")
        self.begin()
        result=resolve_credit_hold(self.conn,usage_id,110,actor_id=1,reason="confirmed invoice")
        self.conn.commit()
        self.assertEqual(result["charged_units"],110)
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],10)
        self.begin()
        resolve_credit_hold(self.conn,usage_id,110,actor_id=1,reason="retry")
        self.conn.commit()
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_admin_audit WHERE action='resolve_hold'").fetchone()[0],1)

    def issue(self,amount=10,reference="issue",expiry=None):
        self.begin()
        result=create_credit_code(self.conn,amount,actor_id=1,note="test issuance",reference=reference,expires_at=expiry)
        self.conn.commit()
        return result

    def test_code_cryptographic_storage_and_issue_replay(self):
        issued=self.issue()
        self.assertRegex(issued["raw_code"],r"^LM-[0-9A-F]{48}$")
        row=self.conn.execute("SELECT * FROM credit_codes").fetchone()
        self.assertNotIn(issued["raw_code"],json.dumps(dict(row)))
        self.assertEqual(row["code_tail"],issued["raw_code"][-8:])
        replay=self.issue()
        self.assertIsNone(replay["raw_code"])
        self.assertEqual(replay["id"],issued["id"])
        self.begin()
        with self.assertRaises(CreditError) as caught:
            create_credit_code(self.conn,11,actor_id=1,note="test issuance",reference="issue")
        self.assertEqual(caught.exception.status,409)
        self.conn.rollback()

    def test_concurrent_code_redemption_is_single_use(self):
        code=self.issue()["raw_code"]
        barrier=threading.Barrier(2)
        def redeem(user_id):
            conn=self.connect()
            try:
                barrier.wait()
                conn.execute("BEGIN IMMEDIATE")
                try:
                    redeem_credit_code(conn,user_id,code)
                    result="ok"
                except CreditError as exc:
                    result=exc.code
                conn.commit()
                return result
            finally:
                conn.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(redeem,(2,3)))
        self.assertCountEqual(results,["ok","invalid_code"])
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"]+wallet_snapshot(self.conn,3)["balance_units"],10)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger WHERE kind='code_redemption'").fetchone()[0],1)

    def test_code_expiry_revoke_and_persistent_rate_limit(self):
        code=self.issue(expiry=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())
        self.begin()
        revoke_credit_code(self.conn,code["id"],actor_id=1,reason="cancelled")
        self.conn.commit()
        for index in range(6):
            with closing(self.connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                with self.assertRaises(CreditError) as caught:
                    redeem_credit_code(conn,2,code["raw_code"])
                self.assertEqual(caught.exception.status,429 if index == 5 else 400)
                conn.commit()
        self.assertEqual(self.conn.execute("SELECT attempt_count FROM credit_code_attempts WHERE user_id=2").fetchone()[0],5)
        expiring=self.issue(reference="expiry",expiry=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())
        self.conn.execute("UPDATE credit_codes SET expires_at=? WHERE id=?",((datetime.now(timezone.utc)-timedelta(hours=1)).isoformat(),expiring["id"]))
        self.conn.commit()
        self.begin()
        with self.assertRaises(CreditError):
            redeem_credit_code(self.conn,3,expiring["raw_code"])
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,3)["balance_units"],0)

    def test_code_failure_rollback_restores_code_and_money(self):
        code=self.issue()
        self.conn.execute("CREATE TRIGGER fail_redemption BEFORE INSERT ON credit_ledger WHEN NEW.kind='code_redemption' BEGIN SELECT RAISE(ABORT,'injected redemption failure'); END")
        self.begin()
        with self.assertRaises(sqlite3.IntegrityError):
            redeem_credit_code(self.conn,2,code["raw_code"])
        self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],0)
        self.assertEqual(self.conn.execute("SELECT status FROM credit_codes WHERE id=?",(code["id"],)).fetchone()[0],"active")

    def test_redemption_window_persists_and_expires(self):
        code=self.issue()
        old=(datetime.now(timezone.utc)-timedelta(minutes=16)).isoformat()
        self.conn.execute("INSERT INTO credit_code_attempts(user_id,window_started_at,attempt_count) VALUES (2,?,5)",(old,))
        self.conn.commit()
        self.begin()
        redeem_credit_code(self.conn,2,code["raw_code"].lower())
        self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],10)
        self.assertEqual(self.conn.execute("SELECT attempt_count FROM credit_code_attempts WHERE user_id=2").fetchone()[0],1)

    def test_code_issuance_rejects_missing_timezone_and_past_expiry(self):
        for expiry in ("2020-01-01T00:00:00+00:00","2999-01-01T00:00:00","not-a-date"):
            self.begin()
            with self.assertRaises(CreditError):
                create_credit_code(self.conn,1,actor_id=1,note="test",reference="invalid",expires_at=expiry)
            self.conn.rollback()

    def test_init_db_runs_additive_migration_and_stale_recovery(self):
        self.fund()
        usage_id=self.hold()
        old=(datetime.now(timezone.utc)-timedelta(minutes=16)).isoformat()
        self.conn.execute("UPDATE credit_holds SET created_at=? WHERE usage_id=?",(old,usage_id))
        self.conn.commit()
        configured=replace(db.settings,database_path=self.path)
        with patch.object(db,"settings",configured),patch.object(db,"ensure_dirs",lambda:None):
            db.init_db()
        self.assertEqual(self.conn.execute("SELECT status FROM credit_holds WHERE usage_id=?",(usage_id,)).fetchone()[0],"reconciliation_required")
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],80)


class ConsoleCase(unittest.TestCase):
    """Use the actual session/dependency chain, rather than bypassing auth."""
    connect=LedgerCase.connect
    begin=LedgerCase.begin
    fund=LedgerCase.fund
    usage=LedgerCase.usage
    hold=LedgerCase.hold
    def setUp(self):
        LedgerCase.setUp(self)
        self.auth_connections=[]
        def auth_connection():
            # Legacy auth uses a connection context without closing it. Track
            # only fixture-owned handles, so Windows can remove its temp DB.
            conn=sqlite3.connect(self.path,timeout=5,check_same_thread=False)
            conn.row_factory=sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            self.auth_connections.append(conn)
            return conn
        configured=replace(auth.settings,session_secret="isolated-unittest-secret",database_path=self.path)
        self.patches=[patch.object(auth,"settings",configured),patch.object(auth,"connect",auth_connection),patch.object(credit_console,"connect",self.connect)]
        for item in self.patches:
            item.start()
        app=FastAPI()
        app.middleware("http")(security_headers)
        app.include_router(credit_console.router)
        self.app=app
        self.client=TestClient(app)

    def tearDown(self):
        self.client.close()
        for item in reversed(self.patches):
            item.stop()
        for conn in self.auth_connections:
            conn.close()
        LedgerCase.tearDown(self)

    def login(self,name):
        self.client.cookies.set(auth.SESSION_COOKIE,auth.create_session(name))

    def test_pending_wallet_access_and_admin_boundary(self):
        self.assertEqual(self.client.get("/api/developer/credits").status_code,401)
        self.login("pending")
        response=self.client.get("/developer/credits")
        self.assertEqual(response.status_code,200)
        self.assertIn("支付待配置",response.text)
        self.assertIn("test-model",SNAPSHOT)
        self.assertEqual(self.client.get("/api/developer/credits").json()["wallet"]["balance_units"],0)
        self.assertEqual(self.client.get("/admin/credits").status_code,403)
        self.assertEqual(self.client.post("/admin/credits/add",data={"user_id":2,"amount_credits":"1","reason":"unauthorized","nonce":"a"*48},headers={"Origin":"http://testserver"}).status_code,403)
        self.login("disabled")
        self.assertEqual(self.client.get("/api/developer/credits").status_code,401)
        self.login("admin")
        self.assertEqual(self.client.get("/admin/credits").status_code,200)

    def test_admin_add_double_submit_validation_and_origin(self):
        self.login("admin")
        fields={"user_id":2,"amount_credits":"1.123456","reason":"test topup","nonce":"a"*48}
        self.assertEqual(self.client.post("/admin/credits/add",data=fields,headers={"Origin":"https://outside.test"}).status_code,403)
        for _ in range(2):
            self.assertEqual(self.client.post("/admin/credits/add",data=fields,headers={"Origin":"http://testserver"}).status_code,200)
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],1_123_456)
        fields["amount_credits"]="2"
        self.assertEqual(self.client.post("/admin/credits/add",data=fields,headers={"Origin":"http://testserver"}).status_code,409)
        fields.update(nonce="b"*48,reason=" ")
        self.assertEqual(self.client.post("/admin/credits/add",data=fields,headers={"Origin":"http://testserver"}).status_code,400)

    def test_redeem_route_persists_rejected_attempts(self):
        self.login("pending")
        for index in range(6):
            response=self.client.post("/developer/credits/redeem",data={"code":"invalid"},headers={"Origin":"http://testserver"})
            self.assertEqual(response.status_code,429 if index == 5 else 400)
        self.assertEqual(self.conn.execute("SELECT attempt_count FROM credit_code_attempts WHERE user_id=2").fetchone()[0],5)

    def test_payment_context_hook_exposes_pending_topup_form(self):
        self.app.state.credit_payment_context={"enabled":True,"message":"sandbox payment context"}
        self.login("pending")
        response=self.client.get("/developer/credits")
        self.assertIn('action="/developer/credits/topup"',response.text)
        self.assertIn('name="amount_cny"',response.text)
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],0)

    def test_admin_issue_redeem_and_revoke_full_workflow(self):
        self.login("admin")
        fields={"amount_credits":"10","reason":"workflow issuance","nonce":"c"*48}
        response=self.client.post("/admin/credits/codes",data=fields,headers={"Origin":"http://testserver"})
        self.assertEqual(response.status_code,200)
        raw=re.search(r"LM-[0-9A-F]{48}",response.text).group()
        replay=self.client.post("/admin/credits/codes",data=fields,headers={"Origin":"http://testserver"})
        self.assertEqual(replay.status_code,200)
        self.assertNotIn(raw,replay.text)
        self.assertNotIn(raw,self.client.get("/admin/credits").text)
        self.login("pending")
        response=self.client.post("/developer/credits/redeem",data={"code":raw},headers={"Origin":"http://testserver"})
        self.assertEqual(response.status_code,200)
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],10_000_000)
        self.assertEqual(self.client.post("/developer/credits/redeem",data={"code":raw},headers={"Origin":"http://testserver"}).status_code,400)
        self.login("admin")
        fields["nonce"]="d"*48
        response=self.client.post("/admin/credits/codes",data=fields,headers={"Origin":"http://testserver"})
        raw=re.search(r"LM-[0-9A-F]{48}",response.text).group()
        code_id=self.conn.execute("SELECT MAX(id) FROM credit_codes").fetchone()[0]
        self.assertEqual(self.client.post(f"/admin/credits/codes/{code_id}/revoke",data={"reason":"workflow cancel"},headers={"Origin":"http://testserver"}).status_code,200)
        self.login("pending")
        self.assertEqual(self.client.post("/developer/credits/redeem",data={"code":raw},headers={"Origin":"http://testserver"}).status_code,400)
        self.assertEqual(wallet_snapshot(self.conn,2)["balance_units"],10_000_000)

    def test_admin_manual_release_route_requires_reason_and_audits(self):
        self.fund()
        usage_id=self.hold()
        self.begin()
        settle_credit(self.conn,usage_id,None,reason="missing usage")
        self.conn.commit()
        self.login("pending")
        path=f"/admin/credits/holds/{usage_id}/resolve"
        fields={"actual_credits":"0","reason":"confirmed no charge"}
        self.assertEqual(self.client.post(path,data=fields,headers={"Origin":"http://testserver"}).status_code,403)
        self.login("admin")
        fields["reason"]=" "
        self.assertEqual(self.client.post(path,data=fields,headers={"Origin":"http://testserver"}).status_code,400)
        self.assertEqual(wallet_snapshot(self.conn,2)["reserved_units"],80)
        fields["reason"]="confirmed no charge"
        response=self.client.post(path,data=fields,headers={"Origin":"http://testserver"})
        self.assertEqual(response.status_code,200)
        self.assertEqual(wallet_snapshot(self.conn,2)["available_units"],100)
        row=self.conn.execute("SELECT * FROM credit_admin_audit WHERE action='resolve_hold'").fetchone()
        self.assertEqual((row["actor_id"],row["amount_units"],row["reason"]),(1,0,"confirmed no charge"))


if __name__ == "__main__":
    unittest.main()
