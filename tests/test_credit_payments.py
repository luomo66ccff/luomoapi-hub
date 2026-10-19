"""Synthetic Stripe receipts, temporary SQLite and HTTP MockTransport only."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from dataclasses import replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import db, credit_payments as payments
from app.auth import require_developer
from app.credit_ledger import CreditError, initialize_credit_schema, wallet_snapshot
from app.credit_payments import (initialize_payment_schema, amount_fen, topup_nonce,
    claim_order, fulfill_order, review_payment, verify_signature, valid_checkout_url, payment_config)
from app.utils.timefmt import now_iso


class CreditPaymentTests(unittest.TestCase):
    def setUp(self):
        self.settings_patch=patch.object(payments,"settings",replace(payments.settings,
            app_base_url="https://api.example.test",session_secret="isolated-payment-fixture-secret-at-least-32-characters"))
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        self.conn=sqlite3.connect(":memory:")
        self.conn.row_factory=sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(db.SCHEMA)
        now=now_iso()
        self.conn.execute("INSERT INTO users(id,username,email,password_hash,role,status,created_at,updated_at) VALUES (1,'customer','c@example.test','unused','developer','pending',?,?)",(now,now))
        initialize_credit_schema(self.conn)
        initialize_payment_schema(self.conn)
        self.conn.commit()
        self.config={"account":"acct_TEST","live":False}

    def tearDown(self):
        self.conn.close()

    def order(self,fen=1234,nonce=None):
        self.conn.execute("BEGIN IMMEDIATE")
        row=claim_order(self.conn,1,nonce or topup_nonce(1),fen,self.config)
        self.conn.commit()
        return row

    def receipts(self,order):
        event={"id":"evt_1","type":"checkout.session.completed"}
        session={"id":"cs_test_1","mode":"payment","payment_status":"paid","status":"complete", "currency":"cny",
            "amount_total":order["amount_fen"],"client_reference_id":order["id"],"metadata":{"order_id":order["id"]},
            "livemode":False,"payment_intent":"pi_1"}
        intent={"id":"pi_1","status":"succeeded","amount_received":order["amount_fen"],"currency":"cny",
                "amount":order["amount_fen"],"livemode":False,"metadata":{"order_id":order["id"]},
                "latest_charge":{"id":"ch_1","payment_intent":"pi_1","paid":True,"captured":True,
                    "amount":order["amount_fen"],"amount_captured":order["amount_fen"],"currency":"cny",
                    "livemode":False,"refunded":False,"amount_refunded":0,"disputed":False}}
        return event,session,intent

    def test_exact_fen_conversion_and_bounds(self):
        self.assertEqual(amount_fen("1.01"),101)
        self.assertEqual(amount_fen("1000.00"),100000)
        for value in ("0.99","1000.01","1.001","1e2","NaN","-1",True):
            with self.subTest(value=value),self.assertRaises(CreditError):
                amount_fen(value)

    def test_raw_webhook_signature_time_and_tampering(self):
        stamp=int(time.time());body=b'{"type":"test"}';secret="whsec_test"
        digest=hmac.new(secret.encode(),str(stamp).encode()+b"."+body,hashlib.sha256).hexdigest()
        header=f"t={stamp},v1={digest}"
        verify_signature(body,header,secret,current_time=stamp)
        for changed_body,changed_header,clock in ((body+b" ",header,stamp),(body,header,stamp+301),(body,"t=0,v1=x",stamp),(body,header+f",t={stamp}",stamp)):
            with self.assertRaises(CreditError):
                verify_signature(changed_body,changed_header,secret,current_time=clock)

    def test_nonce_bound_to_customer_and_amount(self):
        nonce=topup_nonce(1);original=self.order(nonce=nonce)
        self.assertEqual(self.order(nonce=nonce)["id"],original["id"])
        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaises(CreditError):
            claim_order(self.conn,1,nonce,100,self.config)
        self.conn.rollback()
        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaises(CreditError):
            claim_order(self.conn,1,topup_nonce(2),100,self.config)
        self.conn.rollback()

    def test_no_funds_on_order_or_browser_return(self):
        self.order()
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],0)

    def test_paid_receipt_exact_credit_and_event_replays(self):
        order=self.order();event,session,intent=self.receipts(order)
        self.conn.execute("BEGIN IMMEDIATE")
        self.assertTrue(fulfill_order(self.conn,event,session,intent,self.config))
        self.conn.commit()
        for event in (event,{**event,"id":"evt_2","type":"checkout.session.async_payment_succeeded"}):
            self.conn.execute("BEGIN IMMEDIATE")
            fulfill_order(self.conn,event,session,intent,self.config)
            self.conn.commit()
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],1234000000)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],1)

    def test_mismatched_receipts_do_not_add_credit(self):
        order=self.order();event,session,intent=self.receipts(order)
        for change in ({"payment_status":"unpaid"},{"payment_status":"no_payment_required"},{"amount_total":1235},
                       {"amount_total":True},{"currency":"usd"},{"livemode":True},{"mode":"subscription"},{"metadata":{}}):
            self.conn.execute("BEGIN IMMEDIATE")
            with self.subTest(change=change),self.assertRaises(CreditError):
                fulfill_order(self.conn,event,{**session,**change},intent,self.config)
            self.conn.rollback()
        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaises(CreditError):
            fulfill_order(self.conn,event,session,{**intent,"amount_received":1},self.config)
        self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],0)

    def test_payment_intent_and_session_cannot_fund_two_orders(self):
        first=self.order();event,session,intent=self.receipts(first)
        self.conn.execute("BEGIN IMMEDIATE");fulfill_order(self.conn,event,session,intent,self.config);self.conn.commit()
        second=self.order();event,session,intent=self.receipts(second);event["id"]="evt_3"
        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaises(CreditError):
            fulfill_order(self.conn,event,session,intent,self.config)
        self.conn.rollback()
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],first["credit_units"])

    def test_session_reuse_with_a_different_intent_is_rejected_before_any_funding(self):
        first=self.order();event,session,intent=self.receipts(first)
        self.assertTrue(self.complete(event,session,intent))
        second=self.order();event,session,intent=self.receipts(second)
        event["id"]="evt_second";session["payment_intent"]="pi_second"
        intent["id"]="pi_second";intent["latest_charge"].update(id="ch_second",payment_intent="pi_second")
        with self.assertRaises(CreditError) as caught:
            self.complete(event,session,intent)
        self.assertEqual(caught.exception.code,"payment_receipt_reused")
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],first["credit_units"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],1)

    def test_checkout_url_is_fixed_provider_origin(self):
        self.assertTrue(valid_checkout_url("https://checkout.stripe.com/c/pay/cs_test_1"))
        for url in ("https://checkout.stripe.com.evil.test/x","https://checkout.stripe.com@evil.test","http://checkout.stripe.com/x","https://user@checkout.stripe.com/x",
                    "https://checkout.stripe.com:invalid/x","https://[broken/x","https://checkout.stripe.com:444/x"):
            self.assertFalse(valid_checkout_url(url))

    def complete(self,event,session,intent):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            result=fulfill_order(self.conn,event,session,intent,self.config)
            self.conn.commit()
            return result
        except Exception:
            self.conn.rollback()
            raise

    def review(self,event,intent,**kwargs):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            result=review_payment(self.conn,event,intent,intent["latest_charge"],self.config,**kwargs)
            self.conn.commit()
            return result
        except Exception:
            self.conn.rollback()
            raise

    def review_row(self,order):
        return dict(self.conn.execute("SELECT * FROM credit_payment_reviews WHERE order_id=?",(order["id"],)).fetchone())

    def test_expanded_charge_fields_must_all_match_before_funding(self):
        order=self.order();event,session,intent=self.receipts(order)
        changes=({"paid":False},{"captured":False},{"amount":1235},{"amount_captured":1},
            {"currency":"usd"},{"livemode":True},{"payment_intent":"pi_other"},
            {"amount_refunded":True},{"amount_refunded":-1},{"amount_refunded":1235},
            {"refunded":None},{"disputed":0},{"refunded":True,"amount_refunded":0})
        for change in changes:
            changed=deepcopy(intent);changed["latest_charge"].update(change)
            with self.subTest(change=change),self.assertRaises(CreditError):
                self.complete(event,session,changed)
        for change in ({"latest_charge":"ch_1"},{"amount":True},{"amount":1235}):
            with self.subTest(change=change),self.assertRaises(CreditError):
                self.complete(event,session,{**intent,**change})
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_payment_events").fetchone()[0],0)

    def test_refund_before_success_keeps_order_unfunded(self):
        order=self.order();event,session,intent=self.receipts(order)
        intent["latest_charge"].update(refunded=True,amount_refunded=order["amount_fen"])
        refund={"id":"evt_refund","type":"charge.refunded"}
        self.assertTrue(self.review(refund,intent))
        self.assertFalse(self.complete(event,session,intent))
        review=self.review_row(order)
        self.assertEqual((review["state"],review["kind"],review["reversal_units"]),("open","refund",order["credit_units"]))
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],0)

    def test_success_then_partial_refund_never_automatically_debits_wallet(self):
        order=self.order();event,session,intent=self.receipts(order)
        self.assertTrue(self.complete(event,session,intent))
        intent["latest_charge"]["amount_refunded"]=234
        refund={"id":"evt_refund","type":"charge.refunded"}
        self.assertTrue(self.review(refund,intent))
        self.assertFalse(self.review(refund,intent))
        review=self.review_row(order)
        self.assertEqual((review["reversal_units"],review["risk_units"],review["revision"]),(234000000,234000000,1))
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],order["credit_units"])
        self.assertEqual(self.conn.execute("SELECT status FROM credit_payment_orders WHERE id=?",(order["id"],)).fetchone()[0],"payment_review")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],1)

    def test_delayed_clean_success_does_not_clear_open_refund_review(self):
        order=self.order();event,session,clean=self.receipts(order)
        refunded=deepcopy(clean);refunded["latest_charge"]["amount_refunded"]=100
        self.review({"id":"evt_refund","type":"charge.refunded"},refunded)
        self.assertFalse(self.complete(event,session,clean))
        self.assertEqual(self.review_row(order)["state"],"open")
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],0)
        self.assertEqual(self.conn.execute("SELECT status FROM credit_payment_orders WHERE id=?",(order["id"],)).fetchone()[0],"payment_review")

    def test_dispute_closed_remains_review_and_only_refunds_are_reversal_units(self):
        order=self.order();event,session,intent=self.receipts(order)
        self.review({"id":"evt_dispute","type":"charge.dispute.created"},intent,dispute=True,provider_status="needs_response")
        first=self.review_row(order)
        self.assertEqual((first["kind"],first["reversal_units"],first["risk_units"]),("dispute",0,order["credit_units"]))
        self.review({"id":"evt_closed","type":"charge.dispute.closed"},intent,dispute=True,provider_status="won")
        review=self.review_row(order)
        self.assertEqual((review["state"],review["provider_status"],review["revision"]),("open","won",2))
        self.assertFalse(self.complete(event,session,intent))
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],0)

    def test_partial_refund_does_not_erase_an_open_dispute(self):
        order=self.order();_,_,intent=self.receipts(order)
        self.review({"id":"evt_dispute","type":"charge.dispute.created"},intent,dispute=True,provider_status="under_review")
        intent["latest_charge"]["amount_refunded"]=100
        self.review({"id":"evt_refund","type":"charge.refunded"},intent)
        review=self.review_row(order)
        self.assertEqual((review["state"],review["kind"],review["provider_status"]),("open","dispute","under_review"))
        self.assertEqual((review["reversal_units"],review["risk_units"]),(100000000,order["credit_units"]))

    def test_refund_totals_never_decrease_and_new_refund_reopens_resolved_review(self):
        order=self.order();_,_,intent=self.receipts(order)
        intent["latest_charge"]["amount_refunded"]=300
        self.review({"id":"evt_refund1","type":"charge.refunded"},intent)
        intent["latest_charge"]["amount_refunded"]=100
        self.review({"id":"evt_refund2","type":"charge.refunded"},intent)
        self.assertEqual(self.review_row(order)["reversal_units"],300000000)
        self.conn.execute("UPDATE credit_payment_reviews SET state='resolved',resolved_at=?,actor_id=1,resolution_note='audited'",(now_iso(),))
        self.conn.commit()
        intent["latest_charge"]["amount_refunded"]=500
        self.review({"id":"evt_refund3","type":"charge.refunded"},intent)
        review=self.review_row(order)
        self.assertEqual((review["state"],review["reversal_units"],review["revision"]),("open",500000000,3))
        self.assertIsNone(review["resolved_at"])
        self.assertIsNone(review["actor_id"])
        self.assertIsNone(review["resolution_note"])

    def test_closed_unfunded_order_cannot_receive_delayed_success(self):
        order=self.order();event,session,intent=self.receipts(order)
        self.conn.execute("UPDATE credit_payment_orders SET status='closed' WHERE id=?",(order["id"],));self.conn.commit()
        self.assertFalse(self.complete(event,session,intent))
        self.assertEqual(wallet_snapshot(self.conn,1)["balance_units"],0)
        self.assertEqual(self.conn.execute("SELECT status FROM credit_payment_orders WHERE id=?",(order["id"],)).fetchone()[0],"closed")

    def test_review_requires_transaction_and_authoritative_order_link(self):
        order=self.order();_,_,intent=self.receipts(order)
        event={"id":"evt_refund","type":"charge.refunded"}
        intent["latest_charge"]["amount_refunded"]=100
        with self.assertRaises(CreditError) as caught:
            review_payment(self.conn,event,intent,intent["latest_charge"],self.config)
        self.assertEqual(caught.exception.code,"transaction_required")
        intent["metadata"]["order_id"]="topup_unknown"
        with self.assertRaises(CreditError):
            self.review(event,intent)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM credit_payment_reviews").fetchone()[0],0)


class CreditPaymentHTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix="credit-payment-http-")
        self.path=Path(self.directory.name)/"payments.sqlite"
        self.stack=ExitStack()
        self.addCleanup(self.cleanup)
        self.stack.enter_context(patch.object(payments,"settings",replace(payments.settings,
            app_base_url="https://api.example.test",session_secret="isolated-payment-fixture-secret-at-least-32-characters")))
        self.environment={"CREDIT_PAYMENT_PROVIDER":"stripe","CREDIT_STRIPE_SECRET_KEY":"sk_live_fixture_not_a_credential",
            "CREDIT_STRIPE_WEBHOOK_SECRET":"whsec_fixture_not_a_credential","CREDIT_STRIPE_ACCOUNT_ID":"acct_TEST",
            "CREDIT_STRIPE_LIVEMODE":"true"}
        self.stack.enter_context(patch.dict(os.environ,self.environment))
        self.stack.enter_context(patch.object(payments,"connect",self.open_database))
        with closing(self.open_database()) as conn:
            conn.executescript(db.SCHEMA)
            now=now_iso()
            conn.execute("INSERT INTO users(id,username,email,password_hash,role,status,created_at,updated_at) VALUES (1,'customer','c@example.test','unused','developer','pending',?,?)",(now,now))
            initialize_credit_schema(conn);initialize_payment_schema(conn);conn.commit()
        self.config=payment_config()
        self.calls=[]
        self.provider={}
        self.actual_async_client=httpx.AsyncClient
        self.transport=httpx.MockTransport(self.provider_response)
        self.stack.enter_context(patch.object(payments.httpx,"AsyncClient",self.mock_async_client))
        self.app=FastAPI()
        self.app.include_router(payments.router)
        self.app.dependency_overrides[require_developer]=lambda: {"id":1,"username":"customer","role":"developer","status":"pending"}
        self.client=self.stack.enter_context(TestClient(self.app,base_url="https://api.example.test",follow_redirects=False))

    def cleanup(self):
        self.stack.close()
        self.directory.cleanup()

    def open_database(self):
        conn=sqlite3.connect(self.path,timeout=15)
        conn.row_factory=sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def mock_async_client(self,*args,**kwargs):
        kwargs["transport"]=self.transport
        return self.actual_async_client(*args,**kwargs)

    def provider_response(self,request):
        self.assertEqual(request.url.host,"api.stripe.com")
        self.assertEqual(request.headers["Authorization"],"Bearer sk_live_fixture_not_a_credential")
        self.calls.append(request)
        key=(request.method,request.url.path.removeprefix("/v1/"))
        if key not in self.provider:
            self.fail(f"Unexpected synthetic Stripe request: {key}")
        result=self.provider[key]
        if callable(result):
            result=result(request)
        return httpx.Response(200,json=deepcopy(result),request=request)

    def order(self,fen=1234):
        with closing(self.open_database()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            result=claim_order(conn,1,topup_nonce(1),fen,self.config)
            conn.commit()
            return result

    def receipts(self,order):
        session={"id":"cs_live_fixture","mode":"payment","payment_status":"paid","status":"complete","currency":"cny",
            "amount_total":order["amount_fen"],"client_reference_id":order["id"],"metadata":{"order_id":order["id"]},
            "livemode":True,"payment_intent":"pi_fixture"}
        charge={"id":"ch_fixture","payment_intent":"pi_fixture","paid":True,"captured":True,"amount":order["amount_fen"],
            "amount_captured":order["amount_fen"],"currency":"cny","livemode":True,"refunded":False,"amount_refunded":0,"disputed":False}
        intent={"id":"pi_fixture","status":"succeeded","amount":order["amount_fen"],"amount_received":order["amount_fen"],
            "currency":"cny","livemode":True,"metadata":{"order_id":order["id"]},"latest_charge":charge}
        self.provider={
            ("GET","account"):{"id":"acct_TEST"},
            ("GET","checkout/sessions/cs_live_fixture"):session,
            ("GET","payment_intents/pi_fixture"):intent,
            ("GET","charges/ch_fixture"):charge,
            ("GET","disputes/dp_fixture"):{"id":"dp_fixture","livemode":True,"charge":"ch_fixture","payment_intent":"pi_fixture",
                "amount":order["amount_fen"],"currency":"cny","status":"needs_response"},
        }
        return session,intent,charge

    def webhook(self,event_id,event_type,obj,**event_fields):
        body=json.dumps({"id":event_id,"type":event_type,"livemode":True,"data":{"object":obj},**event_fields},separators=(",",":")).encode()
        stamp=str(int(time.time()))
        digest=hmac.new(self.environment["CREDIT_STRIPE_WEBHOOK_SECRET"].encode(),stamp.encode()+b"."+body,hashlib.sha256).hexdigest()
        return self.client.post("/api/payments/stripe/webhook",content=body,
            headers={"Stripe-Signature":f"t={stamp},v1={digest}","Content-Type":"application/json"})

    def state(self,order):
        with closing(self.open_database()) as conn:
            wallet=wallet_snapshot(conn,1)
            stored=dict(conn.execute("SELECT * FROM credit_payment_orders WHERE id=?",(order["id"],)).fetchone())
            review=conn.execute("SELECT * FROM credit_payment_reviews WHERE order_id=?",(order["id"],)).fetchone()
            return wallet,stored,dict(review) if review else None

    def assert_expanded_pi(self):
        requests=[r for r in self.calls if r.url.path=="/v1/payment_intents/pi_fixture"]
        self.assertTrue(requests)
        self.assertTrue(all(r.url.params.get("expand[]")=="latest_charge" for r in requests))

    def test_production_configuration_rejects_all_test_modes_and_test_keys(self):
        self.assertTrue(payment_config()["live"])
        for env in ({"CREDIT_STRIPE_LIVEMODE":"false"},{"CREDIT_STRIPE_LIVEMODE":"0"},
                    {"CREDIT_STRIPE_LIVEMODE":"test"},{"CREDIT_STRIPE_SECRET_KEY":"sk_test_fixture"},
                    {"CREDIT_STRIPE_SECRET_KEY":"sk_test_fixture","CREDIT_STRIPE_LIVEMODE":"false"}):
            with self.subTest(env=env),patch.dict(os.environ,env):
                self.assertIsNone(payment_config())
                self.assertIsNone(payment_config(for_webhook=True))
                response=self.webhook("evt_testmode","checkout.session.completed",{"id":"cs_live_fixture"})
                self.assertEqual(response.status_code,503)
        self.assertEqual(self.calls,[])

    def test_pausing_new_payments_preserves_existing_live_webhook(self):
        order=self.order();self.receipts(order)
        with patch.dict(os.environ,{"CREDIT_PAYMENT_PROVIDER":""}):
            self.assertIsNone(payment_config())
            self.assertTrue(payment_config(for_webhook=True)["live"])
            response=self.webhook("evt_paid","checkout.session.completed",{"id":"cs_live_fixture"})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.state(order)[0]["balance_units"],order["credit_units"])
        self.assert_expanded_pi()

    def test_http_refund_first_matches_trusted_intent_metadata_and_never_funds(self):
        order=self.order();_,_,charge=self.receipts(order)
        charge.update(refunded=True,amount_refunded=order["amount_fen"])
        response=self.webhook("evt_refund","charge.refunded",{"id":"ch_fixture","payment_intent":"pi_untrusted","amount_refunded":0})
        self.assertEqual(response.status_code,200)
        response=self.webhook("evt_success","checkout.session.completed",{"id":"cs_live_fixture","amount_total":1})
        self.assertEqual(response.status_code,200)
        wallet,stored,review=self.state(order)
        self.assertEqual(wallet["balance_units"],0)
        self.assertEqual((stored["status"],stored["payment_intent"]),("payment_review","pi_fixture"))
        self.assertEqual(review["reversal_units"],order["credit_units"])
        self.assert_expanded_pi()

    def test_http_success_first_refund_then_clean_success_stays_review(self):
        order=self.order();_,_,charge=self.receipts(order)
        self.assertEqual(self.webhook("evt_success","checkout.session.completed",{"id":"cs_live_fixture"}).status_code,200)
        charge["amount_refunded"]=123
        self.assertEqual(self.webhook("evt_refund","charge.refunded",{"id":"ch_fixture"}).status_code,200)
        charge["amount_refunded"]=0
        self.assertEqual(self.webhook("evt_late","checkout.session.async_payment_succeeded",{"id":"cs_live_fixture"}).status_code,200)
        wallet,stored,review=self.state(order)
        self.assertEqual(wallet["balance_units"],order["credit_units"])
        self.assertEqual((stored["status"],review["state"],review["reversal_units"]),("payment_review","open",123000000))
        with closing(self.open_database()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],1)

    def test_http_dispute_events_refetch_resources_and_closed_does_not_release(self):
        order=self.order();self.receipts(order)
        for number,event_type,status in ((1,"charge.dispute.created","needs_response"),
                                        (2,"charge.dispute.updated","under_review"),(3,"charge.dispute.closed","won")):
            self.provider[("GET","disputes/dp_fixture")]["status"]=status
            response=self.webhook("evt_dispute"+str(number),event_type,{"id":"dp_fixture","charge":"ch_untrusted","amount":1,"status":"lost"})
            self.assertEqual(response.status_code,200)
        response=self.webhook("evt_success","checkout.session.completed",{"id":"cs_live_fixture"})
        self.assertEqual(response.status_code,200)
        wallet,stored,review=self.state(order)
        self.assertEqual(wallet["balance_units"],0)
        self.assertEqual((stored["status"],review["state"],review["kind"],review["provider_status"]),("payment_review","open","dispute","won"))
        self.assertEqual((review["reversal_units"],review["risk_units"],review["revision"]),(0,order["credit_units"],3))
        self.assertEqual(sum(r.url.path=="/v1/disputes/dp_fixture" for r in self.calls),3)
        self.assert_expanded_pi()

    def test_unconfirmed_refund_and_wrong_merchant_do_not_change_wallet(self):
        order=self.order();self.receipts(order)
        self.assertEqual(self.webhook("evt_fake","charge.refunded",{"id":"ch_fixture","amount_refunded":1234}).status_code,409)
        self.provider[("GET","account")]["id"]="acct_OTHER"
        self.assertEqual(self.webhook("evt_wrong","checkout.session.completed",{"id":"cs_live_fixture"}).status_code,503)
        wallet,stored,review=self.state(order)
        self.assertEqual(wallet["balance_units"],0)
        self.assertIsNone(review)
        self.assertEqual(stored["status"],"created")

    def test_bad_signature_or_test_mode_event_never_calls_provider(self):
        response=self.client.post("/api/payments/stripe/webhook",content=b"{}",headers={"Stripe-Signature":"t=0,v1=bad"})
        self.assertEqual(response.status_code,400)
        self.assertEqual(self.webhook("evt_wrongmode","charge.refunded",{"id":"ch_fixture"},livemode=False).status_code,400)
        self.assertEqual(self.webhook("evt_connect","charge.refunded",{"id":"ch_fixture"},account="acct_OTHER").status_code,400)
        self.assertEqual(self.calls,[])

    def test_http_replay_is_idempotent_for_review_and_success(self):
        order=self.order();_,_,charge=self.receipts(order)
        for _ in range(2):
            self.assertEqual(self.webhook("evt_success","checkout.session.completed",{"id":"cs_live_fixture"}).status_code,200)
        charge["amount_refunded"]=100
        for _ in range(2):
            self.assertEqual(self.webhook("evt_refund","charge.refunded",{"id":"ch_fixture"}).status_code,200)
        wallet,_,review=self.state(order)
        self.assertEqual(wallet["balance_units"],order["credit_units"])
        self.assertEqual(review["revision"],1)
        with closing(self.open_database()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM credit_payment_events").fetchone()[0],2)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],1)

    def test_concurrent_success_and_refund_replays_have_one_credit_and_one_review(self):
        order=self.order();_,_,charge=self.receipts(order)
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda number:self.webhook("evt_paid"+str(number),"checkout.session.completed",{"id":"cs_live_fixture"}),range(2)))
        self.assertEqual([r.status_code for r in responses],[200,200])
        charge["amount_refunded"]=123
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda _:self.webhook("evt_refund","charge.refunded",{"id":"ch_fixture"}),range(2)))
        self.assertEqual([r.status_code for r in responses],[200,200])
        wallet,stored,review=self.state(order)
        self.assertEqual(wallet["balance_units"],order["credit_units"])
        self.assertEqual((stored["status"],review["revision"]),("payment_review",1))
        with closing(self.open_database()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM credit_payment_events").fetchone()[0],3)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone()[0],1)

    def test_checkout_creation_disables_variable_amount_features_and_reuses_nonce(self):
        captured=[]
        self.provider[("GET","account")]={"id":"acct_TEST"}
        def created(request):
            form=dict(httpx.QueryParams(request.content.decode()))
            captured.append((request.headers["Idempotency-Key"],form))
            return {"id":"cs_live_fixture","livemode":True,"url":"https://checkout.stripe.com/c/pay/cs_live_fixture"}
        self.provider[("POST","checkout/sessions")]=created
        nonce=topup_nonce(1)
        for _ in range(2):
            response=self.client.post("/developer/credits/topup",data={"amount_cny":"12.34","nonce":nonce})
            self.assertEqual(response.status_code,200)
        self.assertEqual(len(captured),1)
        order_id,form=captured[0]
        self.assertEqual(form["adaptive_pricing[enabled]"],"false")
        self.assertEqual(form["automatic_tax[enabled]"],"false")
        self.assertEqual(form["allow_promotion_codes"],"false")
        self.assertEqual(form["line_items[0][price_data][unit_amount]"],"1234")
        self.assertEqual(form["payment_intent_data[metadata][order_id]"],order_id)
        self.assertEqual(form["success_url"],"https://api.example.test/developer/credits?payment=returned")
        self.assertEqual(self.state({"id":order_id})[0]["balance_units"],0)

    def test_continue_payment_is_same_origin_owned_and_live_without_provider_call(self):
        order=self.order()
        with closing(self.open_database()) as conn:
            conn.execute("UPDATE credit_payment_orders SET status='awaiting_payment',checkout_url=? WHERE id=?",
                ("https://checkout.stripe.com/c/pay/cs_live_fixture",order["id"]));conn.commit()
        with patch.dict(os.environ,{"CREDIT_PAYMENT_PROVIDER":""}):
            response=self.client.get("/developer/credits/orders/"+order["id"]+"/pay")
        self.assertEqual(response.status_code,303)
        self.assertEqual(response.headers["Location"],"https://checkout.stripe.com/c/pay/cs_live_fixture")
        self.assertEqual(response.headers["Cache-Control"],"no-store")
        self.assertEqual(response.headers["Referrer-Policy"],"no-referrer")
        self.app.dependency_overrides[require_developer]=lambda: {"id":2}
        self.assertEqual(self.client.get("/developer/credits/orders/"+order["id"]+"/pay").status_code,404)
        self.assertEqual(self.calls,[])

    def test_continue_payment_rejects_closed_review_test_mode_and_invalid_url(self):
        order=self.order()
        for values in ({"status":"payment_review"},{"status":"closed"},{"status":"paid"},
                        {"livemode":0},{"provider_account":"acct_OTHER"},
                        {"checkout_url":"https://checkout.stripe.com.evil.test/pay"}):
            with closing(self.open_database()) as conn:
                conn.execute("UPDATE credit_payment_orders SET status='awaiting_payment',livemode=1,provider_account='acct_TEST',checkout_url=? WHERE id=?",
                    ("https://checkout.stripe.com/c/pay/cs_live_fixture",order["id"]))
                for name,value in values.items():
                    conn.execute(f"UPDATE credit_payment_orders SET {name}=? WHERE id=?",(value,order["id"]))
                conn.commit()
            with self.subTest(values=values):
                self.assertEqual(self.client.get("/developer/credits/orders/"+order["id"]+"/pay").status_code,409)
        self.assertEqual(self.calls,[])


if __name__=="__main__":
    unittest.main()
