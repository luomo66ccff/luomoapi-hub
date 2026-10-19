"""Bounded actual-upstream acceptance against a named isolated candidate DB."""
import json
import secrets
from contextlib import closing
import httpx
from app.config import settings
from app.db import connect
from app.credit_ledger import add_credit, wallet_snapshot
from app.self_service_keys import issue_self_key, self_key_nonce
from app.utils.timefmt import now_iso

if settings.database_path.name != "credit-candidate.sqlite":
    raise RuntimeError("This probe is only authorized on credit-candidate.sqlite.")

batch=secrets.token_hex(5)
def fixture(case,fund=True):
    with closing(connect()) as conn:
        now=now_iso()
        user=conn.execute("""INSERT INTO users(username,email,password_hash,role,status,email_verified,created_at,updated_at)
            VALUES (?,?, 'not-a-login-password','developer','pending',0,?,?)""",
            ("qa_credit_"+batch+"_"+case,"qa_"+batch+"_"+case+"@example.test",now,now)).lastrowid
        conn.commit()
        if fund:
            conn.execute("BEGIN IMMEDIATE")
            add_credit(conn,user,40_000_000,reference=f"candidate:fund:{user}",actor_id=None,kind="candidate_funding",note="Isolated candidate acceptance only")
            conn.commit()
        key=issue_self_key(conn,user,"candidate-"+case,self_key_nonce(user))["raw_key"]
        conn.commit()
        return user,key

with httpx.Client(base_url="http://127.0.0.1:8790",timeout=90,trust_env=False) as client:
    ready=client.get("/ready")
    assert ready.status_code==200,ready.status_code
    empty_user,empty_key=fixture("empty",False)
    headers={"Authorization":"Bearer "+empty_key}
    models=client.get("/v1/models",headers=headers)
    assert models.status_code==200 and "gpt-6-luna" in {m["id"] for m in models.json()["data"]}
    empty=client.post("/v1/chat/completions",headers=headers,json={"model":"gpt-6-luna","messages":[{"role":"user","content":"Reply only OK."}],"max_completion_tokens":16})
    assert empty.status_code==402,empty.status_code
    with closing(connect()) as conn:
        assert wallet_snapshot(conn,empty_user)["balance_units"]==0
        assert conn.execute("SELECT COUNT(*) FROM credit_holds WHERE user_id=?",(empty_user,)).fetchone()[0]==0
    print(json.dumps({"case":"zero_balance_models_free","models_status":models.status_code,"generation_status":empty.status_code,"holds":0}),flush=True)
    for protocol,stream in (("chat.completions",False),("chat.completions",True),("responses",False),("responses",True)):
        name=protocol.replace(".","_")+("_sse" if stream else "_json")
        user,key=fixture(name)
        headers={"Authorization":"Bearer "+key}
        if protocol=="responses":
            path="/v1/responses";body={"model":"gpt-6-luna","input":"Reply only OK.","max_output_tokens":16,"stream":stream}
        else:
            path="/v1/chat/completions";body={"model":"gpt-6-luna","messages":[{"role":"user","content":"Reply only OK."}],"max_completion_tokens":16,"stream":stream}
        response=client.post(path,headers=headers,json=body)
        with closing(connect()) as conn:
            row=dict(conn.execute("SELECT status_code,outcome,input_tokens,output_tokens,total_tokens,credit_status,credit_charged_units,credit_reason FROM api_usage_logs WHERE user_id=? AND protocol=? ORDER BY id DESC LIMIT 1",(user,protocol)).fetchone())
            wallet=wallet_snapshot(conn,user)
            result={"case":name,"http":response.status_code,**row,"balance_units":wallet["balance_units"],"reserved_units":wallet["reserved_units"]}
            print(json.dumps(result),flush=True)
            assert response.status_code==200,result
            assert row["credit_status"]=="settled" and row["credit_charged_units"]>0,result
            assert wallet["reserved_units"]==0 and wallet["balance_units"]==40_000_000-row["credit_charged_units"],result
print(json.dumps({"status":"passed","batch":batch,"generation_requests":4}),flush=True)
