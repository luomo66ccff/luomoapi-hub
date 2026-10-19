"""Local-only disposable browser fixture; no upstream or mail credentials."""
import os
from pathlib import Path
from contextlib import closing

project=Path(__file__).resolve().parent.parent
os.environ["DATABASE_PATH"]=str(project.parent/"output"/"browser-fixture.sqlite")
os.environ["SESSION_SECRET"]="local-browser-fixture-secret-only-over-32-characters"
os.environ["APP_BASE_URL"]="http://127.0.0.1:8793"
os.environ["CODEXPROXY_API_KEY"]=""
os.environ["CREDIT_PAYMENT_PROVIDER"]=""

from app.db import connect,init_db
from app.auth import hash_password
from app.utils.timefmt import now_iso
init_db()
with closing(connect()) as conn:
    for name,role,status in (("qa_admin","admin","active"),("qa_registered","developer","pending")):
        conn.execute("INSERT OR IGNORE INTO users(username,email,password_hash,role,status,email_verified,created_at,updated_at) VALUES (?,?,?,?,?,0,?,?)",
            (name,name+"@example.test",hash_password("FixtureOnly-2026"),role,status,now_iso(),now_iso()))
    conn.commit()
from app.main import app
# The app always marks auth cookies Secure in production. This isolated
# localhost wrapper allows browser validation without changing production.
@app.middleware("http")
async def fixture_cookies(request,call_next):
    response=await call_next(request)
    if "set-cookie" in response.headers:
        response.headers["set-cookie"]=response.headers["set-cookie"].replace("; Secure","")
    return response

if __name__=="__main__":
    import uvicorn
    uvicorn.run(app,host="127.0.0.1",port=8793)
