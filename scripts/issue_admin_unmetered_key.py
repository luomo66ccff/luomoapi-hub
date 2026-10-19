"""Issue one auditable administrator-only key, keeping plaintext server-private."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.config import settings
from app.db import connect
from app.keyring import generate_api_key,hash_api_key,verify_api_key
from app.utils.timefmt import now_iso

NAME='管理员专属全模型无限额 t001'
SCOPES='models:read,chat:completions,responses:create,admin:unmetered'
folder=settings.database_path.parent/'private-credentials'
folder.mkdir(mode=0o700,exist_ok=True)
assert not folder.is_symlink()
path=folder/'admin-unmetered-key_t001.json'
if path.exists():
 assert not path.is_symlink()
 credential=json.loads(path.read_text())
else:
 raw,prefix=generate_api_key()
 credential={'api_key':raw,'prefix':prefix,'base_url':settings.app_base_url.rstrip('/')+'/v1','https_port':443,'name':NAME}
 with path.open('x') as out:
  os.chmod(path,0o600);json.dump(credential,out);out.flush();os.fsync(out.fileno())

with connect() as conn:
 conn.execute('BEGIN IMMEDIATE')
 user=conn.execute('SELECT * FROM users WHERE username=?',(settings.admin_username,)).fetchone()
 assert user and user['role']=='admin' and user['status']=='active','Configured owner is not an active administrator'
 row=conn.execute('SELECT * FROM api_keys WHERE user_id=? AND name=?',(user['id'],NAME)).fetchone()
 if row:
  assert row['status']=='active' and row['scopes']==SCOPES and row['model_policy']=='all'
  assert all(row[name]==0 for name in ('rate_limit_per_minute','daily_quota','monthly_quota')) and row['expires_at'] is None
  assert verify_api_key(credential['api_key'],row['key_hash']),'Existing named key differs; do not rotate silently'
  key_id=row['id']
 else:
  now=now_iso()
  cur=conn.execute("INSERT INTO api_keys(user_id,name,key_prefix,key_hash,status,scopes,allowed_routes,model_policy,rate_limit_per_minute,daily_quota,monthly_quota,created_at,approved_at,expires_at) VALUES(?,?,?,?,'active',?,'','all',0,0,0,?,?,NULL)",
   (user['id'],NAME,credential['prefix'],hash_api_key(credential['api_key']),SCOPES,now,now))
  key_id=int(cur.lastrowid)
  conn.execute("INSERT INTO credit_admin_audit(reference,actor_id,action,user_id,reason,created_at) VALUES(?,?,'admin_unmetered_key_created',?,?,?)",
   ('admin-unmetered-key:t001',user['id'],user['id'],'Owner requested administrator-only all-model unlimited key; key_id='+str(key_id),now))
 conn.commit()

credential.update(key_id=key_id,owner_id=user['id'],owner=user['username'],status='active',billing='admin_exempt',model_policy='all',scopes=SCOPES,rate_limit_per_minute=0,daily_quota=0,monthly_quota=0,expires_at=None)
temporary=path.with_suffix('.writing')
with temporary.open('x') as out:
 os.chmod(temporary,0o600);json.dump(credential,out,ensure_ascii=False,indent=2);out.flush();os.fsync(out.fileno())
os.replace(temporary,path)
print(json.dumps({'status':'issued','key_id':key_id,'prefix':credential['prefix'],'owner':user['username'],'model_policy':'all','billing':'admin_exempt','rate_limit_per_minute':0,'daily_quota':0,'monthly_quota':0,'plaintext_path':str(path)}))
