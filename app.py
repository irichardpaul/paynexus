from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).parent
DB_PATH = Path(os.environ.get("PAYNEXUS_DB", ROOT / "paynexus.sqlite3"))
PORT = int(os.environ.get("PORT", "8000"))
LOCK = threading.RLock()
ROLES = {"Student Analyst", "SOC Analyst", "Security Administrator", "Executive"}
STAGES = ["Detection", "Analysis", "Containment", "Eradication", "Recovery", "Closed"]
SCENARIO_NAME = "Suspicious Transaction API Activity"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def digest(password, salt=None):
    salt = salt or secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 240000)
    return salt, key.hex()


def initialize():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK, db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions(id TEXT PRIMARY KEY, merchant TEXT NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL, event TEXT NOT NULL, severity TEXT NOT NULL, actor TEXT NOT NULL, ip TEXT NOT NULL, detail TEXT NOT NULL, scenario_id TEXT NOT NULL DEFAULT 'baseline');
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, stage TEXT NOT NULL, owner TEXT NOT NULL, summary TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, category TEXT NOT NULL, evidence TEXT NOT NULL, recommendation TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Submitted', score INTEGER, feedback TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS controls(id TEXT PRIMARY KEY, name TEXT NOT NULL, framework TEXT NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        if not c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            demo = [("instructor", "Instructor", "Security Administrator", "PayNexus!2026"),
                    ("student1", "Student Analyst", "Student Analyst", "Analyst!2026"),
                    ("soc1", "SOC Analyst", "SOC Analyst", "SOC!2026"),
                    ("exec1", "Executive Viewer", "Executive", "Executive!2026")]
            for username, name, role, password in demo:
                s, h = digest(password)
                c.execute("INSERT INTO users(username,display_name,role,salt,password_hash,created_at) VALUES(?,?,?,?,?,?)", (username,name,role,s,h,now()))
        if not c.execute("SELECT 1 FROM transactions LIMIT 1").fetchone():
            for row in [("TX-84021","Mabuhay Market",1240.50,"Approved"),("TX-84022","Northstar Travel",8500,"Review"),("TX-84023","SariPay Online",399.90,"Approved"),("TX-84024","Harbor Goods",24800,"Flagged"),("TX-84025","Kubo Digital",1750,"Approved")]:
                c.execute("INSERT INTO transactions VALUES(?,?,?,?,?)", (*row,now()))
        if not c.execute("SELECT 1 FROM controls LIMIT 1").fetchone():
            for row in [("AC-2","Account management","NIST SP 800-53","In progress","Identity Team"),("SC-8","Transmission confidentiality","NIST SP 800-53","Implemented","Platform Security"),("A.8.15","Logging","ISO/IEC 27001","In progress","SOC"),("A.5.30","ICT readiness for business continuity","ISO/IEC 27001","Needs review","Resilience Team"),("PCI-10","Log and monitor access","PCI DSS","Implemented","SOC")]:
                c.execute("INSERT INTO controls VALUES(?,?,?,?,?)", row)
        if not c.execute("SELECT 1 FROM alerts LIMIT 1").fetchone():
            samples = [("Unusual API enumeration","High","API Gateway","Open","Burst of transaction lookup requests across multiple customer IDs."),("Privileged login outside baseline","Medium","Authentication","Open","Administrative sign-in from an unfamiliar network range."),("Database query volume spike","High","Database","Investigating","Read volume exceeded the normal service profile.")]
            for title,sev,src,status,detail in samples: c.execute("INSERT INTO alerts(title,severity,source,status,detail,created_at) VALUES(?,?,?,?,?,?)",(title,sev,src,status,detail,now()))
        if not c.execute("SELECT 1 FROM incidents LIMIT 1").fetchone():
            c.execute("INSERT INTO incidents(title,severity,stage,owner,summary,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",("Suspicious Transaction API Activity","High","Analysis","SOC Team","Investigate repeated transaction-record API requests and possible unauthorized data access.",now(),now()))
        c.execute("INSERT OR IGNORE INTO settings VALUES('scenario_runs','0')")
        c.commit()


def asdict(row): return dict(row) if row else None


class Handler(BaseHTTPRequestHandler):
    server_version = "PayNexusLearning/1.0"
    def log_message(self, fmt, *args): pass
    def send_json(self, data, status=200):
        raw = json.dumps(data).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(raw)
    def body(self):
        try: return json.loads(self.rfile.read(int(self.headers.get("Content-Length",0))) or b"{}")
        except Exception: raise ValueError("Request body must be valid JSON")
    def current_user(self):
        jar=SimpleCookie(); jar.load(self.headers.get("Cookie","")); morsel=jar.get("paynexus_session")
        if not morsel: return None
        with db() as c:
            row=c.execute("SELECT u.id,u.username,u.display_name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>? AND u.active=1",(morsel.value,int(time.time()))).fetchone()
            return asdict(row)
    def require(self, roles=None):
        user=self.current_user()
        if not user: self.send_json({"error":"Sign in required"},401); return None
        if roles and user["role"] not in roles: self.send_json({"error":"Your role cannot perform this action"},403); return None
        return user
    def audit(self,user,action,detail,conn):
        conn.execute("INSERT INTO audit(user_id,action,detail,created_at) VALUES(?,?,?,?)",(user["id"],action,detail[:500],now()))
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/" or path=="/index.html":
            file=ROOT/"static"/"index.html"; data=file.read_bytes(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data); return
        if path=="/api/me":
            u=self.current_user(); self.send_json({"user":u}); return
        if not path.startswith("/api/"): self.send_json({"error":"Not found"},404); return
        u=self.require()
        if not u:return
        params=parse_qs(urlparse(self.path).query)
        q=params.get("q",[""])[0].strip(); source=params.get("source",[""])[0]; sev=params.get("severity",[""])[0]
        with db() as c:
            if path=="/api/overview":
                out={"transactions":c.execute("SELECT COUNT(*) n FROM transactions").fetchone()["n"],"alerts":c.execute("SELECT COUNT(*) n FROM alerts WHERE status!='Resolved'").fetchone()["n"],"incidents":c.execute("SELECT COUNT(*) n FROM incidents WHERE stage!='Closed'").fetchone()["n"],"findings":c.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"],"recent": [dict(r) for r in c.execute("SELECT timestamp,source,event,severity,actor FROM logs ORDER BY id DESC LIMIT 6")],"scenario_runs":c.execute("SELECT value FROM settings WHERE key='scenario_runs'").fetchone()[0]}
                self.send_json(out); return
            if path=="/api/transactions": self.send_json([dict(r) for r in c.execute("SELECT * FROM transactions ORDER BY created_at DESC")]); return
            if path=="/api/alerts": self.send_json([dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY id DESC")]); return
            if path=="/api/logs":
                sql="SELECT * FROM logs WHERE (event LIKE ? OR detail LIKE ? OR actor LIKE ? OR ip LIKE ?)"; args=[f"%{q}%"]*4
                if source: sql+=" AND source=?"; args.append(source)
                if sev: sql+=" AND severity=?"; args.append(sev)
                sql+=" ORDER BY id DESC LIMIT 300"; self.send_json([dict(r) for r in c.execute(sql,args)]); return
            if path=="/api/incidents": self.send_json([dict(r) for r in c.execute("SELECT * FROM incidents ORDER BY id DESC")]); return
            if path=="/api/findings":
                if u["role"] in ("Security Administrator","Executive"): rows=c.execute("SELECT f.*,u.display_name submitter FROM findings f JOIN users u ON u.id=f.user_id ORDER BY f.id DESC")
                else: rows=c.execute("SELECT f.*,u.display_name submitter FROM findings f JOIN users u ON u.id=f.user_id WHERE f.user_id=? ORDER BY f.id DESC",(u["id"],))
                self.send_json([dict(r) for r in rows]); return
            if path=="/api/controls": self.send_json([dict(r) for r in c.execute("SELECT * FROM controls ORDER BY id")]); return
            if path=="/api/users":
                if u["role"]!="Security Administrator": self.send_json({"error":"Forbidden"},403); return
                self.send_json([dict(r) for r in c.execute("SELECT id,username,display_name,role,active,created_at FROM users ORDER BY id")]); return
            if path=="/api/activity":
                if u["role"]!="Security Administrator": self.send_json({"error":"Forbidden"},403); return
                self.send_json([dict(r) for r in c.execute("SELECT a.*,u.display_name FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200")]); return
        self.send_json({"error":"Not found"},404)
    def do_POST(self):
        path=urlparse(self.path).path
        try: d=self.body()
        except ValueError as e: self.send_json({"error":str(e)},400); return
        if path=="/api/login":
            username=str(d.get("username",""))[:80].strip(); password=str(d.get("password",""))
            with db() as c:
                r=c.execute("SELECT * FROM users WHERE username=? AND active=1",(username,)).fetchone()
                if not r: self.send_json({"error":"Incorrect username or password"},401); return
                _,h=digest(password,r["salt"])
                if not hmac.compare_digest(h,r["password_hash"]): self.send_json({"error":"Incorrect username or password"},401); return
                token=secrets.token_urlsafe(40); c.execute("INSERT INTO sessions VALUES(?,?,?)",(token,r["id"],int(time.time())+43200)); c.execute("INSERT INTO audit(user_id,action,detail,created_at) VALUES(?,?,?,?)",(r["id"],"Signed in","",now()))
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Set-Cookie",f"paynexus_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200" + ("; Secure" if os.environ.get("COOKIE_SECURE")=="1" else "")); self.end_headers(); self.wfile.write(json.dumps({"user":{"username":r["username"],"display_name":r["display_name"],"role":r["role"]}}).encode()); return
        if path=="/api/logout":
            cookie=SimpleCookie(); cookie.load(self.headers.get("Cookie","")); m=cookie.get("paynexus_session")
            if m:
                with db() as c: c.execute("DELETE FROM sessions WHERE token=?",(m.value,))
            self.send_response(200); self.send_header("Set-Cookie","paynexus_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"); self.end_headers(); return
        u=self.require()
        if not u:return
        role=u["role"]
        try:
            with LOCK, db() as c:
                if path=="/api/password":
                    existing=str(d.get("current_password","")); newpass=str(d.get("new_password",""))
                    row=c.execute("SELECT salt,password_hash FROM users WHERE id=?",(u["id"],)).fetchone()
                    _,candidate=digest(existing,row["salt"])
                    if not hmac.compare_digest(candidate,row["password_hash"]): self.send_json({"error":"Current password is incorrect"},400); return
                    if len(newpass)<12: self.send_json({"error":"New password must be at least 12 characters"},400); return
                    salt,pwhash=digest(newpass); c.execute("UPDATE users SET salt=?,password_hash=? WHERE id=?",(salt,pwhash,u["id"]))
                    cookie=SimpleCookie(); cookie.load(self.headers.get("Cookie","")); m=cookie.get("paynexus_session")
                    c.execute("DELETE FROM sessions WHERE user_id=?",(u["id"],))
                    if m: c.execute("INSERT INTO sessions VALUES(?,?,?)",(m.value,u["id"],int(time.time())+43200))
                    self.audit(u,"Changed password","",c); self.send_json({"ok":True}); return
                if path=="/api/findings" and role in ("Student Analyst","SOC Analyst"):
                    title=str(d.get("title","")).strip(); evidence=str(d.get("evidence","")).strip()
                    if not title or not evidence: self.send_json({"error":"Title and evidence are required"},400); return
                    c.execute("INSERT INTO findings(user_id,title,category,evidence,recommendation,created_at) VALUES(?,?,?,?,?,?)",(u["id"],title,str(d.get("category","Threat analysis"))[:80],evidence[:5000],str(d.get("recommendation",""))[:3000],now())); self.audit(u,"Submitted finding",title,c); self.send_json({"ok":True},201); return
                if path.startswith("/api/alerts/") and path.endswith("/status") and role in ("SOC Analyst","Security Administrator"):
                    ident=path.split("/")[3]; status=str(d.get("status",""))
                    if status not in ("Open","Investigating","Resolved"): self.send_json({"error":"Invalid status"},400); return
                    c.execute("UPDATE alerts SET status=? WHERE id=?",(status,ident)); self.audit(u,"Updated alert",f"{ident}: {status}",c); self.send_json({"ok":True}); return
                if path.startswith("/api/incidents/") and path.endswith("/stage") and role in ("SOC Analyst","Security Administrator"):
                    ident=path.split("/")[3]; stage=str(d.get("stage",""))
                    if stage not in STAGES: self.send_json({"error":"Invalid incident stage"},400); return
                    c.execute("UPDATE incidents SET stage=?,updated_at=? WHERE id=?",(stage,now(),ident)); self.audit(u,"Advanced incident workflow",f"{ident}: {stage}",c); self.send_json({"ok":True}); return
                if path=="/api/scenario/run" and role in ("SOC Analyst","Security Administrator"):
                    run=int(c.execute("SELECT value FROM settings WHERE key='scenario_runs'").fetchone()[0])+1; c.execute("UPDATE settings SET value=? WHERE key='scenario_runs'",(str(run),))
                    scenario=f"run-{run}"; stamp=now()
                    events=[("Authentication","Repeated failed sign-in","High","api-service","203.0.113.42","Five failures against service account before successful authentication."),("API","Transaction records enumerated","Critical","svc-api","203.0.113.42","Rapid lookup requests used sequential customer references."),("Application","Authorization check bypass suspected","High","svc-api","203.0.113.42","Requests returned records outside the caller's assigned test profile."),("Database","Unusual customer-record read","Critical","db-reader","10.20.4.18","Read volume exceeded baseline; synthetic records only.")]
                    for src,event,s,actor,ip,detail in events: c.execute("INSERT INTO logs(timestamp,source,event,severity,actor,ip,detail,scenario_id) VALUES(?,?,?,?,?,?,?,?)",(stamp,src,event,s,actor,ip,detail,scenario))
                    c.execute("INSERT INTO alerts(title,severity,source,status,detail,created_at) VALUES(?,?,?,?,?,?)",(f"Scenario {run}: suspicious API access","Critical","API Gateway","Open","Controlled synthetic sequence: authentication anomalies followed by API enumeration and unusual database reads.",stamp))
                    c.execute("INSERT INTO incidents(title,severity,stage,owner,summary,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(f"Scenario {run}: transaction API investigation","Critical","Detection",u["display_name"],"Determine affected identities and records from the synthetic authentication, API, application, and database event trail.",stamp,stamp))
                    self.audit(u,"Started simulation",f"Scenario run {run}",c); self.send_json({"ok":True,"run":run}); return
                if path=="/api/scenario/reset" and role=="Security Administrator":
                    c.execute("DELETE FROM logs WHERE scenario_id!='baseline'"); c.execute("DELETE FROM alerts WHERE title LIKE 'Scenario %'"); c.execute("DELETE FROM incidents WHERE title LIKE 'Scenario %'"); c.execute("UPDATE settings SET value='0' WHERE key='scenario_runs'"); self.audit(u,"Reset simulation","Removed generated scenario data",c); self.send_json({"ok":True}); return
                if path=="/api/users" and role=="Security Administrator":
                    username=str(d.get("username","")).strip().lower(); name=str(d.get("display_name","")).strip(); password=str(d.get("password","")); newrole=str(d.get("role",""))
                    if len(username)<3 or not name or len(password)<12 or newrole not in ROLES: self.send_json({"error":"Provide a username, display name, valid role, and password of at least 12 characters"},400); return
                    s,h=digest(password)
                    try: c.execute("INSERT INTO users(username,display_name,role,salt,password_hash,created_at) VALUES(?,?,?,?,?,?)",(username,name,newrole,s,h,now()))
                    except sqlite3.IntegrityError: self.send_json({"error":"That username already exists"},409); return
                    self.audit(u,"Created account",f"{username} ({newrole})",c); self.send_json({"ok":True},201); return
                if path.startswith("/api/users/") and path.endswith("/active") and role=="Security Administrator":
                    ident=int(path.split("/")[3]); active=1 if d.get("active") else 0
                    if ident==u["id"] and not active: self.send_json({"error":"You cannot disable your own account"},400); return
                    c.execute("UPDATE users SET active=? WHERE id=?",(active,ident)); c.execute("DELETE FROM sessions WHERE user_id=?",(ident,)); self.audit(u,"Changed account access",f"User {ident}: active={active}",c); self.send_json({"ok":True}); return
                if path.startswith("/api/findings/") and path.endswith("/review") and role=="Security Administrator":
                    ident=int(path.split("/")[3]); score=max(0,min(25,int(d.get("score",0)))); feedback=str(d.get("feedback",""))[:2000]
                    c.execute("UPDATE findings SET status='Reviewed',score=?,feedback=? WHERE id=?",(score,feedback,ident)); self.audit(u,"Reviewed finding",f"Finding {ident}: {score}/25",c); self.send_json({"ok":True}); return
                if path.startswith("/api/controls/") and path.endswith("/status") and role=="Security Administrator":
                    ident=path.split("/")[3]; status=str(d.get("status",""))
                    if status not in ("Implemented","In progress","Needs review"): self.send_json({"error":"Invalid control status"},400); return
                    c.execute("UPDATE controls SET status=? WHERE id=?",(status,ident)); self.audit(u,"Updated control",f"{ident}: {status}",c); self.send_json({"ok":True}); return
        except (ValueError, TypeError): self.send_json({"error":"Invalid request data"},400); return
        self.send_json({"error":"Forbidden or not found"},403)


if __name__=="__main__":
    initialize()
    print(f"PayNexus learning simulation listening on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever()
