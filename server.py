#!/usr/bin/env python3
"""
JAZEYI — client messaging backend (zero dependencies, Python stdlib only).

Runs the portfolio site AND a real messaging system:
  /            -> index.html (public site, conversation starter)
  /chat        -> visitor chat (link contains an unguessable token)
  /admin       -> owner dashboard (password protected)

Storage: SQLite file (chat.db) — conversations & messages persist permanently.

Config via environment variables (all optional, sane defaults):
  JZ_PORT            port to listen on            (default 8000, or --port)
  JZ_ADMIN_PASSWORD  owner dashboard password     (if unset, one is generated
                                                    and printed to the console
                                                    on first run — set this
                                                    before going public!)
  JZ_PUBLIC_URL      e.g. https://jazeyi.example.com (used in recovery emails)
  JZ_SMTP_HOST / JZ_SMTP_PORT / JZ_SMTP_USER / JZ_SMTP_PASS / JZ_SMTP_FROM
                    optional SMTP so "recover my link" emails actually send
"""
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import string
import sys
import threading
import time
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("JZ_DB") or os.path.join(BASE_DIR, "chat.db")
# Render/Fly/Heroku-style hosts inject their own $PORT — use it when present.
PORT = int(os.environ.get("JZ_PORT") or os.environ.get("PORT") or "8000")
if "--port" in sys.argv:
    PORT = int(sys.argv[sys.argv.index("--port") + 1])

# ---------------------------------------------------------------- database
_db_lock = threading.Lock()


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS conversations(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          email TEXT NOT NULL,
          title TEXT NOT NULL,
          description TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','in_progress','completed')),
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          visitor_read_id INTEGER NOT NULL DEFAULT 0,
          owner_read_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
          sender TEXT NOT NULL CHECK(sender IN ('visitor','owner')),
          body TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, id);
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY,
          expires REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS owner(
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL
        );
        """)


# ---------------------------------------------------------------- helpers
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[a-zA-Z]{2,}$")
CLEAN_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PBKDF2_ITERS = 200_000


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def clean(s, limit):
    s = CLEAN_RE.sub("", (s or "")).strip()
    return s[:limit]


def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), PBKDF2_ITERS)
    return "%s$%s" % (salt, dk.hex())


def check_password(pw, stored):
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(pw, salt), stored)


def new_token():
    return secrets.token_urlsafe(24)  # 192-bit, unguessable


def password_ready():
    with db() as con:
        row = con.execute("SELECT v FROM owner WHERE k='pw'").fetchone()
    if row:
        return
    pw = os.environ.get("JZ_ADMIN_PASSWORD", "").strip()
    generated = not pw
    if generated:
        pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(14))
    with db() as con:
        con.execute("INSERT OR REPLACE INTO owner(k,v) VALUES('pw',?)", (hash_password(pw),))
    print("\n" + "=" * 60)
    print("  JAZEYI messaging backend")
    if generated:
        print("  ADMIN PASSWORD (set JZ_ADMIN_PASSWORD to override):  %s" % pw)
    else:
        print("  Admin password loaded from JZ_ADMIN_PASSWORD env var.")
    print("  Dashboard:  /admin")
    print("=" * 60 + "\n")


def verify_password(pw):
    with db() as con:
        row = con.execute("SELECT v FROM owner WHERE k='pw'").fetchone()
    return bool(row) and check_password(pw, row["v"])


# ------------------------------------------------------------ rate limiting
class RateLimiter:
    def __init__(self):
        self.hits = {}
        self.lock = threading.Lock()

    def allow(self, key, limit, window):
        now = time.time()
        with self.lock:
            lst = [t for t in self.hits.get(key, []) if now - t < window]
            if len(lst) >= limit:
                self.hits[key] = lst
                return False
            lst.append(now)
            self.hits[key] = lst
            # light cleanup
            if len(self.hits) > 5000:
                self.hits = {k: [t for t in v if now - t < 3600] for k, v in self.hits.items()}
            return True


RL = RateLimiter()


# ------------------------------------------------------------------ server
class App(BaseHTTPRequestHandler):
    server_version = "JAZEYI/1.0"
    protocol_version = "HTTP/1.1"

    # ---- infra
    def log_message(self, fmt, *args):
        path = (getattr(self, "path", "") or "")
        if path.startswith("/api/") and " 200 " in (args[1] if len(args) > 1 else ""):
            return  # silence polling noise
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _raw(self, code, ctype, body, extra=None):
        tb = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(tb)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(tb)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def json_out(self, obj, code=200, extra=None):
        self._raw(code, "application/json; charset=utf-8", json.dumps(obj), extra)

    def err(self, code, msg):
        self.json_out({"ok": False, "error": msg}, code)

    def serve_file(self, fname):
        fpath = os.path.join(BASE_DIR, fname)
        try:
            with open(fpath, "rb") as f:
                data = f.read()
            self._raw(200, "text/html; charset=utf-8", data)
        except OSError:
            self.err(404, "Page not found.")

    def client_ip(self):
        ip = self.headers.get("CF-Connecting-IP") or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return ip or self.client_address[0]

    def body_json(self, limit=32_000):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0 or n > limit:
            return None
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def session_ok(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = c.get("jz_admin")
        if not morsel:
            return False
        th = sha(morsel.value)
        now = time.time()
        with db() as con:
            row = con.execute("SELECT expires FROM sessions WHERE token_hash=?", (th,)).fetchone()
            if not row or row["expires"] < now:
                return False
            con.execute("DELETE FROM sessions WHERE expires<?", (now,))
        return True

    def set_session_cookie(self, token, max_age):
        secure = self.headers.get("X-Forwarded-Proto") == "https"
        c = cookies.SimpleCookie()
        c["jz_admin"] = token
        c["jz_admin"]["path"] = "/"
        c["jz_admin"]["max-age"] = str(max_age)
        c["jz_admin"]["httponly"] = True
        c["jz_admin"]["samesite"] = "Lax"
        if secure:
            c["jz_admin"]["secure"] = True
        return ("Set-Cookie", c.output(header="").strip())

    def convo_by_token(self, token):
        if not token or len(token) > 200:
            return None
        with db() as con:
            return con.execute("SELECT * FROM conversations WHERE token=?", (token,)).fetchone()

    def public_origin(self):
        pub = os.environ.get("JZ_PUBLIC_URL", "").rstrip("/")
        if pub:
            return pub
        proto = self.headers.get("X-Forwarded-Proto") or "http"
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "localhost"
        return "%s://%s" % (proto, host)

    # ---- routing
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlparse(self.path)
        p = url.path.rstrip("/") or "/"
        ip = self.client_ip()
        if p.startswith("/api/") and not RL.allow("g:" + ip, 300, 60):
            return self.err(429, "Too many requests — slow down a bit.")
        if p in ("/", "/index.html"):
            return self.serve_file("index.html")
        if p in ("/chat", "/chat.html"):
            return self.serve_file("chat.html")
        if p in ("/admin", "/admin.html"):
            return self.serve_file("admin.html")
        if p == "/api/health":
            return self.json_out({"ok": True})
        if p == "/api/thread":
            return self.api_thread(parse_qs(url.query).get("t", [None])[0] or self.headers.get("X-Token"))
        if p == "/api/admin/conversations":
            return self.admin_required(self.admin_conversations)
        if p == "/api/admin/thread":
            return self.admin_required(lambda: self.admin_thread(parse_qs(url.query).get("id", [None])[0]))
        self.err(404, "Not found.")

    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        ip = self.client_ip()
        if p.startswith("/api/") and not RL.allow("g:" + ip, 300, 60):
            return self.err(429, "Too many requests — slow down a bit.")
        if p == "/api/start":
            return self.api_start()
        if p == "/api/send":
            return self.api_send(False)
        if p == "/api/recover":
            return self.api_recover()
        if p == "/api/admin/login":
            return self.admin_login()
        if p == "/api/admin/logout":
            return self.admin_logout()
        if p == "/api/admin/send":
            return self.admin_required(lambda: self.api_send(True))
        if p == "/api/admin/status":
            return self.admin_required(self.admin_status)
        self.err(404, "Not found.")

    def admin_required(self, fn):
        if not self.session_ok():
            return self.err(401, "Sign in required.")
        return fn()

    # ---- visitors
    def api_start(self):
        ip = self.client_ip()
        if not RL.allow("start:" + ip, 8, 3600):
            return self.err(429, "Too many new conversations from this network. Try again later.")
        d = self.body_json()
        if not isinstance(d, dict):
            return self.err(400, "Invalid request.")

        # spam traps: hidden field + suspiciously-fast submit
        if (d.get("website") or "").strip():
            return self.json_out({"ok": True, "path": "/"})  # silently drop bots
        try:
            elapsed = time.time() * 1000 - float(d.get("t", 0))
        except (TypeError, ValueError):
            elapsed = 10_000
        if elapsed < 1500:
            return self.err(400, "That was a little too fast — please try again.")

        name = clean(d.get("name"), 60)
        email = clean(d.get("email"), 254).lower()
        title = clean(d.get("title"), 120)
        desc = clean(d.get("description"), 2000)
        if len(name) < 2:
            return self.err(422, "Please enter your name.")
        if not EMAIL_RE.match(email):
            return self.err(422, "Please enter a valid email address.")
        if len(title) < 2:
            return self.err(422, "Please give the project a title.")
        if len(desc) < 10:
            return self.err(422, "Tell me a little more about the project (10+ characters).")

        iso = now_iso()
        token = new_token()
        with db() as con:
            cur = con.execute(
                "INSERT INTO conversations(token,name,email,title,description,status,created_at,updated_at,visitor_read_id,owner_read_id)"
                " VALUES(?,?,?,?,?,'new',?,?,0,0)",
                (token, name, email, title, desc, iso, iso),
            )
            cid = cur.lastrowid
            mcur = con.execute(
                "INSERT INTO messages(conversation_id,sender,body,created_at) VALUES(?,?,?,?)",
                (cid, "visitor", "Project inquiry: %s\n\n%s" % (title, desc), iso),
            )
            con.execute("UPDATE conversations SET visitor_read_id=? WHERE id=?", (mcur.lastrowid, cid))
        return self.json_out({"ok": True, "path": "/chat#" + token})

    def api_thread(self, token):
        convo = self.convo_by_token(token)
        if not convo:
            return self.err(404, "Conversation not found. Check your link, or recover it with your email.")
        iso = now_iso()
        since = parse_qs(urlparse(self.path).query).get("since", ["0"])[0]
        try:
            since = int(since)
        except ValueError:
            since = 0
        with db() as con:
            maxid = con.execute(
                "SELECT MAX(id) AS m FROM messages WHERE conversation_id=?", (convo["id"],)
            ).fetchone()["m"] or 0
            con.execute("UPDATE conversations SET visitor_read_id=? WHERE id=?", (maxid, convo["id"]))
            msgs = con.execute(
                "SELECT id,sender,body,created_at FROM messages WHERE conversation_id=? AND id>? ORDER BY id",
                (convo["id"], since),
            ).fetchall()
        return self.json_out({
            "ok": True,
            "conversation": {
                "id": convo["id"], "name": convo["name"], "email": convo["email"],
                "title": convo["title"], "description": convo["description"],
                "status": convo["status"], "created_at": convo["created_at"],
            },
            "messages": [dict(m) for m in msgs],
            "owner_read_id": convo["owner_read_id"],
            "server_time": iso,
        })

    def api_send(self, as_owner):
        d = self.body_json(16_000)
        if not isinstance(d, dict):
            return self.err(400, "Invalid request.")
        body = clean(d.get("body"), 2000)
        if not body:
            return self.err(422, "Message can't be empty.")
        if as_owner:
            try:
                cid = int(d.get("conversation_id"))
            except (TypeError, ValueError):
                return self.err(400, "Missing conversation.")
            with db() as con:
                convo = con.execute("SELECT * FROM conversations WHERE id=?", (cid,)).fetchone()
            if not convo:
                return self.err(404, "Conversation not found.")
            token = convo["token"]
        else:
            token = d.get("token")
            convo = self.convo_by_token(token)
            if not convo:
                return self.err(404, "Conversation not found.")
            cid = convo["id"]
            if not RL.allow("send:" + token[-16:], 40, 60):
                return self.err(429, "You're sending messages too fast — take a breath.")
        iso = now_iso()
        with db() as con:
            cur = con.execute(
                "INSERT INTO messages(conversation_id,sender,body,created_at) VALUES(?,?,?,?)",
                (cid, "owner" if as_owner else "visitor", body, iso),
            )
            mid = cur.lastrowid
            con.execute("UPDATE conversations SET updated_at=? WHERE id=?", (iso, cid))
            if as_owner:
                con.execute("UPDATE conversations SET owner_read_id=? WHERE id=?", (mid, cid))
            else:
                con.execute("UPDATE conversations SET visitor_read_id=? WHERE id=?", (mid, cid))
        return self.json_out({"ok": True, "id": mid, "created_at": iso})

    def api_recover(self):
        ip = self.client_ip()
        if not RL.allow("recv:" + ip, 5, 3600):
            return self.err(429, "Too many recovery attempts. Try again later.")
        d = self.body_json()
        email = clean((d or {}).get("email"), 254).lower()
        # Always respond generically — never reveal whether the email exists.
        out = {"ok": True, "message": "If that email has conversations, the links are on their way."}
        if not EMAIL_RE.match(email):
            return self.json_out(out)
        with db() as con:
            rows = con.execute("SELECT token FROM conversations WHERE email=?", (email,)).fetchall()
        if not rows:
            return self.json_out(out)
        host = os.environ.get("JZ_SMTP_HOST", "").strip()
        if not host:
            print("[recover] SMTP not configured — recovery requested for %s (%d conversation(s))" % (email, len(rows)))
            return self.json_out(out)
        try:
            import smtplib
            from email.mime.text import MIMEText
            links = "\n\n".join("- %s/chat#%s" % (self.public_origin(), r["token"]) for r in rows)
            msg = MIMEText("Hey,\n\nHere are your conversation link(s) with JAZEYI — keep them secret, anyone with a link can open the chat:\n\n%s\n\n— JAZEYI\n" % links)
            frm = os.environ.get("JZ_SMTP_FROM") or os.environ.get("JZ_SMTP_USER") or "noreply"
            msg["Subject"] = "Your JAZEYI conversation link(s)"
            msg["From"] = frm
            msg["To"] = email
            port = int(os.environ.get("JZ_SMTP_PORT", "587"))
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.starttls()
                user = os.environ.get("JZ_SMTP_USER")
                if user:
                    s.login(user, os.environ.get("JZ_SMTP_PASS", ""))
                s.send_message(msg)
        except Exception as e:
            print("[recover] SMTP send failed: %s" % e)
        return self.json_out(out)

    # ---- owner
    def admin_login(self):
        ip = self.client_ip()
        if not RL.allow("login:" + ip, 5, 600):
            return self.err(429, "Too many login attempts. Wait 10 minutes.")
        d = self.body_json()
        pw = (d or {}).get("password") or ""
        if not verify_password(pw):
            return self.err(401, "Wrong password.")
        token = secrets.token_urlsafe(32)
        with db() as con:
            con.execute("INSERT INTO sessions(token_hash,expires) VALUES(?,?)", (sha(token), time.time() + 7 * 86400))
        self.json_out({"ok": True}, 200, [self.set_session_cookie(token, 7 * 86400)])

    def admin_logout(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = c.get("jz_admin")
        if morsel:
            with db() as con:
                con.execute("DELETE FROM sessions WHERE token_hash=?", (sha(morsel.value),))
        clr = cookies.SimpleCookie()
        clr["jz_admin"] = ""
        clr["jz_admin"]["path"] = "/"
        clr["jz_admin"]["max-age"] = "0"
        self.json_out({"ok": True}, 200, [("Set-Cookie", clr.output(header="").strip())])

    def admin_conversations(self):
        with db() as con:
            rows = con.execute("""
              SELECT c.*, (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id
                            AND m.sender='visitor' AND m.id > c.owner_read_id) AS unread,
                     (SELECT body FROM messages m2 WHERE m2.conversation_id=c.id ORDER BY m2.id DESC LIMIT 1) AS last_body,
                     (SELECT sender FROM messages m3 WHERE m3.conversation_id=c.id ORDER BY m3.id DESC LIMIT 1) AS last_sender
              FROM conversations c ORDER BY c.updated_at DESC
            """).fetchall()
        return self.json_out({
            "ok": True,
            "conversations": [{
                "id": r["id"], "name": r["name"], "email": r["email"], "title": r["title"],
                "status": r["status"], "created_at": r["created_at"], "updated_at": r["updated_at"],
                "unread": r["unread"],
                "snippet": (r["last_body"] or "")[:90], "last_sender": r["last_sender"] or "",
            } for r in rows],
        })

    def admin_thread(self, cid):
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            return self.err(400, "Missing conversation id.")
        with db() as con:
            convo = con.execute("SELECT * FROM conversations WHERE id=?", (cid,)).fetchone()
            if not convo:
                return self.err(404, "Conversation not found.")
            maxid = con.execute(
                "SELECT MAX(id) AS m FROM messages WHERE conversation_id=?", (cid,)
            ).fetchone()["m"] or 0
            con.execute("UPDATE conversations SET owner_read_id=? WHERE id=?", (maxid, cid))
            msgs = con.execute(
                "SELECT id,sender,body,created_at FROM messages WHERE conversation_id=? ORDER BY id",
                (cid,),
            ).fetchall()
        return self.json_out({
            "ok": True,
            "conversation": {
                "id": convo["id"], "name": convo["name"], "email": convo["email"],
                "title": convo["title"], "description": convo["description"],
                "status": convo["status"], "created_at": convo["created_at"],
                "visitor_link": "%s/chat#%s" % (self.public_origin(), convo["token"]),
            },
            "messages": [dict(m) for m in msgs],
            "visitor_read_id": convo["visitor_read_id"],
        })

    def admin_status(self):
        d = self.body_json()
        try:
            cid = int((d or {}).get("conversation_id"))
        except (TypeError, ValueError):
            return self.err(400, "Missing conversation id.")
        status = (d or {}).get("status")
        if status not in ("new", "in_progress", "completed"):
            return self.err(422, "Invalid status.")
        with db() as con:
            cur = con.execute(
                "UPDATE conversations SET status=?, updated_at=? WHERE id=?",
                (status, now_iso(), cid),
            )
            if cur.rowcount == 0:
                return self.err(404, "Conversation not found.")
        return self.json_out({"ok": True})


def main():
    init_db()
    password_ready()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), App)
    srv.daemon_threads = True
    print("Serving on http://0.0.0.0:%d" % PORT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
