#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, time, hashlib, secrets, urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from http import cookies

# =======================
# CONFIG
# =======================
ROOT = "/storage/emulated/0/Site"
ASSETS_DIR = os.path.join(ROOT, "assets")
DATA_DIR = os.path.join(ASSETS_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
USERS_PLAIN_FILE = os.path.join(DATA_DIR, "users_plain.txt")   # email;password;username;created_at
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
ORDERS_FILE = os.path.join(DATA_DIR, "orders.json")            # pedidos da loja
PORT = 8080

# Pastas/arquivos
os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump({"users":[]}, f, ensure_ascii=False)
if not os.path.exists(SESSIONS_FILE):
    with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f, ensure_ascii=False)
if not os.path.exists(USERS_PLAIN_FILE):
    with open(USERS_PLAIN_FILE, "w", encoding="utf-8") as f:
        f.write("")
if not os.path.exists(ORDERS_FILE):
    with open(ORDERS_FILE, "w", encoding="utf-8") as f:
        json.dump({"orders":[]}, f, ensure_ascii=False)

# =======================
# Helpers
# =======================
def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)

def now_ts(): return int(time.time())
def make_salt(): return secrets.token_hex(16)

def hash_password(password, salt):
    h = hashlib.sha256()
    h.update((password + salt).encode("utf-8"))
    return h.hexdigest()

# =======================
# Users (JSON base)
# =======================
def get_user_by_email(email):
    db = load_json(USERS_FILE, {"users":[]})
    for u in db["users"]:
        if u["email"].lower() == email.lower():
            return u
    return None

def add_user(email, password, username, role="Usuario"):
    if get_user_by_email(email):
        return False, "E-mail já registrado"
    db = load_json(USERS_FILE, {"users":[]})
    salt = make_salt()
    db["users"].append({
        "email": email,
        "username": username,
        "password_hash": hash_password(password, salt),
        "salt": salt,
        "role": role,
        "created_at": now_ts(),
        "last_login": 0,
        "banned": False
    })
    save_json(USERS_FILE, db)
    # espelho solicitando em TXT puro
    plain_upsert(email=email, password=password, username=username, created_at=int(time.time()))
    return True, None

def update_user(u):
    db = load_json(USERS_FILE, {"users":[]})
    for i, it in enumerate(db["users"]):
        if it["email"].lower() == u["email"].lower():
            db["users"][i] = u
            save_json(USERS_FILE, db)
            return True
    return False

def delete_user(email):
    db = load_json(USERS_FILE, {"users":[]})
    db["users"] = [x for x in db["users"] if x["email"].lower()!=email.lower()]
    save_json(USERS_FILE, db)
    # remover do TXT
    plain_delete(email)

# =======================
# Users TXT (puro)
# =======================
def parse_plain_line(line):
    parts = line.rstrip("\n").split(";")
    if len(parts) < 4: return None
    return {"email":parts[0],"password":parts[1],"username":parts[2],"created_at":parts[3]}

def plain_read_all():
    items=[]
    try:
        with open(USERS_PLAIN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                d = parse_plain_line(line)
                if d: items.append(d)
    except: pass
    return items

def plain_write_all(items):
    with open(USERS_PLAIN_FILE, "w", encoding="utf-8") as f:
        for it in items:
            f.write(f"{it['email']};{it['password']};{it['username']};{it.get('created_at','')}\n")

def plain_upsert(email, password, username, created_at=None):
    items = plain_read_all()
    found=False
    for it in items:
        if it["email"].lower()==email.lower():
            it["password"]=password
            it["username"]=username
            if created_at is not None:
                it["created_at"]=str(created_at)
            found=True
            break
    if not found:
        items.append({"email":email,"password":password,"username":username,"created_at":str(created_at or int(time.time()))})
    plain_write_all(items)

def plain_delete(email):
    items = plain_read_all()
    items = [it for it in items if it["email"].lower()!=email.lower()]
    plain_write_all(items)

# =======================
# Sessions
# =======================
def read_sessions(): return load_json(SESSIONS_FILE, {})
def write_sessions(s): save_json(SESSIONS_FILE, s)

def set_session(session_id, email):
    s = read_sessions()
    s[session_id] = {"email": email, "ts": now_ts(), "csrf": secrets.token_hex(16)}
    write_sessions(s)

def clear_session(session_id):
    s = read_sessions()
    if session_id in s:
        del s[session_id]
        write_sessions(s)

def get_session_user(handler):
    sid = None
    if "Cookie" in handler.headers:
        c = cookies.SimpleCookie(handler.headers.get("Cookie"))
        sid = c["sid"].value if "sid" in c else None
    if not sid: return None, None, None
    s = read_sessions()
    sess = s.get(sid)
    if not sess: return None, sid, None
    u = get_user_by_email(sess["email"])
    csrf = sess.get("csrf")
    return u, sid, csrf

def touch_csrf(sid):
    s = read_sessions()
    if sid not in s: return None
    s[sid]["csrf"] = secrets.token_hex(16)
    write_sessions(s)
    return s[sid]["csrf"]

def require_csrf(handler, sid):
    s = read_sessions()
    sess = s.get(sid) if sid else None
    if not sess: return False
    expected = sess.get("csrf")
    got = handler.headers.get("X-CSRF-Token","")
    return bool(expected) and expected == got

def user_is_admin(u): return (u and u.get("role") == "Administrador")

# =======================
# Orders (loja)
# =======================
def append_order(email, coins, price):
    db = load_json(ORDERS_FILE, {"orders":[]})
    db["orders"].append({
        "id": secrets.token_hex(8),
        "email": email,
        "coins": int(coins),
        "price": float(price),
        "created_at": now_ts(),
        "status": "novo"
    })
    save_json(ORDERS_FILE, db)

# =======================
# HTTP Handler
# =======================
class MyHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = path.split('?',1)[0].split('#',1)[0]
        if path == "/": path = "/index.html"
        return os.path.join(ROOT, path.lstrip("/"))

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type,X-CSRF-Token")

    def json_response(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code); self._cors()
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def read_json(self):
        try:
            ln = int(self.headers.get("Content-Length","0"))
            raw = self.rfile.read(ln) if ln>0 else b""
            return json.loads(raw.decode("utf-8") or "{}")
        except:
            return {}

    # --------- GET ----------
    def do_GET(self):
        if self.path.startswith("/api/me"):            return self.handle_me()
        if self.path.startswith("/api/csrf"):          return self.handle_csrf()
        if self.path.startswith("/api/admin/users"):   return self.handle_admin_users()
        return super().do_GET()

    # --------- POST ---------
    def do_POST(self):
        if self.path.startswith("/api/register"):                return self.handle_register()
        if self.path.startswith("/api/login"):                   return self.handle_login()
        if self.path.startswith("/api/logout"):                  return self.handle_logout()
        if self.path.startswith("/api/account/change_password"): return self.handle_change_password()
        if self.path.startswith("/api/account/delete"):          return self.handle_account_delete()
        if self.path.startswith("/api/admin/action"):            return self.handle_admin_action()
        if self.path.startswith("/api/store/coins"):             return self.handle_store_coins()
        return self.send_error(404, "Not Found")

    # --------- endpoints ---------
    def handle_me(self):
        u, _sid, _csrf = get_session_user(self)
        if not u: return self.json_response(200, {"auth":False})
        return self.json_response(200, {
            "auth":True,"email":u["email"],"username":u.get("username",""),
            "role":u["role"],"banned":u.get("banned",False)
        })

    def handle_csrf(self):
        u, sid, _ = get_session_user(self)
        if not sid: return self.json_response(401, {"ok":False,"error":"auth required"})
        token = touch_csrf(sid)
        return self.json_response(200, {"ok":True,"csrf":token})

    def handle_register(self):
        data = self.read_json()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        username = (data.get("username") or "").strip()
        if not email or "@" not in email or len(password)<4 or not username:
            return self.json_response(400, {"ok":False,"error":"Dados inválidos"})
        ok, err = add_user(email, password, username, role="Usuario")
        if not ok: return self.json_response(400, {"ok":False,"error":err or "Falha ao registrar"})

        # login automático
        sid = f"{email}:{now_ts()}:{secrets.token_hex(8)}"
        set_session(sid, email)
        c = cookies.SimpleCookie(); c["sid"] = sid; c["sid"]["path"] = "/"
        body = json.dumps({"ok":True}).encode("utf-8")
        self.send_response(200); self._cors()
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Set-Cookie", c.output(header=''))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def handle_login(self):
        data = self.read_json()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        u = get_user_by_email(email)
        if not u or u.get("banned"):
            return self.json_response(200, {"ok":False,"error":"E-mail/senha incorretos ou conta banida"})
        if hash_password(password, u["salt"]) != u["password_hash"]:
            return self.json_response(200, {"ok":False,"error":"E-mail ou senha incorretos"})
        u["last_login"]=now_ts(); update_user(u)

        sid = f"{email}:{now_ts()}:{secrets.token_hex(8)}"
        set_session(sid, email)
        c = cookies.SimpleCookie(); c["sid"]=sid; c["sid"]["path"]="/"
        body = json.dumps({"ok":True}).encode("utf-8")
        self.send_response(200); self._cors()
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Set-Cookie", c.output(header=''))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def handle_logout(self):
        sid = None
        if "Cookie" in self.headers:
            c = cookies.SimpleCookie(self.headers.get("Cookie"))
            sid = c["sid"].value if "sid" in c else None
        if sid: clear_session(sid)
        c = cookies.SimpleCookie(); c["sid"]=""; c["sid"]["path"]="/"; c["sid"]["max-age"]=0
        self.send_response(200); self._cors()
        self.send_header("Set-Cookie", c.output(header=''))
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.end_headers(); self.wfile.write(b'{"ok":true}')

    def handle_change_password(self):
        u, sid, _csrf = get_session_user(self)
        if not u: return self.json_response(401, {"ok":False,"error":"auth required"})
        if not require_csrf(self, sid): return self.json_response(403, {"ok":False,"error":"csrf"})
        data = self.read_json()
        oldp = data.get("old_password") or ""
        newp = data.get("new_password") or ""
        if len(newp) < 4: return self.json_response(400, {"ok":False,"error":"Senha muito curta"})
        if hash_password(oldp, u["salt"]) != u["password_hash"]:
            return self.json_response(400, {"ok":False,"error":"Senha atual incorreta"})
        u["salt"] = make_salt()
        u["password_hash"] = hash_password(newp, u["salt"])
        update_user(u)
        # atualiza também TXT puro
        plain_upsert(email=u["email"], password=newp, username=u.get("username",""), created_at=None)
        return self.json_response(200, {"ok":True})

    def handle_account_delete(self):
        u, sid, _csrf = get_session_user(self)
        if not u: return self.json_response(401, {"ok":False,"error":"auth required"})
        # apenas admin pode excluir contas
        if not user_is_admin(u):
            return self.json_response(403, {"ok":False,"error":"Apenas administrador pode excluir contas"})
        if not require_csrf(self, sid): return self.json_response(403, {"ok":False,"error":"csrf"})
        data = self.read_json()
        email = (data.get("email") or u["email"]).lower().strip()
        delete_user(email)
        if sid and email.lower()==u["email"].lower():
            clear_session(sid)
        return self.json_response(200, {"ok":True})

    def handle_admin_users(self):
        u, _sid, _csrf = get_session_user(self)
        if not user_is_admin(u): return self.json_response(403, {"error":"forbidden"})
        # filtros: ?search=&page=&page_size=
        q = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(q)
        search = (params.get("search",[""])[0] or "").lower().strip()
        try: page = int(params.get("page",["1"])[0])
        except: page = 1
        try: page_size = int(params.get("page_size",["20"])[0])
        except: page_size = 20
        page = max(1,page); page_size = min(100, max(1,page_size))

        db = load_json(USERS_FILE, {"users":[]})
        rows = db["users"]
        if search:
            rows = [
                x for x in rows
                if (search in x["email"].lower()
                    or search in (x.get("role","").lower())
                    or search in (x.get("username","").lower()))
            ]
        total = len(rows)
        start = (page-1)*page_size
        end = start + page_size
        paged = rows[start:end]
        safe = [{
            "email":x["email"],
            "username":x.get("username",""),
            "role":x["role"],
            "created_at":x["created_at"],
            "last_login":x.get("last_login",0),
            "banned":x.get("banned",False)
        } for x in paged]
        return self.json_response(200, {"total":total,"page":page,"page_size":page_size,"users":safe})

    def handle_admin_action(self):
        u, sid, _csrf = get_session_user(self)
        if not user_is_admin(u): return self.json_response(403, {"ok":False,"error":"forbidden"})
        if not require_csrf(self, sid): return self.json_response(403, {"ok":False,"error":"csrf"})

        data = self.read_json()
        action = data.get("action")
        email = (data.get("email") or "").lower().strip()
        target = get_user_by_email(email)
        if not target: return self.json_response(400, {"ok":False,"error":"Usuário não encontrado"})
        if target["email"].lower() == u["email"].lower() and action in ("delete","ban"):
            return self.json_response(400, {"ok":False,"error":"Não pode aplicar essa ação em si mesmo"})

        if action=="promote":
            target["role"]="Administrador"; update_user(target)
        elif action=="demote":
            target["role"]="Usuario"; update_user(target)
        elif action=="ban":
            target["banned"]=True; update_user(target)
        elif action=="unban":
            target["banned"]=False; update_user(target)
        elif action=="delete":
            delete_user(target["email"])
        else:
            return self.json_response(400, {"ok":False,"error":"Ação inválida"})
        return self.json_response(200, {"ok":True})

    def handle_store_coins(self):
        """Registra pedido de compra de moedas localmente (sem Discord)."""
        u, _sid, _csrf = get_session_user(self)
        # permitir pedido mesmo deslogado? Melhor exigir login:
        if not u:
            return self.json_response(401, {"ok":False,"error":"Faça login para continuar"})
        data = self.read_json()
        try:
            coins = int(data.get("coins", 0))
        except:
            coins = 0
        if coins < 1000 or coins > 10_000_000:
            return self.json_response(400, {"ok":False,"error":"Quantidade inválida (1.000 a 10.000.000)"})
        price = coins / 1000.0  # R$1 para cada 1.000 moedas
        append_order(u["email"], coins, price)
        return self.json_response(200, {"ok":True, "coins":coins, "price":price})

# =======================
# RUN
# =======================
if __name__ == "__main__":
    os.chdir(ROOT)
    httpd = HTTPServer(("0.0.0.0", PORT), MyHandler)
    print(f"Servidor ON em http://0.0.0.0:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Encerrando...")
        httpd.server_close()