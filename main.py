from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import jwt, datetime, hashlib, sqlite3, time, os
from collections import defaultdict

app = FastAPI()
templates = Jinja2Templates(directory="templates")
SECRET  = os.getenv("SECRET_KEY", "pulse_session_key_2025")
DB_PATH = os.getenv("DB_PATH", "pulse.db")

# защита включается/выключается для демонстрации ценности детектора
PROTECTION_ENABLED = False

request_counts = defaultdict(list)

# ── реальный IP за Render proxy ──────────────────────
def get_real_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real = request.headers.get("x-real-ip")
    if real:
        return real
    return request.client.host if request.client else "0.0.0.0"

# ── база данных ──────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password TEXT,
        display_name TEXT, email TEXT, phone TEXT,
        bio TEXT, avatar TEXT,
        joined TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT, content TEXT, spam INTEGER DEFAULT 0,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT, sender TEXT, content TEXT,
        incoming INTEGER DEFAULT 1,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, ip TEXT, user_agent TEXT,
        action TEXT, flags TEXT, event TEXT,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS stolen (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT, cookies TEXT, url TEXT,
        useragent TEXT, screen TEXT, language TEXT,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    return conn

def seed_user(conn, username, display_name):
    # стартовые посты — аккаунт выглядит живым
    conn.execute("INSERT INTO posts (author, content) VALUES (?,?)",
                 (username, "Наконец-то выходные. Кто куда?"))
    conn.execute("INSERT INTO posts (author, content) VALUES (?,?)",
                 (username, "Досмотрел сериал за ночь. Не жалею ни секунды."))
    # приватные сообщения — то, что утечёт при взломе
    dms = [
        ("Алия", "Скинь пожалуйста код от подъезда, забыла"),
        ("Банк", "Ваш одноразовый код: 4471. Никому не сообщайте."),
        ("Данияр", "Бро, я тебе вчера 25000 перевёл, проверь"),
    ]
    for sender, text in dms:
        conn.execute("INSERT INTO messages (owner, sender, content, incoming) VALUES (?,?,?,1)",
                     (username, sender, text))
    conn.commit()

# ── rate limiting ────────────────────────────────────
@app.middleware("http")
async def rate_limit(request: Request, call_next):
    ip = get_real_ip(request)
    now = time.time()
    request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
    if len(request_counts[ip]) > 120:
        return HTMLResponse("Too many requests", status_code=429)
    request_counts[ip].append(now)
    return await call_next(request)

# ── детектор аномалий ────────────────────────────────
def analyze(payload, ip, ua):
    flags, risk = [], 0
    oip = payload.get("ip", "")
    oua = payload.get("ua", "")
    if oip and oip != ip:
        flags.append("IP_CHANGE"); risk += 40
    if oua and oua != ua:
        flags.append("DEVICE_CHANGE"); risk += 30
    return {
        "risk": min(risk, 100),
        "flags": flags,
        "action": "BLOCK" if risk >= 60 else "ALERT" if risk >= 30 else "OK",
    }

def log_event(conn, username, ip, ua, res, event):
    conn.execute(
        "INSERT INTO logs (username, ip, user_agent, action, flags, event) VALUES (?,?,?,?,?,?)",
        (username, ip, ua, res["action"], ", ".join(res["flags"]), event))
    conn.commit()

# ── авторизация: достаём токен из cookie или заголовка ─
def get_session(request: Request):
    token = request.cookies.get("token") or request.headers.get("x-session-token")
    if not token:
        return None, None
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        return payload, token
    except Exception:
        return None, None

# ════════════════════════════════════════════════════
#  ПУБЛИЧНЫЕ СТРАНИЦЫ
# ════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"error": None})

@app.post("/register")
async def register(request: Request,
                   display_name: str = Form(),
                   username: str = Form(),
                   email: str = Form(),
                   phone: str = Form(),
                   password: str = Form()):
    if len(username) < 3:
        return templates.TemplateResponse(request, "register.html", {"error": "Имя пользователя минимум 3 символа"})
    if len(password) < 6:
        return templates.TemplateResponse(request, "register.html", {"error": "Пароль минимум 6 символов"})
    conn = get_conn()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return templates.TemplateResponse(request, "register.html", {"error": "Это имя уже занято"})
    hashed = hashlib.sha256(password.encode()).hexdigest()
    avatar = (display_name or username)[0].upper()
    conn.execute("""INSERT INTO users (username,password,display_name,email,phone,bio,avatar)
                    VALUES (?,?,?,?,?,?,?)""",
                 (username, hashed, display_name or username, email, phone,
                  "Привет, я тут новенький в PULSE", avatar))
    seed_user(conn, username, display_name or username)
    return RedirectResponse("/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})

@app.post("/login")
async def login(request: Request, username: str = Form(), password: str = Form()):
    conn = get_conn()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    user = conn.execute("SELECT * FROM users WHERE username=? AND password=?",
                        (username, hashed)).fetchone()
    if not user:
        return templates.TemplateResponse(request, "login.html", {"error": "Неверный логин или пароль"})
    ip = get_real_ip(request)
    ua = request.headers.get("user-agent", "")
    payload = {
        "user_id": username, "ip": ip, "ua": ua,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    res = analyze(payload, ip, ua)
    log_event(conn, username, ip, ua, res, "login")
    resp = RedirectResponse("/feed", status_code=302)
    # основной токен — защищён HttpOnly
    resp.set_cookie("token", token, httponly=True, samesite="lax", max_age=7200)
    # demo_token — БЕЗ HttpOnly, уязвим к XSS (для демонстрации кражи)
    resp.set_cookie("demo_token", token, httponly=False, samesite="lax", max_age=7200)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("token")
    resp.delete_cookie("demo_token")
    return resp

# ════════════════════════════════════════════════════
#  ПРИЛОЖЕНИЕ ЖЕРТВЫ (PULSE)
# ════════════════════════════════════════════════════
@app.get("/feed", response_class=HTMLResponse)
async def feed(request: Request):
    payload, token = get_session(request)
    if not payload:
        return RedirectResponse("/login")
    conn = get_conn()
    me = conn.execute("SELECT * FROM users WHERE username=?", (payload["user_id"],)).fetchone()
    if not me:
        return RedirectResponse("/login")
    ip = get_real_ip(request); ua = request.headers.get("user-agent", "")
    res = analyze(payload, ip, ua)
    log_event(conn, payload["user_id"], ip, ua, res, "view_feed")
    posts = conn.execute("SELECT * FROM posts WHERE author=? ORDER BY id DESC", (payload["user_id"],)).fetchall()
    unread = conn.execute("SELECT COUNT(*) c FROM messages WHERE owner=? AND incoming=1", (payload["user_id"],)).fetchone()["c"]
    return templates.TemplateResponse(request, "feed.html", {
        "me": me, "posts": posts, "token": token,
        "session_ip": ip, "res": res, "unread": unread,
    })

@app.post("/post")
async def create_post(request: Request, content: str = Form()):
    payload, token = get_session(request)
    if not payload:
        return RedirectResponse("/login")
    conn = get_conn()
    conn.execute("INSERT INTO posts (author, content) VALUES (?,?)", (payload["user_id"], content))
    conn.commit()
    return RedirectResponse("/feed", status_code=302)

@app.get("/messages", response_class=HTMLResponse)
async def messages_page(request: Request):
    payload, token = get_session(request)
    if not payload:
        return RedirectResponse("/login")
    conn = get_conn()
    me = conn.execute("SELECT * FROM users WHERE username=?", (payload["user_id"],)).fetchone()
    ip = get_real_ip(request); ua = request.headers.get("user-agent", "")
    res = analyze(payload, ip, ua)
    log_event(conn, payload["user_id"], ip, ua, res, "view_messages")
    msgs = conn.execute("SELECT * FROM messages WHERE owner=? ORDER BY id", (payload["user_id"],)).fetchall()
    return templates.TemplateResponse(request, "messages.html", {"me": me, "msgs": msgs})

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    payload, token = get_session(request)
    if not payload:
        return RedirectResponse("/login")
    conn = get_conn()
    me = conn.execute("SELECT * FROM users WHERE username=?", (payload["user_id"],)).fetchone()
    ip = get_real_ip(request); ua = request.headers.get("user-agent", "")
    res = analyze(payload, ip, ua)
    log_event(conn, payload["user_id"], ip, ua, res, "view_settings")
    return templates.TemplateResponse(request, "settings.html", {"me": me})

# ════════════════════════════════════════════════════
#  СИМУЛЯЦИЯ INFOSTEALER
# ════════════════════════════════════════════════════
@app.get("/stealer", response_class=HTMLResponse)
async def stealer_page(request: Request):
    return templates.TemplateResponse(request, "stealer.html")

@app.post("/collect")
async def collect(request: Request):
    try:
        data = await request.json()
    except Exception:
        return {"status": "error"}
    token = data.get("token")
    cookies_raw = data.get("cookies", "")
    if not token:
        for part in cookies_raw.split(";"):
            part = part.strip()
            if part.startswith("demo_token="):
                token = part[11:]; break
    conn = get_conn()
    conn.execute("""INSERT INTO stolen (token,cookies,url,useragent,screen,language)
                    VALUES (?,?,?,?,?,?)""",
                 (token, cookies_raw, data.get("url",""), data.get("useragent",""),
                  data.get("screen",""), data.get("language","")))
    conn.commit()
    return {"status": "ok"}

# ════════════════════════════════════════════════════
#  ПАНЕЛЬ АТАКУЮЩЕГО (C2) + ДЕЙСТВИЯ С УКРАДЕННЫМ ТОКЕНОМ
# ════════════════════════════════════════════════════
@app.get("/attacker", response_class=HTMLResponse)
async def attacker_panel(request: Request):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM stolen ORDER BY id DESC LIMIT 30").fetchall()
    victims = len(set(r["useragent"] for r in rows if r["useragent"]))
    active  = sum(1 for r in rows if r["token"])
    return templates.TemplateResponse(request, "attacker.html", {
        "stolen": rows, "victims": victims, "active": active,
        "protection": PROTECTION_ENABLED,
    })

def attacker_guard(request: Request, event: str):
    """Проверяет украденный токен, прогоняет через детектор, решает блокировать ли."""
    payload, token = get_session(request)
    if not payload:
        return None, JSONResponse({"ok": False, "error": "Токен недействителен или истёк"}, status_code=401)
    ip = get_real_ip(request); ua = request.headers.get("user-agent", "")
    res = analyze(payload, ip, ua)
    conn = get_conn()
    log_event(conn, payload["user_id"], ip, ua, res, event)
    if PROTECTION_ENABLED and res["action"] != "OK":
        return None, JSONResponse({
            "ok": False, "blocked": True, "detector": res,
            "message": "Действие заблокировано детектором аномалий",
        }, status_code=403)
    return payload, None

@app.post("/api/read-messages")
async def api_read_messages(request: Request):
    payload, blocked = attacker_guard(request, "read_messages")
    if blocked: return blocked
    conn = get_conn()
    msgs = conn.execute("SELECT sender, content FROM messages WHERE owner=? ORDER BY id",
                        (payload["user_id"],)).fetchall()
    return {"ok": True, "messages": [dict(m) for m in msgs]}

@app.post("/api/account")
async def api_account(request: Request):
    payload, blocked = attacker_guard(request, "read_account")
    if blocked: return blocked
    conn = get_conn()
    u = conn.execute("SELECT display_name,username,email,phone FROM users WHERE username=?",
                     (payload["user_id"],)).fetchone()
    return {"ok": True, "account": dict(u)}

@app.post("/api/change-email")
async def api_change_email(request: Request):
    payload, blocked = attacker_guard(request, "change_email")
    if blocked: return blocked
    conn = get_conn()
    new_email = "attacker_owns_you@evil.com"
    conn.execute("UPDATE users SET email=? WHERE username=?", (new_email, payload["user_id"]))
    conn.commit()
    return {"ok": True, "new_email": new_email,
            "message": "Email аккаунта изменён — жертва потеряла контроль"}

@app.post("/api/change-password")
async def api_change_password(request: Request):
    payload, blocked = attacker_guard(request, "change_password")
    if blocked: return blocked
    conn = get_conn()
    new_pw = hashlib.sha256(b"hacked_by_attacker").hexdigest()
    conn.execute("UPDATE users SET password=? WHERE username=?", (new_pw, payload["user_id"]))
    conn.commit()
    return {"ok": True, "message": "Пароль изменён — жертва заблокирована из аккаунта"}

@app.post("/api/post-spam")
async def api_post_spam(request: Request):
    payload, blocked = attacker_guard(request, "post_spam")
    if blocked: return blocked
    conn = get_conn()
    spam = "🎁 РАЗДАЮ КРИПТУ! Заходи по ссылке evil.link/free и получи 1 BTC бесплатно!"
    conn.execute("INSERT INTO posts (author, content, spam) VALUES (?,?,1)", (payload["user_id"], spam))
    conn.commit()
    return {"ok": True, "post": spam, "message": "Спам опубликован от имени жертвы"}

@app.post("/toggle-protection")
async def toggle_protection():
    global PROTECTION_ENABLED
    PROTECTION_ENABLED = not PROTECTION_ENABLED
    return {"protection": PROTECTION_ENABLED}

# ════════════════════════════════════════════════════
#  ЛОГИ ДЕТЕКТОРА
# ════════════════════════════════════════════════════
@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    return templates.TemplateResponse(request, "logs.html", {"logs": rows, "protection": PROTECTION_ENABLED})

@app.get("/health")
async def health():
    return {"status": "ok"}
