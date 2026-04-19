from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import jwt, datetime, hashlib, sqlite3, time, os
from collections import defaultdict

app = FastAPI()
templates = Jinja2Templates(directory="templates")
SECRET = os.getenv("SECRET_KEY", "diploma_session_key_2025")
DB_PATH = os.getenv("DB_PATH", "users.db")
request_counts = defaultdict(list)

# ── База данных ──────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, token TEXT, ip TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, ip TEXT, user_agent TEXT,
        action TEXT, flags TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    return conn

# ── Rate limiting ────────────────────────────────────
@app.middleware("http")
async def rate_limit(request: Request, call_next):
    ip = request.client.host
    now = time.time()
    request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
    if len(request_counts[ip]) > 60:
        return HTMLResponse("Too many requests", status_code=429)
    request_counts[ip].append(now)
    return await call_next(request)

# ── Детектор аномалий ────────────────────────────────
def analyze(payload: dict, current_ip: str, current_ua: str) -> dict:
    flags, risk = [], 0

    if payload.get("ip") != current_ip:
        flags.append("IP_CHANGE")
        risk += 40

    if payload.get("ua") != current_ua:
        flags.append("DEVICE_CHANGE")
        risk += 30

    return {
        "risk_score": min(risk, 100),
        "flags": flags,
        "action": "BLOCK" if risk >= 60 else "ALERT" if risk >= 30 else "OK"
    }

# ── Маршруты ─────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html",
        {"request": request, "error": None})

@app.post("/register")
async def register(request: Request,
                   username: str = Form(),
                   password: str = Form(),
                   password2: str = Form()):
    if password != password2:
        return templates.TemplateResponse("register.html",
            {"request": request, "error": "Пароли не совпадают"})
    if len(password) < 6:
        return templates.TemplateResponse("register.html",
            {"request": request, "error": "Пароль минимум 6 символов"})
    if len(username) < 3:
        return templates.TemplateResponse("register.html",
            {"request": request, "error": "Логин минимум 3 символа"})
    conn = get_conn()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return templates.TemplateResponse("register.html",
            {"request": request, "error": "Пользователь уже существует"})
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn.execute("INSERT INTO users VALUES (?,?)", (username, hashed))
    conn.commit()
    return RedirectResponse("/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html",
        {"request": request, "error": None})

@app.post("/login")
async def login(request: Request,
                username: str = Form(),
                password: str = Form()):
    conn = get_conn()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, hashed)
    ).fetchone()
    if not user:
        return templates.TemplateResponse("login.html",
            {"request": request, "error": "Неверный логин или пароль"})

    payload = {
        "user_id": username,
        "ip":      request.client.host,
        "ua":      request.headers.get("user-agent", ""),
        "exp":     datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")

    conn.execute(
        "INSERT INTO sessions (username,token,ip,user_agent) VALUES (?,?,?,?)",
        (username, token, request.client.host,
         request.headers.get("user-agent", ""))
    )
    conn.commit()

    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("token", token, httponly=True,
                    samesite="lax", max_age=3600)
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    token = request.cookies.get("token")
    if not token:
        return RedirectResponse("/login")
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return RedirectResponse("/login")
    except Exception:
        return RedirectResponse("/login")

    current_ip = request.client.host
    current_ua = request.headers.get("user-agent", "")
    result = analyze(payload, current_ip, current_ua)

    conn = get_conn()
    conn.execute(
        "INSERT INTO logs (username,ip,user_agent,action,flags) VALUES (?,?,?,?,?)",
        (payload["user_id"], current_ip, current_ua,
         result["action"], ", ".join(result["flags"]))
    )
    conn.commit()

    return templates.TemplateResponse("dashboard.html", {
        "request":    request,
        "user":       payload["user_id"],
        "token":      token,
        "session_ip": current_ip,
        "action":     result["action"],
        "flags":      result["flags"],
        "risk":       result["risk_score"],
    })

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    token = request.cookies.get("token")
    if not token:
        return RedirectResponse("/login")
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return templates.TemplateResponse("logs.html",
        {"request": request, "logs": rows})

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("token")
    return resp

@app.get("/health")
async def health():
    return {"status": "ok"}
