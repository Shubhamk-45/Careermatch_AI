"""DeepfakeGuard backend: accounts (18+), OTP password reset, admin data, real AI analysis."""
import os, re, io, csv, time, hmac, hashlib, sqlite3, smtplib, tempfile, secrets
from datetime import date, datetime
from email.message import EmailMessage
from functools import wraps
from flask import Flask, request, jsonify, g, Response
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

SECRET = os.getenv("SECRET_KEY") or secrets.token_hex(32)   # set SECRET_KEY, or logins reset on restart
ADMINS = {e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()}
DB = os.getenv("DB_PATH", "deepfakeguard.db")
IMAGE_MODEL = os.getenv("IMAGE_MODEL", "Hemg/Deepfake-Detection")
AUDIO_MODEL = os.getenv("AUDIO_MODEL", "MelodyMachine/Deepfake-audio-detection-V2")
THRESHOLD = 0.70
FAKE = ("fake", "deepfake", "synthetic", "spoof", "generated")
REAL = ("real", "bonafide", "genuine", "human", "authentic")
TYPES = {"jpg": "image", "jpeg": "image", "png": "image", "mp4": "video", "mov": "video",
         "mp3": "audio", "wav": "audio", "m4a": "audio", "ogg": "audio"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
CORS(app, origins=os.getenv("ALLOWED_ORIGIN", "*").split(","))   # set ALLOWED_ORIGIN to your site URL
ser = URLSafeTimedSerializer(SECRET)

# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d: d.close()

def init():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, mobile TEXT UNIQUE,
      dob TEXT, pw TEXT, created TEXT, last_login TEXT, logins INTEGER DEFAULT 0, failed INTEGER DEFAULT 0, locked REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, email TEXT, kind TEXT, ip TEXT, ua TEXT, at TEXT);
    CREATE TABLE IF NOT EXISTS otps(email TEXT PRIMARY KEY, code TEXT, exp REAL, tries INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, email TEXT, file TEXT, media TEXT, status TEXT,
      model TEXT, label TEXT, score REAL, at TEXT);""")
    c.commit(); c.close()
init()

now = lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
def log(email, kind):
    db().execute("INSERT INTO events(email,kind,ip,ua,at) VALUES(?,?,?,?,?)",
                 (email, kind, request.headers.get("X-Forwarded-For", request.remote_addr), (request.user_agent.string or "")[:200], now()))
    db().commit()

# ---------- helpers ----------
HITS = {}
def limited(key, n, sec):
    t = time.time(); q = [x for x in HITS.get(key, []) if t - x < sec]
    if len(q) >= n:
        HITS[key] = q; return True
    HITS[key] = q + [t]; return False

def body():
    # accepts JSON even if Content-Type is wrong, and form data as a fallback
    return request.get_json(force=True, silent=True) or request.form.to_dict() or {}

def err(msg, code=400): return jsonify(error=msg), code
def age(dob):
    b = date.fromisoformat(dob); t = date.today()
    return t.year - b.year - ((t.month, t.day) < (b.month, b.day))
def pw_ok(p): return len(p) >= 8 and re.search(r"[A-Za-z]", p) and re.search(r"\d", p)
def public(u): return dict(name=u["name"], email=u["email"], admin=u["email"] in ADMINS)

def auth(admin=False):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            try:
                uid = ser.loads(request.headers.get("Authorization", "")[7:], salt="auth", max_age=8 * 3600)["uid"]
            except (BadSignature, SignatureExpired, KeyError):
                return err("Please log in again.", 401)
            u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if not u: return err("Please log in again.", 401)
            if admin and u["email"] not in ADMINS: return err("Admins only.", 403)
            g.user = u
            return f(*a, **k)
        return w
    return deco

@app.errorhandler(HTTPException)
def http_error(e): return jsonify(error=f"{e.name}: {e.description}"), e.code

@app.errorhandler(Exception)
def server_error(e):
    print("Unhandled error:", repr(e)); return jsonify(error="Server error. Check the server logs."), 500

@app.after_request
def headers(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
    return r

def send_otp(email, code):
    host = os.getenv("SMTP_HOST")
    if not host:
        print(f"[DEV ONLY] SMTP not configured. OTP for {email}: {code}"); return
    m = EmailMessage(); m["Subject"] = "DeepfakeGuard password reset code"
    m["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER")); m["To"] = email
    m.set_content(f"Your DeepfakeGuard OTP is {code}. It expires in 10 minutes. If you did not ask for it, ignore this email.")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", 587))) as s:
        s.starttls(); s.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS")); s.send_message(m)

# ---------- accounts ----------
@app.get("/api/health")
def health(): return jsonify(status="ok")

@app.post("/api/register")
def register():
    if limited(("reg", request.remote_addr), 10, 3600): return err("Too many attempts. Try later.", 429)
    d = body()
    name = str(d.get("name", "")).strip(); email = str(d.get("email", "")).strip().lower()
    mobile = re.sub(r"[\s\-().]", "", str(d.get("mobile", ""))); mobile = "+" + mobile[2:] if mobile.startswith("00") else mobile; dob = str(d.get("dob", "")); pw = str(d.get("password", ""))
    if len(name) < 2: return err("Enter your full name.")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): return err("Enter a valid email.")
    if not re.fullmatch(r"\+?\d{10,15}", mobile): return err("Enter a valid mobile number (10-15 digits).")
    try:
        if not 18 <= age(dob) <= 120: return err("You must be 18 or older to use DeepfakeGuard.", 403)
    except ValueError: return err("Date of birth is required.")
    if not pw_ok(pw): return err("Password needs 8+ characters with letters and numbers.")
    if str(d.get("consent")).lower() not in ("true", "1", "on"): return err("Please accept the data consent.")
    try:
        cur = db().execute("INSERT INTO users(name,email,mobile,dob,pw,created) VALUES(?,?,?,?,?,?)",
                           (name, email, mobile, dob, generate_password_hash(pw), now())); db().commit()
    except sqlite3.IntegrityError: return err("Email or mobile is already registered.", 409)
    log(email, "register")
    u = db().execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(token=ser.dumps({"uid": u["id"]}, salt="auth"), user=public(u))

@app.post("/api/login")
def login():
    if limited(("login", request.remote_addr), 20, 600): return err("Too many attempts. Try later.", 429)
    d = body()
    email = str(d.get("email", "")).strip().lower()
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if u and u["locked"] > time.time(): return err("Account locked for 15 minutes after too many wrong passwords.", 423)
    if not u or not check_password_hash(u["pw"], str(d.get("password", ""))):
        if u:
            f = u["failed"] + 1
            db().execute("UPDATE users SET failed=?, locked=? WHERE id=?", (0 if f >= 5 else f, time.time() + 900 if f >= 5 else 0, u["id"])); db().commit()
        log(email, "login_failed"); return err("Email or password is incorrect.", 401)
    db().execute("UPDATE users SET failed=0, locked=0, last_login=?, logins=logins+1 WHERE id=?", (now(), u["id"])); db().commit()
    log(email, "login")
    return jsonify(token=ser.dumps({"uid": u["id"]}, salt="auth"), user=public(u))

@app.get("/api/me")
@auth()
def me(): return jsonify(user=public(g.user))

@app.post("/api/forgot")
def forgot():
    d = body(); email = str(d.get("email", "")).strip().lower()
    if limited(("otp", email), 3, 3600) or limited(("otp", request.remote_addr), 10, 3600): return err("Too many requests. Try later.", 429)
    if db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        code = f"{secrets.randbelow(10**6):06d}"
        db().execute("REPLACE INTO otps(email,code,exp,tries) VALUES(?,?,?,0)", (email, hashlib.sha256((code + SECRET).encode()).hexdigest(), time.time() + 600)); db().commit()
        try: send_otp(email, code)
        except Exception as e: print("Email failed:", e); return err("Could not send email. Check SMTP settings.", 502)
        log(email, "otp_requested")
    return jsonify(ok=True)   # same reply whether or not the email exists

@app.post("/api/verify-otp")
def verify_otp():
    d = body(); email = str(d.get("email", "")).strip().lower()
    o = db().execute("SELECT * FROM otps WHERE email=?", (email,)).fetchone()
    if not o or o["exp"] < time.time() or o["tries"] >= 5: return err("OTP expired or invalid. Request a new one.", 400)
    db().execute("UPDATE otps SET tries=tries+1 WHERE email=?", (email,)); db().commit()
    if not hmac.compare_digest(o["code"], hashlib.sha256((str(d.get("otp", "")) + SECRET).encode()).hexdigest()): return err("Wrong OTP.")
    db().execute("DELETE FROM otps WHERE email=?", (email,)); db().commit()
    u = db().execute("SELECT pw FROM users WHERE email=?", (email,)).fetchone()
    return jsonify(token=ser.dumps({"e": email, "v": u["pw"][-12:]}, salt="reset"))

@app.post("/api/reset")
def reset():
    d = body()
    try: t = ser.loads(str(d.get("token", "")), salt="reset", max_age=600)
    except (BadSignature, SignatureExpired): return err("Reset session expired. Start again.")
    u = db().execute("SELECT * FROM users WHERE email=?", (t["e"],)).fetchone()
    if not u or u["pw"][-12:] != t["v"]: return err("This reset link was already used.")
    p = str(d.get("new_password", ""))
    if not pw_ok(p): return err("Password needs 8+ characters with letters and numbers.")
    db().execute("UPDATE users SET pw=?, failed=0, locked=0 WHERE id=?", (generate_password_hash(p), u["id"])); db().commit()
    log(u["email"], "password_reset"); return jsonify(ok=True)

# ---------- AI analysis ----------
_models = {}
def model(kind):
    if kind not in _models:
        from transformers import pipeline
        _models[kind] = pipeline("image-classification" if kind == "image" else "audio-classification",
                                 model=IMAGE_MODEL if kind == "image" else AUDIO_MODEL)
    return _models[kind]

def judge(kind, x):
    top = max(model(kind)(x), key=lambda p: p["score"]); lab = top["label"].lower()
    if top["score"] < THRESHOLD: return "inconclusive", top
    if any(w in lab for w in FAKE): return "manipulated", top
    if any(w in lab for w in REAL): return "clean", top
    return "inconclusive", top

def frames(path, n=8):
    import cv2
    from PIL import Image
    cap = cv2.VideoCapture(path); total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0; out = []
    for i in range(n):
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(total * i / n)); ok, f = cap.read()
        if ok: out.append(Image.fromarray(cv2.cvtColor(f, cv2.COLOR_BGR2RGB)))
    cap.release(); return out

@app.post("/api/analyze")
@auth()
def analyze():
    if limited(("scan", g.user["id"]), 30, 3600): return err("Scan limit reached. Try again later.", 429)
    f = request.files.get("file")
    if not f or "." not in f.filename: return err("No file uploaded.")
    ext = f.filename.rsplit(".", 1)[-1].lower(); kind = TYPES.get(ext)
    if not kind: return err("Unsupported file type.", 415)
    path = None
    try:
        if kind == "image":
            from PIL import Image
            st, top = judge("image", Image.open(f.stream).convert("RGB")); label, score, model_name, det = top["label"], top["score"], IMAGE_MODEL, ""
        else:
            with tempfile.NamedTemporaryFile(suffix="." + ext, delete=False) as t:
                f.save(t.name); path = t.name
            if kind == "audio":
                st, top = judge("audio", path); label, score, model_name, det = top["label"], top["score"], AUDIO_MODEL, ""
            else:
                res = [judge("image", x) for x in frames(path)]
                if not res: return jsonify(status="inconclusive", media=kind, model=IMAGE_MODEL, label="no frames read", score=None, details="Video could not be read.")
                m = sum(r[0] == "manipulated" for r in res); k = sum(r[0] == "clean" for r in res)
                st = "manipulated" if m >= len(res) / 2 else "clean" if k >= len(res) / 2 else "inconclusive"
                label, score, model_name = f"{m}/{len(res)} frames suspicious", sum(r[1]["score"] for r in res) / len(res), IMAGE_MODEL
                det = f"{len(res)} frames checked. The video's audio track was not analysed."
    except Exception as e:
        return err(f"Analysis failed: {e}", 500)
    finally:
        if path and os.path.exists(path): os.remove(path)     # uploads are never kept
    db().execute("INSERT INTO scans(email,file,media,status,model,label,score,at) VALUES(?,?,?,?,?,?,?,?)",
                 (g.user["email"], f.filename[:120], kind, st, model_name, label, score, now())); db().commit()
    return jsonify(status=st, media=kind, model=model_name, label=label, score=score, details=det)

# ---------- admin ----------
TABLES = {"users": "SELECT name,email,mobile,dob,created,last_login,logins FROM users ORDER BY id DESC",
          "events": "SELECT at,email,kind,ip FROM events ORDER BY id DESC LIMIT 1000",
          "scans": "SELECT at,email,file,media,status,model,label,score FROM scans ORDER BY id DESC LIMIT 1000"}

@app.get("/api/admin/<t>")
@auth(admin=True)
def admin_rows(t):
    if t not in TABLES: return err("Not found.", 404)
    return jsonify(rows=[dict(r) for r in db().execute(TABLES[t])])

@app.get("/api/admin/<t>.csv")
@auth(admin=True)
def admin_csv(t):
    if t not in TABLES: return err("Not found.", 404)
    rows = db().execute(TABLES[t]).fetchall(); out = io.StringIO(); w = csv.writer(out)
    if rows: w.writerow(rows[0].keys())
    safe = lambda v: "'" + str(v) if str(v)[:1] in "=+-@" else v    # blocks CSV formula injection
    for r in rows: w.writerow([safe(v) if v is not None else "" for v in r])
    return Response(out.getvalue(), mimetype="text/csv")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
