"""
KeyAuth API — Flask + JSONBin.io (banco persistente)
"""

import os
import json
import random
import string
import threading
import hashlib
import hmac
import base64
import time
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests as req_lib

# ════════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════════
MASTER_PASSWORD  = os.environ.get("MASTER_PASSWORD", "27112025")
MASTER_USER      = os.environ.get("MASTER_USER", "fax")
JWT_SECRET       = os.environ.get("JWT_SECRET", "fivem2025xK9mP3qL7nR2vT8wY4zA6bC")
JSONBIN_KEY      = os.environ.get("JSONBIN_KEY", "$2a$10$E5iuyg.pcXUG6Np8LTjcSeUxnaK96BFgFUBnYHks.TnRrOb0cLuBm")
JSONBIN_BIN_ID   = os.environ.get("JSONBIN_BIN_ID", "6ad80d10ffd5d160537db66a")
JSONBIN_BASE     = "https://api.jsonbin.io/v3/b"

DB_LOCK = threading.Lock()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

# ════════════════════════════════════════════════════════
#  JSONBIN — banco de dados persistente
# ════════════════════════════════════════════════════════
def _jsonbin_headers(write=False):
    h = {"X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json"}
    if not write:
        h["X-Bin-Meta"] = "false"
    return h

def load_db() -> list[dict]:
    try:
        r = req_lib.get(
            f"{JSONBIN_BASE}/{JSONBIN_BIN_ID}/latest",
            headers={"X-Master-Key": JSONBIN_KEY, "X-Bin-Meta": "false"},
            timeout=10
        )
        return r.json().get("keys", [])
    except Exception as e:
        print(f"[load_db error] {e}")
        return []

def save_db(keys: list[dict]) -> bool:
    try:
        r = req_lib.put(
            f"{JSONBIN_BASE}/{JSONBIN_BIN_ID}",
            json={"keys": keys},
            headers={"X-Master-Key": JSONBIN_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        print(f"[save_db] status={r.status_code} body={r.text[:100]}")
        return r.status_code == 200
    except Exception as e:
        print(f"[save_db error] {e}")
        return False

def find_key(keys, key_code):
    code = key_code.strip().upper()
    return next((k for k in keys if k["key_code"] == code), None)

def generate_key_code():
    chars = string.ascii_uppercase + string.digits
    return "KEY-" + "".join(random.choices(chars, k=11))

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def calc_expires(duration_type, from_dt):
    delta_map = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}
    if duration_type == "perm":
        return None
    return (from_dt + timedelta(days=delta_map.get(duration_type, 0))).isoformat()

def require_admin(req):
    pw   = req.headers.get("X-Admin-Password", "")
    user = req.headers.get("X-Admin-User", "")
    return pw == MASTER_PASSWORD and (user == MASTER_USER or user == "")

# ════════════════════════════════════════════════════════
#  RATE LIMITING
# ════════════════════════════════════════════════════════
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX    = 10
rate_store        = {}
rate_lock         = threading.Lock()

def check_rate_limit(ip):
    now = time.time()
    with rate_lock:
        ts = [t for t in rate_store.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
        if len(ts) >= RATE_LIMIT_MAX:
            rate_store[ip] = ts
            return False
        ts.append(now)
        rate_store[ip] = ts
        return True

def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

# ════════════════════════════════════════════════════════
#  JWT
# ════════════════════════════════════════════════════════
def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_create(payload, expires_in=1800):
    header  = _b64e(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    payload = dict(payload)
    payload["exp"] = int(time.time()) + expires_in
    payload["iat"] = int(time.time())
    body    = _b64e(json.dumps(payload).encode())
    sig     = hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64e(sig)}"

def jwt_verify(token):
    try:
        h, b, s = token.split(".")
        expected = hmac.new(JWT_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64e(expected), s):
            return None
        payload = json.loads(_b64d(b))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

# ════════════════════════════════════════════════════════
#  ROTA LOGIN ADMIN (para o painel web)
# ════════════════════════════════════════════════════════
@app.route("/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
    if request.method == "OPTIONS": return "", 204
    body = request.get_json(force=True) or {}
    user = body.get("username", "")
    pw   = body.get("password", "")
    if user == MASTER_USER and pw == MASTER_PASSWORD:
        token = jwt_create({"role": "admin", "user": user}, expires_in=7200)
        return jsonify({"ok": True, "token": token}), 200
    return jsonify({"ok": False, "message": "Credenciais inválidas."}), 401


# ════════════════════════════════════════════════════════
#  ROTAS AUTH
# ════════════════════════════════════════════════════════
@app.route("/auth/login", methods=["POST", "OPTIONS"])
def auth_login():
    if request.method == "OPTIONS": return "", 204
    ip = get_ip()
    if not check_rate_limit(ip):
        return jsonify({"ok": False, "message": "Muitas tentativas. Aguarde 1 minuto."}), 429

    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "").strip().upper()
    hwid     = body.get("hwid", "").strip()

    if not key_code or not hwid:
        return jsonify({"ok": False, "message": "Dados inválidos."}), 400

    with DB_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)

        if not key:
            return jsonify({"ok": False, "message": "❌  Key não encontrada."}), 200
        if key["status"] != "active":
            return jsonify({"ok": False, "message": "❌  Key desativada."}), 200
        if key["expires_at"]:
            exp = datetime.fromisoformat(key["expires_at"])
            if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return jsonify({"ok": False, "message": "❌  Key expirada."}), 200

        if key["hwid"] is None:
            now = datetime.now(timezone.utc)
            key["hwid"]         = hwid
            key["activated_at"] = now.isoformat()
            key["expires_at"]   = calc_expires(key["duration_type"], now)
            save_db(keys)
        elif key["hwid"] != hwid:
            return jsonify({"ok": False, "message": "❌  HWID incompatível!\nPeça um Reset de HWID no painel."}), 200

    token = jwt_create({"key": key_code, "hwid": hwid, "type": "session"})
    return jsonify({"ok": True, "message": "✅  Acesso autorizado!", "token": token, "expires_in": 1800}), 200


@app.route("/auth/inject", methods=["POST", "OPTIONS"])
def auth_inject():
    if request.method == "OPTIONS": return "", 204
    ip = get_ip()
    if not check_rate_limit(ip):
        return jsonify({"ok": False, "message": "Rate limit excedido."}), 429

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Token não fornecido."}), 401

    payload = jwt_verify(auth_header[7:])
    if not payload:
        return jsonify({"ok": False, "message": "❌  Sessão expirada. Faça login novamente."}), 200

    body = request.get_json(force=True) or {}
    hwid = body.get("hwid", "").strip()

    if payload.get("hwid") != hwid:
        return jsonify({"ok": False, "message": "❌  HWID incompatível."}), 200

    with DB_LOCK:
        keys     = load_db()
        key      = find_key(keys, payload.get("key"))
        if not key or key["status"] != "active":
            return jsonify({"ok": False, "message": "❌  Key desativada."}), 200
        if key["expires_at"]:
            exp = datetime.fromisoformat(key["expires_at"])
            if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return jsonify({"ok": False, "message": "❌  Key expirada."}), 200
        if key["hwid"] != hwid:
            return jsonify({"ok": False, "message": "❌  HWID incompatível."}), 200

    return jsonify({"ok": True, "message": "✅  Injeção autorizada."}), 200


# ════════════════════════════════════════════════════════
#  ROTAS ADMIN
# ════════════════════════════════════════════════════════
@app.route("/admin/generate", methods=["POST", "OPTIONS"])
def admin_generate():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(request): return jsonify({"error": "Não autorizado."}), 401

    body          = request.get_json(force=True) or {}
    duration_type = body.get("duration_type", "7d")
    qty           = max(1, min(int(body.get("qty", 1)), 50))

    if duration_type not in ("1d", "7d", "30d", "90d", "perm"):
        return jsonify({"error": "duration_type inválido."}), 400

    with DB_LOCK:
        keys     = load_db()
        existing = {k["key_code"] for k in keys}
        new_keys = []
        for _ in range(qty):
            code = generate_key_code()
            while code in existing:
                code = generate_key_code()
            existing.add(code)
            entry = {
                "key_code":      code,
                "duration_type": duration_type,
                "status":        "active",
                "hwid":          None,
                "created_at":    now_iso(),
                "activated_at":  None,
                "expires_at":    None,
            }
            keys.append(entry)
            new_keys.append(entry)
        save_db(keys)

    return jsonify({"generated": new_keys}), 201


@app.route("/admin/keys", methods=["GET", "OPTIONS"])
def admin_list_keys():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(request): return jsonify({"error": "Não autorizado."}), 401
    with DB_LOCK:
        keys = load_db()
    keys.sort(key=lambda k: k.get("created_at", ""), reverse=True)
    return jsonify(keys), 200


@app.route("/admin/reset-hwid", methods=["POST", "OPTIONS"])
def admin_reset_hwid():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(request): return jsonify({"error": "Não autorizado."}), 401
    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")
    with DB_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)
        if not key: return jsonify({"error": "Key não encontrada."}), 404
        key["hwid"]         = None
        key["activated_at"] = None
        key["expires_at"]   = None
        save_db(keys)
    return jsonify({"message": "HWID resetado.", "key": key}), 200


@app.route("/admin/toggle-status", methods=["POST", "OPTIONS"])
def admin_toggle_status():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(request): return jsonify({"error": "Não autorizado."}), 401
    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")
    with DB_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)
        if not key: return jsonify({"error": "Key não encontrada."}), 404
        key["status"] = "disabled" if key["status"] == "active" else "active"
        save_db(keys)
    return jsonify({"message": f"Status: {key['status']}", "key": key}), 200


@app.route("/admin/delete", methods=["DELETE", "OPTIONS"])
def admin_delete():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(request): return jsonify({"error": "Não autorizado."}), 401
    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")
    with DB_LOCK:
        keys   = load_db()
        new_db = [k for k in keys if k["key_code"] != key_code.strip().upper()]
        if len(new_db) == len(keys):
            return jsonify({"error": "Key não encontrada."}), 404
        save_db(new_db)
    return jsonify({"message": "Key deletada."}), 200


# ════════════════════════════════════════════════════════
#  HEALTH CHECK
# ════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "online", "service": "KeyAuth API"}), 200

@app.route("/debug", methods=["GET"])
def debug():
    try:
        keys = load_db()
        return jsonify({"ok": True, "keys_count": len(keys), "bin_id": JSONBIN_BIN_ID[:8] + "..."}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200

@app.route("/debug/write", methods=["GET"])
def debug_write():
    try:
        # Testa escrita direto
        test_data = [{"key_code": "KEY-TEST123TEST", "status": "active", "duration_type": "perm",
                      "hwid": None, "created_at": now_iso(), "activated_at": None, "expires_at": None}]
        ok = save_db(test_data)
        if ok:
            # Tenta ler de volta
            keys = load_db()
            return jsonify({"ok": True, "saved": ok, "read_back": len(keys), "jsonbin_key_prefix": JSONBIN_KEY[:10]}), 200
        else:
            return jsonify({"ok": False, "saved": False}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
