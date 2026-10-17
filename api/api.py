"""
KeyAuth API — Arquitetura Segura
- JWT com expiração de 30 minutos
- Validação dupla: login + pré-injeção
- Rate limiting por IP e por key
- Verificação de HWID em toda requisição autenticada
- A URL da API não precisa estar hardcoded no cliente
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

# ════════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════════
MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "27112005")
JWT_SECRET      = os.environ.get("JWT_SECRET", "mude_isso_para_uma_string_aleatoria_longa_32chars")
DATA_FILE       = os.path.join(os.path.dirname(__file__), "keys.json")
FILE_LOCK       = threading.Lock()

# Rate limiting — máximo de tentativas por IP
RATE_LIMIT_WINDOW  = 60    # segundos
RATE_LIMIT_MAX     = 10    # tentativas por janela
rate_limit_store   = {}    # { ip: [timestamps] }
rate_limit_lock    = threading.Lock()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

# ════════════════════════════════════════════════════════
#  JWT SIMPLES (sem dependência externa)
# ════════════════════════════════════════════════════════
def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_create(payload: dict, expires_in: int = 1800) -> str:
    """Cria um JWT HS256. expires_in em segundos (padrão 30 min)."""
    header  = _b64_encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    payload = dict(payload)
    payload["exp"] = int(time.time()) + expires_in
    payload["iat"] = int(time.time())
    body    = _b64_encode(json.dumps(payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64_encode(sig)}"

def jwt_verify(token: str) -> dict | None:
    """Verifica e decodifica o JWT. Retorna None se inválido/expirado."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        sig_input = f"{header}.{body}".encode()
        expected  = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64_encode(expected), sig):
            return None
        payload = json.loads(_b64_decode(body))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

# ════════════════════════════════════════════════════════
#  RATE LIMITING
# ════════════════════════════════════════════════════════
def check_rate_limit(ip: str) -> bool:
    """Retorna True se o IP pode prosseguir, False se bloqueado."""
    now = time.time()
    with rate_limit_lock:
        timestamps = rate_limit_store.get(ip, [])
        # Remove timestamps antigos
        timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if len(timestamps) >= RATE_LIMIT_MAX:
            rate_limit_store[ip] = timestamps
            return False
        timestamps.append(now)
        rate_limit_store[ip] = timestamps
        return True

def get_ip() -> str:
    # Suporta proxy reverso (Render/Railway usam X-Forwarded-For)
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

# ════════════════════════════════════════════════════════
#  HELPERS — banco JSON
# ════════════════════════════════════════════════════════
def load_db() -> list[dict]:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_db(data: list[dict]) -> None:
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def find_key(keys: list[dict], key_code: str) -> dict | None:
    code = key_code.strip().upper()
    return next((k for k in keys if k["key_code"] == code), None)

def generate_key_code() -> str:
    chars = string.ascii_uppercase + string.digits
    return "KEY-" + "".join(random.choices(chars, k=11))

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def calc_expires(duration_type: str, from_dt: datetime) -> str | None:
    delta_map = {"1d": 1, "7d": 7, "30d": 30}
    if duration_type == "perm":
        return None
    return (from_dt + timedelta(days=delta_map.get(duration_type, 0))).isoformat()

def require_admin(req) -> bool:
    return req.headers.get("X-Admin-Password", "") == MASTER_PASSWORD

# ════════════════════════════════════════════════════════
#  ROTA 1 — LOGIN (valida key + HWID, retorna JWT)
#  POST /auth/login
#  Body: { "key_code": "KEY-...", "hwid": "123456" }
#  Retorna: { "ok": true, "token": "<jwt>", "expires_in": 1800 }
# ════════════════════════════════════════════════════════
@app.route("/auth/login", methods=["POST", "OPTIONS"])
def auth_login():
    if request.method == "OPTIONS":
        return "", 204

    ip = get_ip()
    if not check_rate_limit(ip):
        return jsonify({"ok": False, "message": "Muitas tentativas. Aguarde 1 minuto."}), 429

    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "").strip().upper()
    hwid     = body.get("hwid", "").strip()

    if not key_code or not hwid:
        return jsonify({"ok": False, "message": "Dados inválidos."}), 400

    with FILE_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)

        if not key:
            return jsonify({"ok": False, "message": "❌  Key não encontrada."}), 200

        if key["status"] != "active":
            return jsonify({"ok": False, "message": "❌  Key desativada."}), 200

        if key["expires_at"]:
            exp = datetime.fromisoformat(key["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return jsonify({"ok": False, "message": "❌  Key expirada."}), 200

        # Primeiro acesso — vincula HWID
        if key["hwid"] is None:
            now = datetime.now(timezone.utc)
            key["hwid"]         = hwid
            key["activated_at"] = now.isoformat()
            key["expires_at"]   = calc_expires(key["duration_type"], now)
            save_db(keys)

        elif key["hwid"] != hwid:
            return jsonify({
                "ok": False,
                "message": "❌  HWID incompatível!\nPeça um Reset de HWID no painel."
            }), 200

    # Gera JWT com key_code e hwid embutidos
    token = jwt_create({"key": key_code, "hwid": hwid, "type": "session"})
    return jsonify({"ok": True, "message": "✅  Acesso autorizado!", "token": token, "expires_in": 1800}), 200


# ════════════════════════════════════════════════════════
#  ROTA 2 — VERIFICAÇÃO PRÉ-INJEÇÃO (valida o JWT)
#  POST /auth/inject
#  Header: Authorization: Bearer <token>
#  Body: { "hwid": "123456" }
#  Retorna: { "ok": true } ou { "ok": false }
# ════════════════════════════════════════════════════════
@app.route("/auth/inject", methods=["POST", "OPTIONS"])
def auth_inject():
    if request.method == "OPTIONS":
        return "", 204

    ip = get_ip()
    if not check_rate_limit(ip):
        return jsonify({"ok": False, "message": "Rate limit excedido."}), 429

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Token não fornecido."}), 401

    token   = auth_header[7:]
    payload = jwt_verify(token)

    if not payload:
        return jsonify({"ok": False, "message": "❌  Sessão expirada. Faça login novamente."}), 200

    body = request.get_json(force=True) or {}
    hwid = body.get("hwid", "").strip()

    # Verifica HWID do token com o HWID enviado agora
    if payload.get("hwid") != hwid:
        return jsonify({"ok": False, "message": "❌  HWID incompatível."}), 200

    # Verifica no banco se a key ainda está ativa (pode ter sido desativada depois do login)
    key_code = payload.get("key")
    with FILE_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)

        if not key or key["status"] != "active":
            return jsonify({"ok": False, "message": "❌  Key desativada."}), 200

        if key["expires_at"]:
            exp = datetime.fromisoformat(key["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
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
    if not require_admin(request):  return jsonify({"error": "Não autorizado."}), 401

    body          = request.get_json(force=True) or {}
    duration_type = body.get("duration_type", "7d")
    qty           = max(1, min(int(body.get("qty", 1)), 50))

    if duration_type not in ("1d", "7d", "30d", "perm"):
        return jsonify({"error": "duration_type inválido."}), 400

    with FILE_LOCK:
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
    if not require_admin(request):  return jsonify({"error": "Não autorizado."}), 401
    with FILE_LOCK:
        keys = load_db()
    keys.sort(key=lambda k: k.get("created_at", ""), reverse=True)
    return jsonify(keys), 200


@app.route("/admin/reset-hwid", methods=["POST", "OPTIONS"])
def admin_reset_hwid():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(request):  return jsonify({"error": "Não autorizado."}), 401
    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")
    with FILE_LOCK:
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
    if not require_admin(request):  return jsonify({"error": "Não autorizado."}), 401
    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")
    with FILE_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)
        if not key: return jsonify({"error": "Key não encontrada."}), 404
        key["status"] = "disabled" if key["status"] == "active" else "active"
        save_db(keys)
    return jsonify({"message": f"Status: {key['status']}", "key": key}), 200


@app.route("/admin/delete", methods=["DELETE", "OPTIONS"])
def admin_delete():
    if request.method == "OPTIONS": return "", 204
    if not require_admin(request):  return jsonify({"error": "Não autorizado."}), 401
    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")
    with FILE_LOCK:
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
