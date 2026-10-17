"""
KeyAuth API — Flask
Banco de dados: keys.json (arquivo local no servidor)
Deploy: Railway ou Render (grátis)

Endpoints:
  POST /admin/generate      → gera keys (requer senha mestre no header)
  GET  /admin/keys          → lista todas as keys
  POST /admin/reset-hwid    → reseta HWID de uma key
  POST /admin/toggle-status → ativa ou desativa uma key
  DELETE /admin/delete      → deleta uma key
  POST /auth/validate       → valida key + HWID (usado pelo loader)
"""

import os
import json
import random
import string
import threading
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS

# ════════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════════
MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD", "27112005")
DATA_FILE       = os.path.join(os.path.dirname(__file__), "keys.json")
FILE_LOCK       = threading.Lock()   # evita condição de corrida em writes

app = Flask(__name__)
CORS(app)   # permite requisições do painel Netlify (origem diferente)

# ════════════════════════════════════════════════════════
#  HELPERS — persistência em JSON
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
    suffix = "".join(random.choices(chars, k=11))
    return f"KEY-{suffix}"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def calc_expires(duration_type: str, from_dt: datetime) -> str | None:
    delta_map = {"1d": 1, "7d": 7, "30d": 30}
    if duration_type == "perm":
        return None
    days = delta_map.get(duration_type, 0)
    return (from_dt + timedelta(days=days)).isoformat()

# ════════════════════════════════════════════════════════
#  MIDDLEWARE — autenticação admin
# ════════════════════════════════════════════════════════
def require_admin(req) -> bool:
    """Verifica se o header X-Admin-Password bate com MASTER_PASSWORD."""
    pwd = req.headers.get("X-Admin-Password", "")
    return pwd == MASTER_PASSWORD

# ════════════════════════════════════════════════════════
#  ROTAS ADMIN
# ════════════════════════════════════════════════════════

@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    if not require_admin(request):
        return jsonify({"error": "Não autorizado."}), 401

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
            while code in existing:          # garante unicidade
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


@app.route("/admin/keys", methods=["GET"])
def admin_list_keys():
    if not require_admin(request):
        return jsonify({"error": "Não autorizado."}), 401

    with FILE_LOCK:
        keys = load_db()

    # Ordena por created_at desc
    keys.sort(key=lambda k: k.get("created_at", ""), reverse=True)
    return jsonify(keys), 200


@app.route("/admin/reset-hwid", methods=["POST"])
def admin_reset_hwid():
    if not require_admin(request):
        return jsonify({"error": "Não autorizado."}), 401

    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")

    with FILE_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)
        if not key:
            return jsonify({"error": "Key não encontrada."}), 404

        key["hwid"]         = None
        key["activated_at"] = None
        key["expires_at"]   = None
        save_db(keys)

    return jsonify({"message": "HWID resetado com sucesso.", "key": key}), 200


@app.route("/admin/toggle-status", methods=["POST"])
def admin_toggle_status():
    if not require_admin(request):
        return jsonify({"error": "Não autorizado."}), 401

    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")

    with FILE_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)
        if not key:
            return jsonify({"error": "Key não encontrada."}), 404

        key["status"] = "disabled" if key["status"] == "active" else "active"
        save_db(keys)

    return jsonify({"message": f"Status alterado para '{key['status']}'.", "key": key}), 200


@app.route("/admin/delete", methods=["DELETE"])
def admin_delete():
    if not require_admin(request):
        return jsonify({"error": "Não autorizado."}), 401

    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "")

    with FILE_LOCK:
        keys    = load_db()
        new_db  = [k for k in keys if k["key_code"] != key_code.strip().upper()]
        if len(new_db) == len(keys):
            return jsonify({"error": "Key não encontrada."}), 404
        save_db(new_db)

    return jsonify({"message": "Key deletada."}), 200


# ════════════════════════════════════════════════════════
#  ROTA DE VALIDAÇÃO (Loader Python)
# ════════════════════════════════════════════════════════

@app.route("/auth/validate", methods=["POST"])
def auth_validate():
    body     = request.get_json(force=True) or {}
    key_code = body.get("key_code", "").strip().upper()
    hwid     = body.get("hwid", "").strip()

    if not key_code or not hwid:
        return jsonify({"ok": False, "message": "Dados inválidos."}), 400

    with FILE_LOCK:
        keys = load_db()
        key  = find_key(keys, key_code)

        # ── Key não existe ─────────────────────────────
        if not key:
            return jsonify({"ok": False, "message": "❌  Key não encontrada."}), 200

        # ── Desativada ─────────────────────────────────
        if key["status"] != "active":
            return jsonify({"ok": False, "message": "❌  Key desativada. Contate o administrador."}), 200

        # ── Expirada ───────────────────────────────────
        if key["expires_at"]:
            exp = datetime.fromisoformat(key["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return jsonify({"ok": False, "message": "❌  Key expirada."}), 200

        # ── Primeiro acesso: vincula HWID ──────────────
        if key["hwid"] is None:
            now = datetime.now(timezone.utc)
            key["hwid"]         = hwid
            key["activated_at"] = now.isoformat()
            key["expires_at"]   = calc_expires(key["duration_type"], now)
            save_db(keys)
            return jsonify({"ok": True, "message": "✅  Key ativada com sucesso!"}), 200

        # ── HWID incompatível ──────────────────────────
        if key["hwid"] != hwid:
            return jsonify({
                "ok":      False,
                "message": "❌  HWID incompatível!\nEsta key está vinculada a outro PC.\nPeça um Reset de HWID no painel."
            }), 200

        # ── Acesso normal ──────────────────────────────
        return jsonify({"ok": True, "message": "✅  Acesso autorizado!"}), 200


# ════════════════════════════════════════════════════════
#  HEALTH CHECK
# ════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "online", "service": "KeyAuth API"}), 200


# ════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
