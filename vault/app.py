import os
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

import hmac

@app.get("/secret")
def secret():
    auth_header = request.headers.get("Authorization", "")
    tok = auth_header.replace("Bearer ", "")
    
    if not hmac.compare_digest(tok, os.getenv("VAULT_TOKEN", "MISSING_VAULT_TOKEN")):
        abort(403)
    return jsonify({
        "vault": "ok",
        "flag_vault": os.getenv("FLAG_VAULT", "FLAG{missing}")
    })

@app.get("/health")
def health():
    return jsonify({"ok":True})

@app.get("/debug")
def debug():
    return jsonify(dict(os.environ))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
