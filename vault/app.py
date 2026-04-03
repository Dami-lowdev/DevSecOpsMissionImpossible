import os
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

@app.get("/secret")
def secret():
    tok = request.args.get("token", "")
    if tok != os.getenv("VAULT_TOKEN", ""):
        abort(403)
    return jsonify({
        "vault": "ok",
        "flag_vault": os.getenv("FLAG_VAULT", "FLAG{missing}")
    })

@app.get("/health")
def health():
    return jsonify({"ok":True})

# Removed /debug endpoint to prevent environment variables exfiltration

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
