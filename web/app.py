import os
import re
import json
import requests
from requests.exceptions import RequestException
from flask import Flask, request, jsonify, abort, make_response, render_template_string

app = Flask(__name__)

# still intentionally flawed for the exercise
app.config["SECRET_KEY"] = os.getenv("JWT_SECRET", "dev-secret-CHANGE-ME")
app.config["JSON_SORT_KEYS"] = False

HOME = """
<h1>Mission Pipeline</h1>
<p>Objectif : sécuriser <b>la supply chain</b> (build/test/scan), les <b>secrets</b>, et l'app (<b>SSRF</b>, auth, logs).</p>
<ul>
  <li><a href="/status">/status</a></li>
  <li><a href="/whoami">/whoami</a></li>
  <li><a href="/fetch?url=https://example.com">/fetch</a> (⚠️ SSRF)</li>
  <li><a href="/admin?token=...">/admin</a> (token)</li>
  <li><a href="/docs">/docs</a> (pistes DevSecOps)</li>
</ul>
<p><b>Note</b> : tout reste local. Les “flags” sont dans les variables d’environnement.</p>
"""

@app.get("/")
def index():
    return render_template_string(HOME)

@app.get("/status")
def status():
    return jsonify({"service": "escape-app-expert", "ok": True})

# Weak identity: trusts a header set by reverse proxy (not present here)
@app.get("/whoami")
def whoami():
    user = request.headers.get("X-User", "anonymous")
    resp = make_response(jsonify({"user": user}))
    # intentionally weak cookie settings for workshop
    resp.set_cookie("session", "dev", httponly=False, samesite="Lax")
    return resp


# ============================================================
# BLUE TEAM — Mission 1 : Mitigation SSRF
# Auteur   : mike
# Date     : 2026-02-20
# ============================================================
#
# MÉCANISME DE PROTECTION :
#   1. Allowlist de schémas : seuls http et https autorisés.
#      → file://, gopher://, dict://, ftp:// et autres vecteurs bloqués.
#
#   2. Blocage des hostnames internes connus :
#      → vault, localhost, host.docker.internal... bloqués par nom.
#      Raison : Docker résout "vault" en IP interne avant la requête.
#
#   3. Résolution DNS + blocage IP privées (RFC 1918, loopback, link-local) :
#      → On résout le nom de domaine en IP AVANT d'envoyer la requête.
#      → On vérifie que l'IP n'appartient pas à un sous-réseau privé.
#      Raison : empêche le DNS rebinding (validation IP en temps réel).
#
#   4. allow_redirects=False :
#      → Empêche qu'une 302 redirige silencieusement vers 127.0.0.1
#      après validation de l'URL d'origine.
#
#   5. Gestion d'erreurs maîtrisée :
#      → Aucune stacktrace exposée. Messages d'erreur JSON structurés.
#
# LIMITATIONS CONNUES :
#   - Un attaquant contrôlant le DNS (TTL=0) peut changer l'IP après
#     la résolution (DNS rebinding avancé). Mitigation partielle seulement
#     sans cache DNS dédié ou proxy de sortie.
#   - L'allowlist de domaines n'est pas implémentée ici (aucun domaine
#     légitime n'est connu dans ce TP). En production : TOUJOURS ajouter
#     une allowlist explicite des domaines autorisés.
#   - Le timeout de 3 s peut permettre une énumération lente du réseau.
# ============================================================

import socket
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

# Schémas autorisés uniquement
ALLOWED_SCHEMES = {"http", "https"}

# Hostnames internes explicitement interdits (noms de service Docker, etc.)
BLOCKED_HOSTNAMES = {
    "localhost",
    "vault",
    "host.docker.internal",
    "metadata.google.internal",
    "169.254.169.254",  # AWS / GCP metadata IP
}

# Plages d'adresses IP privées à bloquer (RFC 1918 + loopback + link-local + CGNAT)
BLOCKED_NETWORKS = [
    ip_network("10.0.0.0/8"),          # RFC 1918 — réseaux privés de classe A
    ip_network("172.16.0.0/12"),        # RFC 1918 — réseaux privés de classe B
    ip_network("192.168.0.0/16"),       # RFC 1918 — réseaux privés de classe C
    ip_network("127.0.0.0/8"),          # Loopback IPv4 (localhost)
    ip_network("169.254.0.0/16"),       # Link-local (APIPA / AWS metadata)
    ip_network("100.64.0.0/10"),        # CGNAT (RFC 6598)
    ip_network("::1/128"),              # Loopback IPv6
    ip_network("fc00::/7"),             # Unique local IPv6
    ip_network("fe80::/10"),            # Link-local IPv6
]


def _is_safe_url(url: str) -> tuple[bool, str]:
    """
    Valide une URL contre les règles anti-SSRF.
    Retourne (is_safe: bool, reason: str).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL malformée"

    # 1. Vérification du schéma
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Schéma '{parsed.scheme}' non autorisé (seuls http/https sont acceptés)"

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "Hostname manquant dans l'URL"

    # 2. Blocage des hostnames internes connus
    if hostname in BLOCKED_HOSTNAMES:
        return False, "Accès aux services internes interdit"

    # 3. Résolution DNS et vérification de l'IP résolue
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False, "Impossible de résoudre le nom de domaine"

    try:
        addr = ip_address(resolved_ip)
    except ValueError:
        return False, "Adresse IP résolue invalide"

    # Blocage si l'IP appartient à un réseau privé / loopback / link-local
    for network in BLOCKED_NETWORKS:
        if addr in network:
            return False, "Accès aux adresses IP internes/privées interdit"

    return True, "OK"


@app.get("/fetch")
def fetch():
    """
    [BLUE TEAM — mike] Route /fetch sécurisée contre le SSRF.
    Effectue une requête HTTP vers une URL externe validée.
    """
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify({
            "error": "Paramètre 'url' manquant",
            "usage": "/fetch?url=https://example.com"
        }), 400

    # Validation anti-SSRF
    is_safe, reason = _is_safe_url(url)
    if not is_safe:
        # Log côté serveur (sans exposer les détails à l'attaquant)
        app.logger.warning("[SSRF-BLOCKED] url=%s | raison=%s | ip=%s",
                           url, reason, request.remote_addr)
        return jsonify({
            "error": "URL refusée par la politique de sécurité",
            "code": "SSRF_BLOCKED"
            # Pas de 'reason' exposée — évite l'aide à l'énumération
        }), 403

    try:
        r = requests.get(
            url,
            timeout=3,
            allow_redirects=False,   # Bloque les redirections vers des IP internes
            headers={"User-Agent": "EscapeApp/1.0"}
        )
        # Si redirection, on la signale sans la suivre
        if r.is_redirect:
            return jsonify({
                "error": "Redirection bloquée par politique de sécurité",
                "code": "REDIRECT_BLOCKED"
            }), 403

        return (
            r.text,
            r.status_code,
            {"Content-Type": r.headers.get("Content-Type", "text/plain")},
        )

    except requests.exceptions.Timeout:
        return jsonify({"error": "La requête a expiré (timeout)"}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Impossible de se connecter à la ressource distante"}), 502
    except RequestException as e:
        app.logger.error("[FETCH-ERROR] url=%s | err=%s", url, str(e))
        return jsonify({"error": "Erreur lors de la requête distante"}), 502


# Admin protected by static token (still bad)
@app.get("/admin")
def admin():
    token = request.args.get("token", "")
    if token != os.getenv("ADMIN_TOKEN", ""):
        abort(403)
    return jsonify({
        "admin": True,
        "flag_supply_chain": os.getenv("FLAG_SUPPLY", "FLAG{missing}"),
        "hint": "Try auditing the pipeline scripts & dependencies. Also check internal services.",
    })

@app.get("/docs")
def docs():
    return render_template_string("""
<h2>DevSecOps targets (expert)</h2>
<ol>
  <li>Supply chain: tests + SAST + dependency audit + image scan + SBOM + signing</li>
  <li>Secrets hygiene: no .env committed, no tokens in repo, add secret scanning</li>
  <li>AppSec: SSRF mitigation, auth hardening, safer cookies, logging</li>
  <li>Build hardening: pin base image, non-root user, .dockerignore, minimal image</li>
</ol>
<p>Tip: there is an internal service on the Docker network you should not be able to read from the web app.</p>
""")

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug)
