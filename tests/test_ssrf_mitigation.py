"""
Tests de validation SSRF — Mission 1 Blue Team
Auteur : mike | 2026-02-20

Usage (sans Docker) :
    pip install pytest requests
    # Lancer l'app localement d'abord : python web/app.py
    pytest tests/test_ssrf_mitigation.py -v

Usage (avec Docker actif) :
    pytest tests/test_ssrf_mitigation.py -v --base-url=http://localhost:5001
"""

import pytest
import requests

BASE = "http://localhost:5001"


# ─── Tests AVANT correction (état vulnérable — à commenter après fix) ────────
# Ces tests documentent le comportement VULNÉRABLE pour référence.
# class TestSSRF_Vulnerable:
#     def test_ssrf_vault_debug(self):
#         """AVANT : devrait retourner les secrets du vault — preuve SSRF"""
#         r = requests.get(f"{BASE}/fetch?url=http://vault:7000/debug")
#         assert r.status_code == 200
#         assert "VAULT_TOKEN" in r.text  # Secret exposé sans auth


# ─── Tests APRÈS correction (comportement attendu) ───────────────────────────

class TestSSRF_Mitigated:
    """
    Tests de régression pour la mitigation SSRF.
    Chaque test vérifie qu'une attaque connue est bien bloquée.
    """

    # ── Cas bloqués (doivent retourner 403) ──────────────────────────────────

    def test_block_vault_internal_hostname(self):
        """Bloque l'accès au service vault par son nom Docker (hostname interne)."""
        r = requests.get(f"{BASE}/fetch?url=http://vault:7000/debug")
        assert r.status_code == 403, "vault doit être bloqué par la liste noire de hostnames"
        body = r.json()
        assert "SSRF_BLOCKED" in body.get("code", ""), "Le code SSRF_BLOCKED doit être retourné"

    def test_block_localhost(self):
        """Bloque l'accès à localhost (loopback)."""
        r = requests.get(f"{BASE}/fetch?url=http://localhost/admin")
        assert r.status_code == 403, "localhost doit être bloqué"

    def test_block_127_0_0_1(self):
        """Bloque l'accès à 127.0.0.1 même si l'IP est fournie directement."""
        r = requests.get(f"{BASE}/fetch?url=http://127.0.0.1:7000/debug")
        assert r.status_code == 403, "127.0.0.1 doit être bloqué (loopback)"

    def test_block_private_ip_10(self):
        """Bloque le sous-réseau privé 10.0.0.0/8 (RFC 1918)."""
        r = requests.get(f"{BASE}/fetch?url=http://10.0.0.1/secret")
        assert r.status_code == 403, "10.x.x.x doit être bloqué (réseau privé)"

    def test_block_private_ip_172(self):
        """Bloque le sous-réseau privé 172.16.0.0/12 (RFC 1918) — réseau Docker par défaut."""
        r = requests.get(f"{BASE}/fetch?url=http://172.17.0.1/")
        assert r.status_code == 403, "172.17.x.x doit être bloqué (réseau Docker)"

    def test_block_private_ip_192_168(self):
        """Bloque le sous-réseau privé 192.168.0.0/16 (RFC 1918)."""
        r = requests.get(f"{BASE}/fetch?url=http://192.168.1.1/")
        assert r.status_code == 403, "192.168.x.x doit être bloqué"

    def test_block_aws_metadata_ip(self):
        """Bloque l'IP de l'API metadata AWS (169.254.169.254)."""
        r = requests.get(f"{BASE}/fetch?url=http://169.254.169.254/latest/meta-data/")
        assert r.status_code == 403, "IP metadata AWS doit être bloquée (link-local)"

    def test_block_file_scheme(self):
        """Bloque le schéma file:// (lecture de fichiers locaux)."""
        r = requests.get(f"{BASE}/fetch?url=file:///etc/passwd")
        assert r.status_code == 403, "file:// doit être bloqué"

    def test_block_gopher_scheme(self):
        """Bloque le schéma gopher:// (vecteur SSRF avancé)."""
        r = requests.get(f"{BASE}/fetch?url=gopher://vault:7000/_")
        assert r.status_code == 403, "gopher:// doit être bloqué"

    def test_block_missing_url(self):
        """Retourne 400 si le paramètre url est absent."""
        r = requests.get(f"{BASE}/fetch")
        assert r.status_code == 400, "Paramètre url manquant → 400"

    def test_block_empty_url(self):
        """Retourne 400 si le paramètre url est vide."""
        r = requests.get(f"{BASE}/fetch?url=")
        assert r.status_code == 400, "URL vide → 400"

    # ── Cas autorisés (doivent fonctionner normalement) ──────────────────────

    def test_allow_external_http(self):
        """Autorise les requêtes vers des domaines externes légitimes."""
        try:
            r = requests.get(f"{BASE}/fetch?url=https://example.com", timeout=10)
            # Selon la connectivité réseau, peut retourner 200 ou être unreachable
            assert r.status_code in (200, 502, 504), \
                f"Une URL externe valide ne doit pas retourner 403 (got {r.status_code})"
        except requests.RequestException:
            pytest.skip("Pas d'accès réseau externe dans cet environnement")

    def test_error_response_is_json(self):
        """Vérifie que les erreurs sont toujours retournées en JSON structuré."""
        r = requests.get(f"{BASE}/fetch?url=http://vault:7000/debug")
        assert r.headers.get("Content-Type", "").startswith("application/json"), \
            "Les erreurs doivent être en JSON"
        body = r.json()
        assert "error" in body, "Le champ 'error' doit être présent"

    def test_no_stacktrace_in_error(self):
        """Vérifie qu'aucune stacktrace Python n'est exposée dans les erreurs."""
        r = requests.get(f"{BASE}/fetch?url=http://vault:7000/debug")
        body = r.text
        assert "Traceback" not in body, "Les stacktraces ne doivent pas être exposées"
        assert "File \"" not in body, "Les chemins de fichiers ne doivent pas être exposés"


# ─── Résumé des tests ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Lancer avec : pytest tests/test_ssrf_mitigation.py -v")
