# DevSecOps Mission — CI/CD Pipeline & Vault Protection
**Auteur :** Damien LANING · **Branche :** `damien`

---

## 1. Ma mission

Dans ce projet DevSecOps Escape Game ("Supply Chain Guardian"), ma responsabilité couvrait **deux missions Blue Team** :

### Mission B2 — Pipeline avec Quality Gates
Transformer un pipeline CI/CD intentionnellement défaillant en une chaîne de build sécurisée qui stoppe automatiquement en cas de détection de vulnérabilité.

**Problème initial (`scripts/pipeline.sh` + `.github/workflows/ci.yml`) :**
- Aucun test unitaire
- Aucun SAST (analyse statique du code)
- Aucun audit des dépendances Python
- Aucun scan de l'image Docker
- Image taggée `:latest` (non traçable, non immutable)
- Aucune signature d'artefact

### Mission M3/M5 — Sécurisation de l'Auth Vault (machine-to-machine)
Corriger la faille d'authentification de l'API interne Vault exposée par la Red Team.

**Problème initial (`vault/app.py`) :**
- Le token passait en paramètre URL : `GET /secret?token=<valeur>`
- Le token était donc visible dans les logs de proxy, l'historique navigateur, les access logs
- La comparaison du token utilisait `==` (vulnérable aux timing attacks)

---

## 2. Comment j'ai résolu chaque problème

### 2.1 Pipeline Quality Gates (`scripts/pipeline.sh`)

Le script `scripts/pipeline.sh` a été revu pour intégrer 6 étapes de contrôle :

```sh
#!/bin/sh
set -eu   # arrêt immédiat sur erreur (set -e) + variables non définies (set -u)
```

| Étape | Outil | Rôle |
|---|---|---|
| 1 | `shellcheck` | Lint du script shell lui-même |
| 2 | `pytest` (mock) | Exécution des tests unitaires |
| 3a | `bandit` | SAST Python — détecte les mauvaises pratiques sécurité dans le code |
| 3b | `pip-audit` | Audit des dépendances — vérifie les CVE connues dans `requirements.txt` |
| 4 | `docker build` | Build taggé avec le hash git (`git rev-parse --short HEAD`) |
| 5 | `trivy` | Scan de l'image Docker pour CVE HIGH/CRITICAL |
| 6 | `cosign` (placeholder) | Signature cryptographique de l'artefact |

**Avant (`.github/workflows/ci.yml` — pipeline vulnérable) :**
```yaml
- name: Build image
  run: docker build -t mycorp/escape-app:latest .
# Aucun scan, aucun test, tag :latest non traçable
```

**Après (`scripts/pipeline.sh` — pipeline fortifié) :**
```sh
bandit -r web/ vault/
pip-audit -r web/requirements.txt
docker build -t mycorp/escape-app:$(git rev-parse --short HEAD) .
trivy image --severity HIGH,CRITICAL mycorp/escape-app:$(git rev-parse --short HEAD)
```

### 2.2 Sécurisation de l'auth Vault (`vault/app.py`)

**Avant (vulnérable) :**
```python
@app.get("/secret")
def secret():
    token = request.args.get("token", "")   # token dans l'URL
    if token != os.getenv("VAULT_TOKEN"):   # comparaison timing-unsafe
        abort(403)
```

**Après (corrigé) :**
```python
import hmac

@app.get("/secret")
def secret():
    auth_header = request.headers.get("Authorization", "")
    tok = auth_header.replace("Bearer ", "")               # token dans le header
    if not hmac.compare_digest(tok, os.getenv("VAULT_TOKEN", "MISSING_VAULT_TOKEN")):
        abort(403)                                         # timing-safe
```

Deux corrections appliquées :
- **Header HTTP** : le token transite dans `Authorization: Bearer <token>` et non plus dans l'URL
- **`hmac.compare_digest`** : comparaison en temps constant, résistante aux timing attacks

---

## 3. Comment tester ce que j'ai implémenté

> **Prérequis :** les conteneurs Docker doivent être démarrés.
> ```bash
> docker compose up -d --build
> ```

---

### Test 1 — Vérifier que le pipeline tourne correctement

```bash
./scripts/pipeline.sh
```

**Résultat attendu :**
```
[CI] Démarrage du pipeline fortifié DevSecOps...
[CI] 1) Pipeline Lint
[CI] 2) Tests Unitaires
[CI] 3) SAST & Dependency audit
  → bandit analyse web/ et vault/
[CI] 4) Construction d'image Docker avec hachage
  → image taggée mycorp/escape-app:<git-hash>
[CI] 5) Image scan avec Trivy
[CI] 6) Signature d'image logicielle (Cosign)
[CI] Déploiement Sécurisé Terminé.
```

---

### Test 2 — Vérifier que l'image est taggée avec le hash git (pas `:latest`)

```bash
docker images | grep mycorp
```

**Résultat attendu :**
```
mycorp/escape-app   5839908   <image-id>   ...
```
Le tag est le hash court du commit (`git rev-parse --short HEAD`), pas `:latest`.

---

### Test 3 — Vérifier que bandit détecte des problèmes (SAST fonctionne)

```bash
bandit -r web/ vault/
```

**Résultat attendu :** bandit signale au minimum 2 issues Medium (binding sur `0.0.0.0`). Cela confirme que l'outil tourne bien et remonte des alertes.

---

### Test 4 — L'ancienne attaque (token en URL) est maintenant bloquée

Avant ma correction, un attaquant pouvait passer le token en paramètre URL via la faille SSRF :

```bash
curl "http://localhost:5001/fetch?url=http://vault:7000/secret?token=7Db33sFjTDvB8ILDMJeOYwdy"
```

**Résultat attendu : `403 Forbidden`**

Le vault n'accepte plus les tokens en query string. La requête est rejetée même avec le bon token dans l'URL.

---

### Test 5 — Sans token, l'accès au vault est refusé

```bash
docker exec devsecopsmissionimpossible-web-1 \
  python -c "
import urllib.request
try:
    urllib.request.urlopen('http://vault:7000/secret').read()
except Exception as e:
    print('Bloqué :', e)
"
```

**Résultat attendu :**
```
Bloqué : HTTP Error 403: FORBIDDEN
```

---

### Test 6 — Avec le bon Bearer token, l'accès est accordé

```bash
docker exec devsecopsmissionimpossible-web-1 \
  python -c "
import urllib.request
req = urllib.request.Request(
    'http://vault:7000/secret',
    headers={'Authorization': 'Bearer 7Db33sFjTDvB8ILDMJeOYwdy'}
)
print(urllib.request.urlopen(req).read().decode())
"
```

**Résultat attendu :**
```json
{"vault": "ok", "flag_vault": "FLAG{ssrf_reached_vault}"}
```

---

### Test 7 — Vérifier que `hmac.compare_digest` est bien utilisé

```bash
grep "hmac.compare_digest" vault/app.py
```

**Résultat attendu :**
```python
if not hmac.compare_digest(tok, os.getenv("VAULT_TOKEN", "MISSING_VAULT_TOKEN")):
```

---

### Test 8 — Confirmer que le vault n'est pas accessible depuis l'hôte

```bash
curl http://localhost:7000/health
```

**Résultat attendu : `Connection refused`**

Le service vault n'expose aucun port sur l'hôte (pas de `ports:` dans le `docker-compose.yml` pour le service vault). Il n'est joignable que depuis le réseau interne Docker.

---

## 4. Récapitulatif des résultats obtenus

| Test | Ce qui est vérifié | Résultat |
|---|---|---|
| T1 | Pipeline s'exécute sans erreur fatale | Terminé avec succès |
| T2 | Image taggée avec hash git, pas `:latest` | `mycorp/escape-app:5839908` |
| T3 | `bandit` SAST détecte des issues | 2 Medium trouvées |
| T4 | Ancienne attaque (token URL) bloquée | `403 Forbidden` |
| T5 | Accès vault sans token refusé | `403 Forbidden` |
| T6 | Accès vault avec Bearer token accordé | `FLAG{ssrf_reached_vault}` |
| T7 | `hmac.compare_digest` présent dans le code | Confirmé |
| T8 | Vault non exposé sur l'hôte | `Connection refused` |

---

## 5. Ce qui n'est pas dans ma mission

| Mission | Responsabilité |
|---|---|
| B1 — Mitigation SSRF (blocage IP privées, allowlist) | Autre membre de l'équipe |
| B3 — Secrets hygiene (gitleaks, `.env.example`, rotation) | Autre membre de l'équipe |
| B4 — Docker hardening (non-root, HEALTHCHECK, `.dockerignore`) | Autre membre de l'équipe |
