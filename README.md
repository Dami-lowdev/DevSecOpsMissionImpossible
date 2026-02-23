
# DevSecOps Escape Game ## “Supply Chain Guardian”

Objectif : aller **au-delà** des failles évidentes et travailler **DevSecOps** : supply chain, scans, politique, preuve, remediation.

---

## Prérequis

- Docker Desktop
- Git + VS Code
- (optionnel) Trivy, pip-audit, gitleaks (ou équivalents)

---

## Démarrage

```bash
docker compose up --build
```

Ouvrir :

- <http://localhost:5001>

---

## Gameplay (2 phases)

### Phase Red (attaque / preuve)

Vous devez trouver **au moins 2 flags** et démontrer **2 risques supply chain**.

### Phase Blue (défense / durcissement)

Vous devez rendre :

- une app corrigée (SSRF + cookies + auth)
- un build durci (Dockerfile + .dockerignore + non-root)
- une CI améliorée (tests + scans + quality gates)
- une stratégie secrets (gitleaks + .env.example + rotation)

---

## Missions Red Team (expert)

### M1 — SSRF vers service interne (30 pts) Trouver un moyen de lire un contenu d’un service **non exposé** au host

Indice : un service interne existe sur le réseau Docker, et l’app fait des requêtes serveur.

**Flag attendu :** `FLAG{ssrf_reached_vault}`

---

### M2 — Weak admin auth (15 pts)

Accéder à `/admin` et récupérer `FLAG{supply_chain_guardian}`.

Piste : d’où vient le token ? (secrets, env, fichiers, logs, build context)

---

### M3 — Supply chain risks (25 pts)

Identifier **5 risques** dans la CI / pipeline :

- tags `latest`
- pas de tests
- pas de SAST
- pas d’audit dépendances
- pas de scan d’image
- pas de SBOM
- pas de signature
- pas de policy gate
- pas de provenance

Livrer une liste structurée risque → impact → mitigation.

---

### M4 — Build context leakage (15 pts)Prouver qu’un fichier “qui ne devrait pas” se retrouve dans l’image

Piste : `.dockerignore`

---

## Missions Blue Team

### B1 — Mitiger SSRF proprement (35 pts)

Mettre en place :

- allowlist de domaines OU
- blocage des IP privées/loopback + vérif DNS (anti rebinding) + redirections contrôlées

But : interdire l’accès à `vault` depuis `/fetch`.

---

### B2 — Pipeline avec Quality Gates (35 pts)

Ajouter (au choix) :

- tests (même simples)
- `pip-audit` (ou équivalent)
- `bandit` (SAST python) (ou équivalent)
- scan image `trivy` (ou équivalent)
- SBOM (syft) (ou équivalent)
- signature (cosign) (ou équivalent)

Condition : si un scan échoue → le pipeline échoue.

---

### B3 — Secrets hygiene (20 pts)

- supprimer `.env` du repo (remplacer par `.env.example`)
- supprimer tout fichier “secrets”
- ajouter secret scanning (gitleaks ou pre-commit)
- documenter la rotation

---

### B4 — Docker hardening (20 pts)

- base image pin
- `USER` non-root
- `HEALTHCHECK`
- `.dockerignore`
- réduire la surface (option multi-stage)

---

## Présentation finale (6 minutes / équipe)

1. Les 2 flags trouvés + preuve
2. Les 5 risques supply chain + impact
3. Les correctifs majeurs (SSRF + CI + secrets)
4. La checklist DevSecOps (10 règles d’or)

---

## Important

Les attaques doivent rester inoffensives.

---

---

## 🛡️ Blue Team — Correction SSRF (Branche `mike`)

> **Auteur :** Mike · **Branche :** `mike` · **Commit :** `da569e8`
> **Objectif :** Corriger la vulnérabilité SSRF de la route `/fetch` sans casser les fonctionnalités légitimes.

---

### 🔴 Vulnérabilité initiale (état rouge)

```python
# web/app.py — version vulnérable
@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    resp = requests.get(url, timeout=5)   # ← aucune validation !
    return resp.text
```

**Attaque possible :**
```bash
curl "http://localhost:5001/fetch?url=http://vault:7000/debug"
# → retournait tous les secrets du vault (os.environ complet)
```

---

### ✅ Correction appliquée — Défense en profondeur (5 couches)

| Couche | Contrôle | Rôle |
|--------|----------|------|
| **1** | Schéma HTTP/HTTPS uniquement | Bloque `file://`, `ftp://`, `gopher://`, etc. |
| **2** | Blocage des hostnames internes | Bloque `localhost`, `vault`, `internal`, `*.local` |
| **3** | Résolution DNS + blocage IP privées | Bloque `127.x`, `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x` |
| **4** | Timeout strict (3s) + désactivation des redirections | Empêche le contournement par redirection |
| **5** | Gestion d'erreur générique | Ne révèle aucune information interne en cas d'échec |

---

### 🧪 Comment tester la correction

**Lancer l'application :**
```bash
docker-compose up --build -d
```

---

#### 🔴 Test 1 — Attaque SSRF sur vault (doit être BLOQUÉ)
```powershell
curl "http://localhost:5001/fetch?url=http://vault:7000/debug"
```
**Résultat attendu :**
```json
{"code": "SSRF_BLOCKED", "error": "URL refusée par la politique de sécurité"}
```

---

#### 🔴 Test 2 — Attaque via localhost (doit être BLOQUÉ)
```powershell
curl "http://localhost:5001/fetch?url=http://localhost/admin"
```
**Résultat attendu :**
```json
{"code": "SSRF_BLOCKED", "error": "URL refusée par la politique de sécurité"}
```

---

#### 🔴 Test 3 — Schéma interdit (doit être BLOQUÉ)
```powershell
curl "http://localhost:5001/fetch?url=file:///etc/passwd"
```
**Résultat attendu :**
```json
{"code": "SSRF_BLOCKED", "error": "URL refusée par la politique de sécurité"}
```

---

#### 🟢 Test 4 — URL externe légitime (doit fonctionner)
```powershell
curl "http://localhost:5001/fetch?url=https://example.com"
```
**Résultat attendu :** contenu HTML de example.com (la route fonctionne normalement)

---

### ⚙️ Tests automatisés (pytest)

```bash
pip install pytest
pytest tests/test_ssrf_mitigation.py -v
```

**13 tests couvrant :**
- Blocage vault, localhost, 127.0.0.1, IPs privées RFC1918
- Blocage des schémas interdits (file://, ftp://)
- Validation du rejet des redirections internes
- Vérification que les URLs externes restent autorisées

---

### 💡 Justification des choix techniques

- **Pas d'allowlist fixe** → trop restrictif pour un service générique de fetch
- **Résolution DNS côté serveur** → la validation se fait APRÈS résolution (anti DNS rebinding)
- **Timeout 3s** → évite les attaques de type Slowloris ou les scans de ports internes
- **Erreur générique** → on ne révèle pas si c'est un blocage IP, DNS ou hostname

---

### 🚧 Limitations connues et documentées

- **DNS rebinding avancé** : un serveur DNS malveillant peut répondre différemment entre validation et requête réelle (fenêtre de ~ms)
- **SSRF via services cloud** : l'endpoint AWS `169.254.169.254` est bloqué, mais d'autres metadata endpoints (GCP, Azure) nécessiteraient des règles supplémentaires
- **Pas d'allowlist de domaines** : si le besoin métier est connu, une allowlist serait plus sûre qu'une blocklist

