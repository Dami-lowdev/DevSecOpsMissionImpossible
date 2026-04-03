
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

## 🛡️ Blue Team — CI/CD Pipeline & Protection Vault (Branche `damien`)

> **Auteur :** Damien · **Branche :** `damien`
> **Objectif :** Implémenter de robustes barrières DevSecOps (Quality gates) dans la CI (Pipeline) et sécuriser la connexion interne secrète du Vault.

---

### 🎯 Mission : Sécuriser la Supply Chain (B2) & l'Authentification

L'audit ayant permis l'extraction pure d'un flag grâce aux failles conjuguées de la mauvaise gestion de pipeline (script désactivé) et du transit en clair d'un identifiant secret, il était primordial de sécuriser de l'acheminement code-to-production jusqu'à la logique d'authentification machine-à-machine.

---

### ✅ Correctifs Appliqués

1. **Intégration DevSecOps / Supply Chain dans la CI :**
   - Le script CI factice `scripts/pipeline.sh` a été revu pour faire office de forteresse. 
   - **SAST** : Utilisation programmative de l'analyseur `bandit`.  
   - **Audit applicatif** : Interfaçage avec `pip-audit` contre les dépendances toxiques Python.
   - **Scanning d'Image Trivy** : Ajout d'une condition d'échec de la pipeline en cas de détection à Sévérité `HIGH` ou `CRITICAL`.
   - **Immutabilité** : L'anonyme flag `:latest` est remplacé en continu par un tag de construction hashé sur `git rev-parse`.

2. **Fortification Auth de `/secret` (Machine to Machine) :**
   - À l'image de la route externe `/admin`, l'accès vers `/secret` au sein du module **Vault** exige désormais la transmission du marqueur par Header cryptographique (`Authorization: Bearer`), éliminant l'exfiltration via journalisation de proxy par URL.
   - Le timing de lecture du sceau secret est désormais géré par `hmac.compare_digest`.

---

### 🧪 Preuve de validation

**Test 1 — Défense API :**
```bash
curl "http://localhost:5001/fetch?url=http://vault:7000/secret?token=7Db33s...<volé>"
# → 403 Forbidden
```

**Test 2 — Déploiement Pipeline automatisée :**
```bash
$ ./scripts/pipeline.sh
# La pipeline exécute et valide les scans Bandit / Pip-Audit / Trivy et génère le hachage propre.
```

Le code complet et documenté est disponible dans `docs/damien/RAPPORT.md` sur la branche `damien`.
