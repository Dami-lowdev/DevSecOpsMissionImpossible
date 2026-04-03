
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

## 🛡️ Blue Team — Hygiène des Secrets & Auth (Branche `yohann`)

> **Auteur :** Yohann · **Branche :** `yohann`
> **Objectif :** Corriger le stockage des secrets et le mécanisme d'authentification vulnérable de l'endpoint `/admin`.

---

### 🎯 Mission : Sécuriser les secrets & l'authentification (B3)

Suite à l'audit red team qui a récupéré le `ADMIN_TOKEN` via le fichier `.env` commité dans Git et un paramètre GET faible, des mesures de l'approche DevSecOps pour l'hygiène des secrets ont été implémentées.

---

### ✅ Correctifs Appliqués

1. **Suppression du `.env` du repo Git :**
   - Le fichier contenant les vrais tokens secrets de production a été supprimé des commits et ignoré (`.gitignore`) pour éviter toute fuite.

2. **Création d'un modèle d'environnement anonymisé :**
   - Un fichier `.env.example` placeholder a été ajouté pour guider l'onboarding de l'équipe sans exposer la donnée.

3. **Renforcement de l'authentification (`/admin`) :**
   - L'endpoint ne lit plus le token dans l'URL `?token=...`.
   - Il lit sécuritairement dans l'entête HTTP `Authorization: Bearer <token>`, protégeant contre l'expiration de logs proxy ou historique du navigateur.
   - La comparaison du mot de passe s'effectue désormaus via la méthode stricte `hmac.compare_digest()` afin de mitiger les Timing Attacks (Side-channel).

---

### 🧪 Preuve de validation

**Test 1 — Défense de l'ancienne attaque (GET parameter ignoré) :**
```bash
curl "http://localhost:5001/admin?token=VRAI_TOKEN_VOLE"
# → Résultat: 403 Forbidden
```

**Test 2 — Auth Sécurisée (Header) :**
```bash
curl -H "Authorization: Bearer <mon_nouveau_vrai_token>" "http://localhost:5001/admin"
# → Résultat: 200 OK avec payload
```

Le code complet et documenté est disponible dans `docs/yohann/RAPPORT.md` sur la branche `yohann`.
