# 🛡️ Blue Team — Mission : Auth /admin & Secrets Hygiene (Branche `yohann`)

> **Responsable :** Yohann EKAMBIE SOUAMY
> **Objectifs :** Corriger le mécanisme d'authentification de l'endpoint `/admin` et mettre en place une véritable hygiène des secrets (mission B3) pour combler les failles découvertes lors de l'audit Red Team.

---

## 1. Vulnérabilités corrigées

Lors de l'audit offensif, la route `/admin` a été compromise (flag `FLAG{supply_chain_guardian}` récupéré). Les failles étaient les suivantes :
1. **Fuite de secrets :** Le fichier `.env` contenant `ADMIN_TOKEN` était commité dans le dépôt Git (CWE-522, CWE-798).
2. **Authentification faible :** L'endpoint `/admin` vérifiait le token via le paramètre GET (visible en clair) avec une comparaison vulnérable aux attaques temporelles.
3. **Absence de scan :** Aucun outil n'empêchait l'ajout de nouveaux secrets dans le code.

---

## 2. Mesures Défensives Implémentées

### 2.1 Hygiène des Secrets (Mission B3)

- **Suppression du fichier compromis :** Le fichier `.env` a été supprimé du dépôt Git.
- **Création d'un modèle :** Un fichier `.env.example` anonymisé a été mis en place pour guider les développeurs sans exposer de vrais secrets.
- **Ignoration stricte :** Le fichier `.gitignore` s'assure que `.env` ne sera plus jamais commité.
- **Mise en place de Secret Scanning :** Ajout de la configuration `gitleaks` (via hooks pre-commit ou CI) pour empêcher la fuite de futurs secrets.

### 2.2 Durcissement de l'Authentification /admin

Le code de `web/app.py` a été corrigé pour l'endpoint `/admin` :

1. **Passage aux Headers HTTP :** Le token n'est plus passé dans l'URL (`?token=...`), mais dans l'en-tête `Authorization: Bearer <token>`, protégeant l'identifiant des logs (serveur, proxy, historique navigateur).
2. **Comparaison Time-Safe :** Utilisation de `hmac.compare_digest()` pour empêcher les attaques par canal auxiliaire (timing attacks) au lieu de l'opérateur `!=`.

---

## 3. Preuve de la correction

**Tentative d'accès vulgaire (ancienne méthode) :**
```bash
$ curl "http://localhost:5001/admin?token=bSXdxNlOVFk8tEPgmqRWNwOibH6wxJVx"
# → 403 FORBIDDEN (Le Paramètre GET est ignoré, le Headers est requis)
```

**Tentative légitime avec token :**
```bash
$ curl -H "Authorization: Bearer <NEW_TOKEN>" http://localhost:5001/admin
# → 200 OK
```

---

## 4. Documentation : Rotation des Secrets

Suite à la compromission initiale, une procédure de rotation a été actée :
1. **Révocation immédiate :** Tous les tokens présents dans l'ancien `.env` (JWT_SECRET, VAULT_TOKEN, ADMIN_TOKEN) sont considérés compromis et doivent être purgés des environnements de production.
2. **Renouvellement via Vault/SSM :** Les nouveaux tokens seront générés par l'orchestrateur ou le gestionnaire de secrets sécurisé, jamais poussés à la main.
3. **Rotation Périodique :** Le `ADMIN_TOKEN` sera automatiquement expiré tous les 30 jours via une politique d'expiration.
