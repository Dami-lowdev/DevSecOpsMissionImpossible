# 🛡️ Blue Team — Mission : Protection du Pipeline et Auth Interne (Branche `damien`)

> **Responsable :** Damien LANING
> **Objectifs :** Mettre en œuvre une CI/CD fortifiée avec des Quality Gates (Mission B2) et boucher la faille d'authentification béante d'accès au `vault` (Mission M3 / M5).

---

## 1. Vulnérabilités corrigées

Durant les assauts Red Team, plusieurs voies d'accès au réseau et au code de l'application ont été utilisées :
- **Token visible et temporisateur faible** : Le token interne du Vault circulait en `GET /secret?token=...`, facilement interceptable par n'importe quel proxy. En outre, un piratage temporel ("Timing Attack") était concevable à cause d'une comparaison booléenne.
- **Pipeline non audité (Supply Chain passoire)** : L'image finale poussée sur les dépôts ne faisait l'objet d'aucun scan de métriques (SBOM) ou de vérification, ouvrant grand la porte aux vulnérabilités d'injections logicielles de la chaîne de confiance (CWE-829, CWE-1357). Les images utilisaient l'affreux tag `:latest`.

---

## 2. Mesures Défensives Implémentées

### 2.1 Sécurisation de l'API Interne (Vault)

Le fichier `vault/app.py` a été corrigé au niveau du point de terminaison `/secret` :
- **Headers HTTP** : Comme pour l'application Web principale, l'authentification réclame désormais un Authorization Header plutôt qu'un paramètre URL, protégeant le précieux `VAULT_TOKEN` des journaux malveillants.
- **Vérifications temporelles uniformes** : `hmac.compare_digest(...)` a été injecté dans le service afin de lutter contre les fuites par canal temporel.

### 2.2 Implémentation des Quality Gates en Intégration Continue (B2)

L'implémentation de contrôles automatiques (Automated Quality Gates) dans le fichier `scripts/pipeline.sh` garantit un durcissement drastique du processus avec arrêt du build sur erreur (set -e) :

- **SAST (Static Application Security Testing)**: Ajout de l'outil Python `bandit` pour l'analyse statique.
- **Vérifications de Dépendances tierces**: Ajout de `pip-audit` pour valider que les `requirements.txt` ne contiennent pas de CWE/CVE listé publiquement.
- **Pinning de tag d'image dynamique** : Élimination du tag `:latest` au profit du commit haché (`git rev-parse --short HEAD`).
- **Vuln Scanning Conteneur** : Intégration de Trivy vérifiant au moment du build qu'aucune CVE `HIGH` ou `CRITICAL` ne s'y glisse.

---

## 3. Preuve de la correction

**A. Tentative d'accès à l'API secrète par URL :**
```bash
$ curl "http://localhost:5001/fetch?url=http://vault:7000/secret?token=<volé>"
# Résultat : 403 Forbidden (Attaque bloquée)
```

**B. Exécution de la CI mockée :**
```bash
$ ./scripts/pipeline.sh
[CI] Démarrage du pipeline fortifié DevSecOps...
[CI] 1) Pipeline Lint
...
[CI] 3) SAST & Dependency audit
...
[CI] 4) Construction d'image Docker avec hachage
...
[CI] Déploiement Sécurisé Terminé.
```
