# 🛡️ Blue Team — Mission : Durcissement Docker & Sécurisation Interne (Branche `andrisca`)

> **Responsable :** Andrisca MABIKA
> **Objectifs :** Sécuriser la construction du conteneur (Mission B4) et fermer la vulnérabilité d'exfiltration de secrets via `/debug` trouvée durant l'audit Red Team.

---

## 1. Vulnérabilités corrigées

Lors de l'audit Red Team (Mission M1/M2), la vulnérabilité critique suivante a été exploitée :
- Un appel SSRF vers `vault:7000/debug` a permis de récupérer `VAULT_TOKEN` et d'autres variables d'environnement en clair (CWE-200).
- Le `Dockerfile` d'origine souffrait de mauvaises pratiques menant potentiellement à un piratage de la "Supply Chain" :
  - **Build Context Leakage** : Tout était copié dans le conteneur (`.env`, `.git`) en l'absence de fichier `.dockerignore`.
  - **Exécution en mode `root`** : Aucun utilisateur dédié.
  - **Absence de surveillance** : Pas de `HEALTHCHECK` pour isoler ou tuer un conteneur corrompu/défaillant.

---

## 2. Mesures Défensives Implémentées

### 2.1 Suppression du Endpoint de diagnostic (AppSec)
Le fonctionnement normal de l'application n'exige en aucun cas de lister les variables système. 
- La route `@app.get("/debug")` de `vault/app.py` a été entièrement supprimée. 
- *Impact :* Une requête SSRF de type "Reconnaissance" vers le vault échouera silencieusement sans révéler aucune clé d'accès interne.

### 2.2 Durcissement du Conteneur (Mission B4 : Docker Hardening)

L'image est désormais restreinte selon les principes de moindre privilège :

- **Ajout d'un fichier `.dockerignore` :** Celui-ci empêche le code source de l'outil (comme `scripts/`) ou les secrets (`.env`, historique `.git`) de se retrouver figés dans les calques (layers) de l'image.
- **Principe de moindre privilège :** Une directive `RUN useradd -r -ms /bin/false appuser && chown -R appuser:appuser /app` suivie de `USER appuser` permet à l'application de ne plus s'exécuter en tant que `root`. Si un pirate obtient l'exécution de code à distance (RCE), il ne pourra plus installer de paquets, modifier des fichiers système, ni facilement compromettre l'hôte (CWE-269).
- **Implémentation d'un `HEALTHCHECK` :** Un healthcheck natif à Docker a été configuré permettant à l'orchestrateur de s'assurer de la bonne vivacité de nos processus.

---

## 3. Preuve de la correction

**A. Tentative d'accès à l'API de débogage :**
```bash
$ curl "http://localhost:5001/fetch?url=http://vault:7000/debug"
# Résultat : 404 Not Found (Ressource supprimée)
```

**B. Vérification de l'utilisateur :**
```bash
$ docker exec -it <container_id> whoami
appuser
# (Au lieu de 'root' précédemment)
```

**C. Vérification des fichiers secrets dans le build :**
```bash
$ docker exec -it <container_id> cat /app/.env
cat: /app/.env: No such file or directory
# Le .dockerignore fonctionne parfaitement
```
