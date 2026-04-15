Rapport de Validation de Sécurité – Branche yohann (Mission B3)
Salut Yohann,

Pour valider le travail que tu as effectué sur la branche yohann concernant l'hygiène des secrets et le durcissement de l'authentification, nous avons réalisé une série de tests. L'objectif était de jouer le rôle d'un attaquant et d'un utilisateur légitime pour confirmer que tes correctifs sont efficaces.

Le bilan est très positif ! Voici le détail de ce que nous avons testé.

Contexte : Les correctifs que tu as implémentés
Hygiène des Secrets : Le fichier .env a été retiré de Git et remplacé par un modèle .env.example.
Durcissement de l'Authentification : L'endpoint /admin n'accepte plus le token dans l'URL (?token=...) et impose de le passer dans l'en-tête Authorization: Bearer <token>.
Test 1 : Validation du cas légitime (le "Happy Path")
Ce premier test visait à s'assurer que la nouvelle méthode d'authentification sécurisée fonctionne comme prévu.

Action : Nous avons simulé un administrateur se connectant correctement. Pour cela, nous avons utilisé le token 7wbp9100 présent dans notre fichier .env local et l'avons placé dans l'en-tête HTTP, comme l'exige ton correctif.

Commande exécutée :

bash
curl -H "Authorization: Bearer 7wbp9100" "http://localhost:5001/admin"
Résultat obtenu :

json
{"admin":true,"flag_supply_chain":"FLAG{supply_chain_guardian}","hint":"..."}
Conclusion : Succès total. Le serveur a reconnu le token et nous a donné accès à la page /admin, nous permettant de récupérer le flag. Cela prouve que ton correctif est fonctionnel et ne bloque pas les utilisateurs légitimes.

Test 2 : Tentative de contournement avec l'ancienne faille
Ce second test était le plus important : vérifier que l'ancienne vulnérabilité est bien comblée.

Action : Nous avons rejoué l'attaque initiale en passant ce même token valide (7wbp9100) directement dans l'URL.

Commande exécutée :

bash
curl "http://localhost:5001/admin?token=7wbp9100"
Résultat obtenu : Une erreur 403 Forbidden.

Conclusion : Succès critique. Le serveur a refusé l'accès, prouvant que le code n'inspecte plus l'URL pour trouver un token. Tu as bien fermé la porte à cette vulnérabilité, empêchant ainsi que des secrets ne fuitent dans les logs des serveurs ou les historiques de navigateurs.

Synthèse pour l'équipe
Les tests confirment que les objectifs de la mission B3 sont pleinement atteints :

Les secrets ne sont plus exposés dans le code source, grâce au nettoyage de Git et à l'utilisation du couple .env / .env.example.
L'authentification est désormais robuste et suit les standards de sécurité en utilisant les en-têtes HTTP.
Excellent travail sur cette mission ! La branche est solide et prête pour la suite.