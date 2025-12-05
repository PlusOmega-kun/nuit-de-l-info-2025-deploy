# CVE Intelligence Browser

## Présentation

Ce projet est une plateforme web permettant de rechercher, visualiser et analyser des vulnérabilités informatiques (CVE) à partir de plusieurs sources de données. Il propose une interface moderne pour explorer les failles, obtenir des statistiques, et importer ses propres listes de vulnérabilités.

## Fonctionnalités principales
- **Recherche de CVE** : Recherchez des vulnérabilités par identifiant, mot-clé ou période.
- **Visualisation détaillée** : Accédez à la fiche complète d'une CVE (score, description, impact, liens externes).
- **Statistiques** : Visualisez des graphiques sur la répartition des failles, leur sévérité, etc.
- **Import de fichiers** : Importez vos propres listes de CVE au format CSV/Excel pour analyse.
- **Connexion à une base MongoDB** : Les données sont stockées et requêtées via MongoDB.

## Structure du projet
- `public/` : Interface web (frontend) - contient `index.html`, `style.css` et `app.js`.
- `app.js` : Serveur Node.js (Express) qui expose l'API REST pour interroger les CVE, les statistiques, gérer les imports, et sert les fichiers statiques.
- `import.js` : Script d'import massif de données CVE dans MongoDB à partir de fichiers JSON.
- `mitre-cve-database/` : Scripts et données brutes (hors `cve-data/mitre`).
- `test/` : Fichiers de test et d'exemple.

## Prérequis
- **Node.js** (v18+ recommandé)
- **MongoDB** (local ou distant) - optionnel, le serveur peut démarrer sans MongoDB

## Installation
1. Clonez le dépôt et installez les dépendances :
	```bash
	npm install
	```
2. Configurez l'accès à MongoDB dans les scripts si besoin (URI par défaut : `mongodb://localhost:27017`).

## Installation des dépendances
Pour installer les dépendances nécessaires et récupérer les données CVE, exécutez le script suivant :

```bash
./mitre-cve-database/fetch-cve-data.sh
```

## Lancement du serveur
À la racine du projet :
```bash
node app.js
```
Le serveur sera accessible sur [http://localhost:3000](http://localhost:3000).

## Utilisation de l'interface web
Accédez à [http://localhost:3000](http://localhost:3000) dans votre navigateur. L'interface communique avec le serveur Node.js pour afficher les résultats.

## Import de données CVE (optionnel)
Pour importer des données brutes dans MongoDB, à la racine du projet :
```bash
node import.js
```
Le script utilise maintenant un chemin relatif vers `mitre-cve-database/cve-data/mitre/cves`.

## À quoi sert ce projet ?
Ce projet vise à faciliter la veille de sécurité, l'analyse de vulnérabilités et la gestion de risques pour les professionnels de la cybersécurité, les RSSI, ou toute personne souhaitant explorer la base CVE de façon moderne et interactive.

## Remarques
- Le dossier `mitre-cve-database/cve-data/mitre` contient les données brutes volumineuses et n'est pas nécessaire pour l'utilisation standard.
- Le projet est open-source et peut être adapté à vos besoins.

---

*Développé pour la Nuit de l'Info 2025*
