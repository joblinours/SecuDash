# SecuDash Dashboard

## Présentation

SecuDash est un tableau de bord web moderne pour la veille cybersécurité et marchés financiers. Il agrège en temps réel :

- Les dernières actualités cyber (flux RSS)
- Les CVE critiques récentes
- Les victimes de ransomware en Europe/US (carte interactive)
- Les cours de marchés (indices, actions, cryptos)
- Des raccourcis personnalisés
- Une barre de recherche Google rapide

## À quoi sert ce projet ?

Ce projet vise à fournir une vue synthétique, ergonomique et personnalisable de l’actualité cyber et financière, pour les professionnels, passionnés ou étudiants en cybersécurité.

## Fonctionnement

- **Backend Python/Flask** : collecte les données (RSS, API, fichiers JSON), expose des endpoints REST.
- **Frontend HTML/JS/CSS** : interface responsive, carte Leaflet, graphiques Chart.js, recherche dynamique.
- **Données** :
  - Flux RSS configurables (`rss_feeds.json`)
  - Marchés surveillés (`markets.json`)
  - Raccourcis personnalisés (`shortcuts.json`)
- **Carte ransomware** : victimes récentes géolocalisées, détails par pays.
- **Actualités/CVE** : recherche, tri, modales détaillées.

## Installation & Lancement local

### Prérequis

- Python 3.8+
- `pip install flask feedparser requests yfinance`

### Démarrage rapide

```bash
git clone https://github.com/joblinours/SecuDash.git
python3 SecuDash/api/cve.py
python3 SecuDash/main/main.py
```

- Accédez à [http://localhost:5000](http://localhost:5000) dans votre navigateur.

### Structure des fichiers

- `rss_parser/main.py` : serveur Flask principal
- `api/` : scripts d’API annexes (ransomware, marchés)
- `rss_feeds.json` : flux RSS à surveiller
- `markets.json` : actifs financiers à suivre
- `shortcuts.json` : raccourcis personnalisés
- `static/` : images, favicon, etc.

## Personnalisation

- **Ajouter/retirer des flux RSS** : éditez `rss_feeds.json`
- **Modifier les marchés surveillés** : éditez `markets.json`
- **Changer les raccourcis** : éditez `shortcuts.json` (icônes FontAwesome supportées)
- **Adapter le style** : modifiez le HTML/CSS dans `main.py` (template inline)

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

Made with ❤️ by jobl1n0urs
