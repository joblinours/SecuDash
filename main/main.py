import json
import time
import feedparser
import requests
from flask import Flask, jsonify, render_template_string, request
from threading import Thread
import datetime

# Ajout pour la carte
import math

# Remplacement investpy par tvdatafeed
# from tvDatafeed import TvDatafeed, Interval
import yfinance as yf  # Ajout pour remplacer tvDatafeed

app = Flask(__name__)
NEWS_LIMIT = 20
news_cache = []


def load_feeds():
    with open("../rss_feeds.json", encoding="utf-8") as f:
        return json.load(f)


def fetch_news():
    global news_cache
    feeds = load_feeds()
    all_news = []
    for feed in feeds:
        parsed = feedparser.parse(feed["url"])
        for entry in parsed.entries[:5]:
            all_news.append(
                {
                    "title": entry.title,
                    "link": entry.link,
                    "published": entry.get("published", ""),
                    "source": feed["title"],
                }
            )
    # Trie par date décroissante
    all_news.sort(key=lambda x: x["published"], reverse=True)
    news_cache = all_news[:NEWS_LIMIT]


def fetch_cves():
    try:
        resp = requests.get("http://localhost:5001/cves", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


def fetch_ransomware():
    """Récupère et filtre les victimes ransomware récentes Europe/US, groupées par pays."""
    url = "https://api.ransomware.live/v2/recentvictims"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code != 200:
            return {}
        data = resp.json()
    except Exception:
        return {}

    # Pays et noms
    COUNTRY_NAMES = {
        "FR": "France",
        "DE": "Allemagne",
        "IT": "Italie",
        "ES": "Espagne",
        "PT": "Portugal",
        "BE": "Belgique",
        "NL": "Pays-Bas",
        "LU": "Luxembourg",
        "CH": "Suisse",
        "AT": "Autriche",
        "PL": "Pologne",
        "CZ": "Tchéquie",
        "SK": "Slovaquie",
        "HU": "Hongrie",
        "SI": "Slovénie",
        "HR": "Croatie",
        "RS": "Serbie",
        "BA": "Bosnie-Herzégovine",
        "ME": "Monténégro",
        "MK": "Macédoine du Nord",
        "BG": "Bulgarie",
        "RO": "Roumanie",
        "MD": "Moldavie",
        "UA": "Ukraine",
        "BY": "Biélorussie",
        "LT": "Lituanie",
        "LV": "Lettonie",
        "EE": "Estonie",
        "AL": "Albanie",
        "GR": "Grèce",
        "SE": "Suède",
        "NO": "Norvège",
        "DK": "Danemark",
        "FI": "Finlande",
        "US": "États-Unis",
    }
    EUROPE_CONTINENTALE = set(COUNTRY_NAMES.keys()) - {"US"}
    US_CODE = "US"

    # Coordonnées centroids pays (simplifié, à compléter si besoin)
    COUNTRY_COORDS = {
        "FR": [46.6, 2.2],
        "DE": [51.1, 10.4],
        "IT": [42.9, 12.6],
        "ES": [40.4, -3.7],
        "PT": [39.4, -8.2],
        "BE": [50.8, 4.6],
        "NL": [52.1, 5.3],
        "LU": [49.8, 6.1],
        "CH": [46.8, 8.2],
        "AT": [47.6, 14.1],
        "PL": [52.1, 19.4],
        "CZ": [49.8, 15.5],
        "SK": [48.7, 19.7],
        "HU": [47.2, 19.5],
        "SI": [46.1, 14.8],
        "HR": [45.8, 16.0],
        "RS": [44.0, 20.9],
        "BA": [44.2, 17.7],
        "ME": [42.7, 19.3],
        "MK": [41.6, 21.7],
        "BG": [42.7, 25.5],
        "RO": [45.9, 24.9],
        "MD": [47.0, 28.8],
        "UA": [48.4, 31.2],
        "BY": [53.7, 27.9],
        "LT": [55.2, 23.8],
        "LV": [56.9, 24.6],
        "EE": [58.7, 25.0],
        "AL": [41.1, 20.0],
        "GR": [39.1, 22.9],
        "SE": [60.1, 18.6],
        "NO": [60.5, 8.5],
        "DK": [56.0, 10.0],
        "FI": [64.5, 26.0],
        "US": [39.8, -98.6],
    }

    def is_recent(date_str):
        from datetime import datetime, timedelta

        try:
            date = datetime.strptime(date_str[:19], "%Y-%m-%d %H:%M:%S")
            return date >= datetime.now() - timedelta(days=7)
        except Exception:
            return False

    def is_europe_or_us(code):
        return code in EUROPE_CONTINENTALE or code == US_CODE

    victims_by_country = {}
    for entry in data:
        country = entry.get("country", "")
        if not is_europe_or_us(country):
            continue
        if not is_recent(entry.get("attackdate", "")):
            continue
        info = {
            "victim": entry.get("victim", "N/A"),
            "group": entry.get("group", "N/A"),
            "activity": entry.get("activity", "N/A"),
            "date": entry.get("attackdate", ""),
        }
        if country not in victims_by_country:
            victims_by_country[country] = []
        victims_by_country[country].append(info)

    # Format pour la carte
    result = []
    for code, victims in victims_by_country.items():
        result.append(
            {
                "country": code,
                "country_name": COUNTRY_NAMES.get(code, code),
                "count": len(victims),
                "coords": COUNTRY_COORDS.get(code, [0, 0]),
                "victims": victims,
            }
        )
    return result


def load_markets():
    with open("../markets.json", encoding="utf-8") as f:
        return json.load(f)


def fetch_market_data():
    """Récupère le cours actuel et l'historique 1 mois pour chaque actif défini dans markets.json."""
    markets = load_markets()
    results = []
    for asset in markets:
        symbol = asset["symbol"]
        asset_type = asset.get("type", "stock")
        name = asset.get("name", symbol)
        if asset_type == "crypto":
            # CoinGecko API
            coingecko_ids = {
                "BTC": "bitcoin",
                "ETH": "ethereum",
            }
            cg_id = coingecko_ids.get(symbol.upper())
            if not cg_id:
                continue
            try:
                resp = requests.get(
                    f"https://api.coingecko.com/api/v3/simple/price?ids={cg_id}&vs_currencies=eur",
                    timeout=6,
                )
                price = resp.json()[cg_id]["eur"]
            except Exception:
                price = None
            try:
                resp = requests.get(
                    f"https://api.coingecko.com/api/v3/coins/{cg_id}/market_chart?vs_currency=eur&days=30",
                    timeout=8,
                )
                prices = resp.json()["prices"]
                history = [
                    {
                        "date": datetime.datetime.utcfromtimestamp(
                            p[0] // 1000
                        ).strftime("%Y-%m-%d"),
                        "price": p[1],
                    }
                    for p in prices[:: max(1, len(prices) // 30)]
                ]
            except Exception:
                history = []
            results.append(
                {
                    "symbol": symbol,
                    "name": name,
                    "type": asset_type,
                    "price": price,
                    "currency": "EUR",
                    "history": history,
                }
            )
        else:
            # Utilisation de yfinance pour actions/indices
            price = None
            history = []
            currency = "EUR" if symbol in ["^FCHI", "PX1", "CAC", "MC.PA"] else "USD"
            try:
                ticker = yf.Ticker(symbol)
                # Prix actuel (1d, 1m interval)
                data = ticker.history(period="1d", interval="1m")
                if not data.empty:
                    price = float(data["Close"].iloc[-1])
                # Historique 1 mois (1d interval)
                data_hist = ticker.history(period="1mo", interval="1d")
                if not data_hist.empty:
                    history = [
                        {
                            "date": idx.strftime("%Y-%m-%d"),
                            "price": float(row["Close"]),
                        }
                        for idx, row in data_hist.iterrows()
                        if not math.isnan(row["Close"])
                    ]
                    if len(history) > 30:
                        step = max(1, len(history) // 30)
                        history = history[::step]
            except Exception:
                price = None
                history = []
            results.append(
                {
                    "symbol": symbol,
                    "name": name,
                    "type": asset_type,
                    "price": price,
                    "currency": currency,
                    "history": history,
                }
            )
    return results


def load_shortcuts():
    try:
        with open("../shortcuts.json", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def background_fetch():
    while True:
        fetch_news()
        time.sleep(300)  # 5 minutes


@app.route("/news")
def get_news():
    return jsonify(news_cache)


@app.route("/ransomware")
def ransomware_api():
    return jsonify(fetch_ransomware())


@app.route("/markets")
def markets_api():
    return jsonify(fetch_market_data())


@app.route("/")
def index():
    cves = fetch_cves()
    ransomware = fetch_ransomware()
    markets = fetch_market_data()
    shortcuts = load_shortcuts()
    html = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>CyberSec Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <!-- Ajout favicon -->
        <link rel="icon" type="image/png" href="/static/cybernews.png"/>
        <link href="https://fonts.googleapis.com/css?family=Montserrat:600,400&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
        <style>
            body {
                font-family: 'Montserrat', Arial, sans-serif;
                margin: 0;
                background: #181a1b;
                min-height: 100vh;
                color: #f7f6f1;
            }
            .dashboard-cards, .dashboard-main, .ransomware-map-container, .google-search-bar-container {
                max-width: 95vw !important;
                width: 95vw !important;
                min-width: 90vw !important;
                margin-left: auto;
                margin-right: auto;
            }
            .dashboard-cards {
                display: flex;
                gap: 1em; /* réduit l'espacement */
                margin: 2em auto 1.2em auto;
                max-width: 95vw !important;
                width: 95vw !important;
                min-width: 90vw !important;
                border-bottom: 2px solid #232320;
                justify-content: center; /* Ajout pour centrer les tuiles */
            }
            .dash-card {
                flex: 1 1 140px;
                min-width: 140px;
                max-width: 180px;
                background: #232320;
                border-radius: 12px;
                box-shadow: 0 2px 12px rgba(30,31,29,0.13);
                padding: 0.8em 0.8em 0.7em 0.8em;
                display: flex;
                align-items: center;
                gap: 0.7em;
                transition: transform 0.13s, box-shadow 0.13s;
                cursor: pointer;
            }
            .dash-card:hover {
                transform: translateY(-4px) scale(1.03);
                box-shadow: 0 6px 24px rgba(230,58,48,0.18);
                background: #262726;
            }
            .dash-icon {
                font-size: 1.7em;
                width: 36px;
                height: 36px;
                color: #e63a30;
                background: #1e1f1d;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: 0 1px 4px rgba(30,31,29,0.10);
            }
            .dash-info {
                display: flex;
                flex-direction: column;
                gap: 0.2em;
            }
            .dash-label {
                font-size: 0.93em;
                color: #bdbdb7;
                font-weight: 600;
            }
            .dash-value {
                font-size: 1.18em;
                font-weight: 700;
                color: #f7f6f1;
            }
            .dashboard-main {
                display: flex;
                gap: 2em;
                /* max-width: 1200px; */
                /* width: 100%; */
                margin: 0 auto 2em auto;
                align-items: flex-start;
                width: 100%;
            }
            .dashboard-left, .dashboard-right {
                display: flex;
                flex-direction: column;
                gap: 2em;
            }
            .dashboard-left {
                flex: 1.5 1 0;
                min-width: 340px;
            }
            .dashboard-center {
                flex: 1 1 0;
                min-width: 260px;
                max-width: 400px;
            }
            .dashboard-right {
                flex: 1.2 1 0;
                min-width: 340px;
            }
            .card {
                background: #232320;
                border-radius: 14px;
                box-shadow: 0 2px 12px rgba(30,31,29,0.13);
                padding: 1.2em 1em 1em 1em;
                margin-bottom: 0;
                display: flex;
                flex-direction: column;
                gap: 1em;
                min-height: 0;
            }
            .card-title {
                color: #e63a30;
                font-size: 1.13em;
                font-weight: 700;
                margin-bottom: 0.3em;
                letter-spacing: 0.5px;
                display: flex;
                align-items: center;
                gap: 0.5em;
                border-bottom: 2px solid #e63a30;
                padding-bottom: 0.2em;
                margin-bottom: 0.7em;
                background: linear-gradient(90deg, #e63a3022 60%, transparent 100%);
            }
            .shortcuts-title {
                color: #e63a30;
                font-size: 1.13em;
                font-weight: 700;
                margin-bottom: 0.3em;
                letter-spacing: 0.5px;
                display: flex;
                align-items: center;
                gap: 0.5em;
                border-bottom: 2px solid #e63a30;
                padding-bottom: 0.2em;
                margin-bottom: 0.7em;
                background: linear-gradient(90deg, #e63a3022 60%, transparent 100%);
                cursor: pointer;
            }
            .card-content-scroll {
                overflow-y: auto;
                max-height: 340px;
                padding-right: 0.5em;
            }
            /* Custom scrollbars */
            ::-webkit-scrollbar { width: 8px; background: #181a1b;}
            ::-webkit-scrollbar-thumb { background: #2e2e2b; border-radius: 6px;}
            .markets-row {
                display: flex;
                gap: 1em;
                flex-wrap: wrap;
            }
            .market-card {
                background: #232320;
                border-radius: 10px;
                box-shadow: 0 1px 4px rgba(30,31,29,0.07);
                padding: 1em 1em 1em 1em;
                min-width: 180px;
                max-width: 220px;
                flex: 1 1 180px;
                margin-bottom: 0.5em;
                transition: box-shadow 0.13s, background 0.13s, transform 0.13s;
                cursor: pointer;
            }
            .market-card:hover {
                box-shadow: 0 4px 18px rgba(230,58,48,0.13);
                background: #282926;
                transform: translateY(-2px) scale(1.02);
            }
            .market-symbol {
                font-weight: 600;
                color: #e63a30;
                font-size: 1.05em;
            }
            .market-price {
                font-size: 1.15em;
                font-weight: 700;
                color: #f7f6f1;
                margin-bottom: 0.3em;
            }
            .market-currency {
                color: #bdbdb7;
                font-size: 0.98em;
                margin-left: 0.5em;
            }
            .market-chart {
                width: 100% !important;
                height: 80px !important;
                min-width: 120px;
                max-width: 100%;
                display: block;
            }
            /* News & CVE */
            ul {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            .news-list li, .cve-list li {
                margin-bottom: 1.2em;
                background: #232320;
                border-radius: 8px;
                padding: 0.7em 0.7em 0.7em 0.9em;
                box-shadow: 0 1px 4px rgba(30,31,29,0.07);
                border-left: 4px solid #e63a30;
                transition: background 0.13s, opacity 0.13s;
            }
            .news-list li:hover, .cve-list li:hover {
                background: #282926;
            }
            .news-link {
                color: #e63a30;
                text-decoration: none;
                font-size: 1.09em;
                font-weight: 600;
                transition: color 0.13s;
                word-break: break-word;
            }
            .news-link:hover {
                color: #f7f6f1;
                text-decoration: underline;
            }
            .meta {
                margin-top: 0.5em;
                display: flex;
                align-items: center;
                gap: 1em;
                flex-wrap: wrap;
            }
            .badge {
                display: inline-block;
                background: #e63a30;
                color: #f7f6f1;
                font-size: 0.93em;
                font-weight: 600;
                border-radius: 6px;
                padding: 0.18em 0.7em;
                margin-right: 0.5em;
                letter-spacing: 0.5px;
            }
            .date {
                color: #bdbdb7;
                font-size: 0.98em;
                font-style: italic;
            }
            .cve-id {
                font-weight: 600;
                color: #e63a30;
                font-size: 1em;
            }
            .cve-score {
                background: #e63a30;
                color: #f7f6f1;
                border-radius: 6px;
                font-size: 0.93em;
                font-weight: 600;
                padding: 0.13em 0.6em;
                margin-left: 0.5em;
            }
            .cve-date {
                color: #bdbdb7;
                font-size: 0.95em;
                font-style: italic;
                margin-left: 0.5em;
            }
            .cve-desc {
                margin-top: 0.4em;
                font-size: 0.97em;
                color: #f7f6f1;
            }
            .cve-sort {
                margin-bottom: 0.7em;
                display: flex;
                align-items: center;
                gap: 0.7em;
            }
            .cve-sort label {
                color: #e63a30;
                font-weight: 600;
            }
            .cve-sort select {
                background: #1e1f1d;
                color: #f7f6f1;
                border: 1px solid #e63a30;
                border-radius: 4px;
                padding: 0.2em 0.7em;
                font-size: 1em;
            }
            /* Recherche news */
            .news-search-bar {
                margin-bottom: 1em;
                display: flex;
                align-items: center;
                gap: 0.7em;
            }
            .news-search-bar input[type="text"] {
                background: #1e1f1d;
                color: #f7f6f1;
                border: 1px solid #e63a30;
                border-radius: 4px;
                padding: 0.4em 1em;
                font-size: 1em;
                width: 100%;
                max-width: 320px;
            }
            .news-search-bar input[type="text"]:focus {
                outline: 2px solid #e63a30;
                background: #232320;
                box-shadow: 0 0 0 2px #e63a3033;
            }
            .news-search-bar i {
                color: #e63a30;
                font-size: 1.1em;
            }
            /* Modal styles */
            .modal-overlay {
                display: none;
                position: fixed;
                z-index: 1000;
                left: 0; top: 0;
                width: 100vw; height: 100vh;
                background: rgba(24,26,27,0.93);
                justify-content: center;
                align-items: center;
                transition: opacity 0.18s;
            }
            .modal-overlay.active {
                display: flex;
            }
            .modal-content {
                background: #232320;
                border-radius: 18px;
                box-shadow: 0 8px 48px rgba(30,31,29,0.23);
                width: 80vw;
                max-width: 900px;
                max-height: 80vh;
                min-height: 320px;
                overflow-y: auto;
                padding: 2.2em 2em 1.5em 2em;
                position: relative;
                color: #f7f6f1;
                animation: modalIn 0.18s;
            }
            @keyframes modalIn {
                from { transform: scale(0.97) translateY(30px); opacity: 0.2;}
                to { transform: scale(1) translateY(0); opacity: 1;}
            }
            .modal-close-btn {
                position: absolute;
                top: 1.1em; right: 1.3em;
                background: none;
                border: none;
                color: #e63a30;
                font-size: 2em;
                cursor: pointer;
                z-index: 10;
                transition: color 0.13s;
            }
            .modal-close-btn:hover {
                color: #f7f6f1;
            }
            .modal-title {
                font-size: 1.5em;
                font-weight: 700;
                color: #e63a30;
                margin-bottom: 1em;
                display: flex;
                align-items: center;
                gap: 0.5em;
            }
            .modal-section {
                margin-bottom: 1.5em;
            }
            .modal-section:last-child {
                margin-bottom: 0;
            }
            /* Pour améliorer la lisibilité dans la modal */
            .modal-content ul, .modal-content .markets-row {
                max-height: 48vh;
                overflow-y: auto;
            }
            .modal-content .market-card {
                max-width: 340px;
                min-width: 220px;
                font-size: 1.08em;
            }
            .modal-content .news-list li, .modal-content .cve-list li {
                font-size: 1.13em;
            }
            .modal-content .victims-list .victim-item {
                font-size: 1.13em;
            }
            @media (max-width: 700px) {
                .modal-content { width: 98vw; padding: 1.1em 0.5em;}
            }
            /* Nouvelle carte ransomware harmonisée */
            .ransomware-map-container {
                display: flex;
                flex-direction: row;
                width: 100%;
                max-width: 1200px;
                margin: 2em auto 0 auto;
                background: #232320;
                box-shadow: 0 2px 12px rgba(30,31,29,0.13);
                border-radius: 16px;
                min-height: 320px;
                overflow: hidden;
                border: 1.5px solid #232320;
            }
            .ransomware-map-section {
                width: 65%;
                min-width: 0;
                height: 320px;
                border-radius: 16px 0 0 16px;
                background: #232320;
                position: relative;
            }
            #ransom-map {
                width: 100%;
                height: 320px;
                border-radius: 16px 0 0 16px;
                margin: 0;
                box-shadow: none;
                background: #1e1f1d;
            }
            .victims-panel {
                width: 35%;
                min-width: 220px;
                max-width: 400px;
                background: #232320;
                border-left: 1.5px solid #282926;
                padding: 1.1em 0.7em 1.1em 1.1em;
                overflow-y: auto;
                height: 320px;
                border-radius: 0 16px 16px 0;
                box-sizing: border-box;
                display: flex;
                flex-direction: column;
                position: relative;
                z-index: 5;
            }
            .victims-panel-title {
                color: #e63a30;
                font-size: 1.13em;
                font-weight: 700;
                margin-bottom: 0.7em;
                letter-spacing: 0.5px;
                display: flex;
                align-items: center;
                gap: 0.5em;
                border-bottom: 2px solid #e63a30;
                padding-bottom: 0.2em;
                margin-bottom: 0.7em;
                background: linear-gradient(90deg, #e63a3022 60%, transparent 100%);
            }
            .victims-list {
                list-style: none;
                padding: 0;
                margin: 0;
                flex: 1 1 0;
                overflow-y: auto;
            }
            .victim-item {
                background: #232320;
                border-radius: 8px;
                padding: 0.5em 0.7em;
                margin-bottom: 0.5em;
                box-shadow: 0 1px 4px rgba(30,31,29,0.07);
                border-left: 4px solid #e63a30;
                cursor: pointer;
                transition: background 0.13s, opacity 0.13s, border-left 0.13s;
            }
            .victim-item:hover, .victim-item.active {
                background: #282926;
                border-left: 6px solid #f7f6f1;
            }
            .victim-title {
                font-weight: 600;
                color: #e63a30;
            }
            .victim-group {
                color: #bdbdb7;
                font-size: 0.97em;
                margin-left: 0.5em;
            }
            .victim-country {
                color: #bdbdb7;
                font-size: 0.97em;
                margin-left: 0.5em;
            }
            .victim-date {
                color: #bdbdb7;
                font-size: 0.95em;
                font-style: italic;
                margin-left: 0.5em;
            }
            /* Carte Leaflet custom */
            .leaflet-container {
                background: #1e1f1d !important;
                border-radius: 16px 0 0 16px;
                font-family: 'Montserrat', Arial, sans-serif;
            }
            .leaflet-popup-content-wrapper, .leaflet-tooltip {
                background: #232320 !important;
                color: #f7f6f1 !important;
                border-radius: 10px !important;
                border: 1.5px solid #e63a30 !important;
                font-size: 1em;
                box-shadow: 0 2px 12px rgba(30,31,29,0.13);
            }
            .leaflet-popup-tip, .leaflet-tooltip-tip {
                background: #e63a30 !important;
            }
            /* Pulse animation pour marker actif */
            @keyframes pulse {
                0% { box-shadow: 0 0 0 0 rgba(230,58,48,0.5);}
                70% { box-shadow: 0 0 0 12px rgba(230,58,48,0);}
                100% { box-shadow: 0 0 0 0 rgba(230,58,48,0);}
            }
            .leaflet-interactive.pulse {
                animation: pulse 1.2s infinite;
                stroke: #f7f6f1 !important;
                stroke-width: 3 !important;
            }
            /* Responsive */
            @media (max-width: 900px) {
                .ransomware-map-container {
                    flex-direction: column;
                    min-height: 0;
                    border-radius: 16px;
                    width: 98vw !important;
                    max-width: 98vw !important;
                }
                .ransomware-map-section, #ransom-map {
                    width: 100%;
                    height: 220px;
                    border-radius: 16px 16px 0 0;
                }
                .victims-panel {
                    width: 100%;
                    max-width: none;
                    border-radius: 0 0 16px 16px;
                    border-left: none;
                    border-top: 1.5px solid #282926;
                    height: 180px;
                }
            }
            /* Carte raccourcis personnalisés */
            .shortcuts-card {
                background: #232320;
                border-radius: 14px;
                box-shadow: 0 2px 12px rgba(30,31,29,0.13);
                padding: 1.2em 1em 1em 1em;
                margin-bottom: 0;
                display: flex;
                flex-direction: column;
                gap: 1em;
                min-height: 0;
                align-items: flex-start;
            }
            .shortcuts-title {
                color: #e63a30;
                font-size: 1.13em;
                font-weight: 700;
                margin-bottom: 0.3em;
                letter-spacing: 0.5px;
                display: flex;
                align-items: center;
                gap: 0.5em;
                border-bottom: 2px solid #e63a30;
                padding-bottom: 0.2em;
                margin-bottom: 0.7em;
                background: linear-gradient(90deg, #e63a3022 60%, transparent 100%);
                cursor: pointer;
            }
            .shortcuts-list {
                display: flex;
                flex-wrap: wrap;
                gap: 0.7em;
            }
            .shortcut-item {
                display: flex;
                align-items: center;
                gap: 0.5em;
                background: #282926;
                border-radius: 8px;
                padding: 0.5em 0.9em;
                color: #f7f6f1;
                text-decoration: none;
                font-weight: 600;
                font-size: 1.05em;
                transition: background 0.13s, color 0.13s, box-shadow 0.13s;
                box-shadow: 0 1px 4px rgba(30,31,29,0.07);
            }
            .shortcut-item:hover {
                background: #e63a30;
                color: #fff;
                box-shadow: 0 2px 12px rgba(230,58,48,0.13);
            }
            .shortcut-icon {
                font-size: 1.3em;
                min-width: 1.3em;
                color: #e63a30;
            }
            .shortcut-item:hover .shortcut-icon {
                color: #fff;
            }
            /* Barre de recherche Google */
            .google-search-bar-container {
                width: 100%;
                max-width: 1200px;
                margin: 0.7em auto 0.5em auto; /* réduit la marge top */
                display: flex;
                justify-content: center;
            }
            .google-search-bar {
                display: flex;
                align-items: center;
                background: #232320;
                border-radius: 10px;
                box-shadow: 0 1px 4px rgba(30,31,29,0.07);
                padding: 0.5em 1em;
                width: 100%;
                max-width: 480px;
                border: 1.5px solid #e63a30;
                gap: 0.7em;
            }
            .google-search-bar input[type="text"] {
                background: transparent;
                color: #f7f6f1;
                border: none;
                outline: none;
                font-size: 1.1em;
                width: 100%;
                padding: 0.3em 0.2em;
            }
            .google-search-bar i {
                color: #e63a30;
                font-size: 1.2em;
            }
            /* Responsive pour la colonne centrale */
            @media (max-width: 1200px) {
                .dashboard-main {
                    flex-direction: column;
                }
                .dashboard-left, .dashboard-center, .dashboard-right {
                    min-width: 0;
                    width: 100%;
                }
            }
            /* Ajout du footer */
            .footer-madeby {
                width: 100vw;
                text-align: center;
                color: #bdbdb7;
                font-size: 1em;
                margin: 2.5em 0 0.5em 0;
                letter-spacing: 0.5px;
                font-family: 'Montserrat', Arial, sans-serif;
                opacity: 0.85;
            }
            .footer-madeby .heart {
                color: #e63a30;
                font-size: 1.1em;
                vertical-align: middle;
            }
        </style>
        <script>
            // Données initiales côté client
            const NEWS = {{ news|tojson }};
            const RANSOMWARE = {{ ransomware|tojson }};
            const CVES = {{ cves|tojson }};
            const MARKETS = {{ markets|tojson }};
            const SHORTCUTS = {{ shortcuts|tojson }};
            // Pour dashboard cards
            const DASH = {
                news: NEWS.length,
                cves: CVES.length,
                ransomware: RANSOMWARE.reduce((a, b) => a + b.count, 0),
                markets: MARKETS.length
            };
            // Rassemble toutes les victimes avec leur pays et coordonnées
            const ALL_VICTIMS = [];
            RANSOMWARE.forEach(item => {
                (item.victims || []).forEach(v => {
                    ALL_VICTIMS.push({
                        ...v,
                        country: item.country,
                        country_name: item.country_name,
                        coords: item.coords
                    });
                });
            });

            let map, markers = {}, lastActiveVictim = null, lastPulseMarker = null;

            function getRadius(count) {
                return Math.max(12, Math.min(38, 10 + Math.sqrt(count) * 7));
            }
            function popupContent(country, victims) {
                let html = `<b style="color:#e63a30;">${country}</b><br><ul class="victim-list" style="padding-left:0;">`;
                victims.forEach(v => {
                    let dateOnly = v.date ? v.date.slice(0, 10) : '';
                    html += `<li style="margin-bottom:0.3em;">
                        <span class="victim-title">${v.victim}</span>
                        <span class="victim-group">(${v.group})</span><br>
                        <span class="victim-date">${dateOnly}</span><br>
                        <span style="color:#bdbdb7;">${v.activity}</span>
                    </li>`;
                });
                html += "</ul>";
                return html;
            }
            // Recherche dynamique actualités
            function renderNews() {
                const search = (document.getElementById('news-search-input')?.value || '').toLowerCase();
                let filtered = NEWS;
                if (search.length > 0) {
                    filtered = NEWS.filter(item =>
                        item.title.toLowerCase().includes(search) ||
                        item.source.toLowerCase().includes(search)
                    );
                }
                const ul = document.getElementById('news-list');
                ul.innerHTML = '';
                filtered.slice(0, 20).forEach(item => {
                    const li = document.createElement('li');
                    li.innerHTML = `
                        <a class="news-link" href="${item.link}" target="_blank">${item.title}</a>
                        <div class="meta">
                            <span class="badge">${item.source}</span>
                            <span class="date" data-date="${item.published}">${item.published}</span>
                        </div>
                    `;
                    ul.appendChild(li);
                });
                document.querySelectorAll('.date[data-date]').forEach(function(el) {
                    const d = new Date(el.getAttribute('data-date'));
                    if (!isNaN(d)) {
                        el.textContent = d.toLocaleString('fr-FR', {
                            year: 'numeric', month: 'short', day: 'numeric',
                            hour: '2-digit', minute: '2-digit'
                        });
                    }
                });
            }
            // Trie et affiche la liste des CVE selon le critère sélectionné
            function renderCVEs() {
                const sortValue = document.getElementById('cve-sort-select').value;
                let cves = [...CVES];
                if (sortValue === "date-desc") {
                    cves.sort((a, b) => new Date(b.published) - new Date(a.published));
                } else if (sortValue === "date-asc") {
                    cves.sort((a, b) => new Date(a.published) - new Date(b.published));
                } else if (sortValue === "score-desc") {
                    cves.sort((a, b) => b.score - a.score);
                } else if (sortValue === "score-asc") {
                    cves.sort((a, b) => a.score - b.score);
                }
                const ul = document.getElementById('cve-list');
                ul.innerHTML = '';
                if (cves.length === 0) {
                    ul.innerHTML = '<li>Aucune CVE critique récente.</li>';
                } else {
                    cves.forEach(cve => {
                        const li = document.createElement('li');
                        li.innerHTML = `
                            <a class="cve-id" href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank">${cve.id}</a>
                            <span class="cve-score">CVSS ${cve.score.toFixed(1)}</span>
                            <span class="cve-date" data-date="${cve.published}">${cve.published}</span>
                            <div class="cve-desc">${cve.description}</div>
                        `;
                        ul.appendChild(li);
                    });
                }
                document.querySelectorAll('.cve-date[data-date]').forEach(function(el) {
                    const d = new Date(el.getAttribute('data-date'));
                    if (!isNaN(d)) {
                        el.textContent = d.toLocaleString('fr-FR', {
                            year: 'numeric', month: 'short', day: 'numeric',
                            hour: '2-digit', minute: '2-digit'
                        });
                    }
                });
            }
            // Graphiques interactifs avec tooltip prix
            function renderMarkets() {
                const container = document.getElementById('markets-row');
                container.innerHTML = '';
                MARKETS.forEach(asset => {
                    const card = document.createElement('div');
                    card.className = 'market-card';
                    card.innerHTML = `
                        <div class="market-symbol">${asset.name} (${asset.symbol})</div>
                        <div class="market-price">${asset.price !== null ? asset.price.toLocaleString('fr-FR', {maximumFractionDigits: 2}) : 'N/A'}
                            <span class="market-currency">${asset.currency}</span>
                        </div>
                        <canvas id="chart-${asset.symbol.replace(/[^a-zA-Z0-9]/g,'')}" class="market-chart" width="180" height="80"></canvas>
                    `;
                    container.appendChild(card);
                    if (asset.history && asset.history.length > 1) {
                        const ctx = card.querySelector('canvas').getContext('2d');
                        let history = asset.history.filter(h => h.price !== null);
                        if (history.length > 30) {
                            const step = Math.max(1, Math.floor(history.length / 30));
                            history = history.filter((_, i) => i % step === 0);
                        }
                        const labels = history.map(h => h.date);
                        const data = history.map(h => h.price);
                        new Chart(ctx, {
                            type: 'line',
                            data: {
                                labels: labels,
                                datasets: [{
                                    label: asset.symbol,
                                    data: data,
                                    borderColor: '#e63a30',
                                    backgroundColor: 'rgba(230,58,48,0.08)',
                                    tension: 0.2,
                                    pointRadius: 0,
                                }]
                            },
                            options: {
                                plugins: {
                                    legend: { display: false },
                                    tooltip: {
                                        enabled: true,
                                        callbacks: {
                                            label: function(context) {
                                                return 'Prix: ' + context.parsed.y.toLocaleString('fr-FR', {maximumFractionDigits: 2});
                                            }
                                        },
                                        backgroundColor: '#232320',
                                        titleColor: '#e63a30',
                                        bodyColor: '#f7f6f1',
                                        borderColor: '#e63a30',
                                        borderWidth: 1,
                                    }
                                },
                                scales: {
                                    x: { display: false },
                                    y: { display: false }
                                },
                                elements: { line: { borderWidth: 2 } },
                                responsive: false,
                                maintainAspectRatio: false,
                                hover: { mode: 'nearest', intersect: false }
                            }
                        });
                    }
                });
            }
            function renderVictimsPanel() {
                const panel = document.getElementById('victims-list');
                panel.innerHTML = '';
                if (ALL_VICTIMS.length === 0) {
                    panel.innerHTML = '<li>Aucune victime récente.</li>';
                    return;
                }
                ALL_VICTIMS.forEach((v, idx) => {
                    const li = document.createElement('li');
                    li.className = 'victim-item';
                    li.setAttribute('data-country', v.country);
                    li.setAttribute('data-coords', JSON.stringify(v.coords));
                    li.setAttribute('data-idx', idx);
                    // Affiche uniquement la date (YYYY-MM-DD)
                    let dateOnly = v.date ? v.date.slice(0, 10) : '';
                    li.innerHTML = `
                        <span class="victim-title">${v.victim}</span>
                        <span class="victim-group">(${v.group})</span>
                        <span class="victim-country">${v.country_name}</span>
                        <span class="victim-date">${dateOnly}</span>
                    `;
                    li.addEventListener('click', function() {
                        // Highlight selection
                        if (lastActiveVictim) lastActiveVictim.classList.remove('active');
                        li.classList.add('active');
                        lastActiveVictim = li;
                        // Centre la carte sur le pays de la victime
                        const coords = v.coords;
                        if (map && coords && coords.length === 2) {
                            map.setView(coords, 5, {animate: true});
                            // Ouvre le popup du marker correspondant
                            if (markers[v.country]) {
                                markers[v.country].openPopup();
                                // Effet pulse sur le marker
                                if (lastPulseMarker) lastPulseMarker._path.classList.remove('pulse');
                                if (markers[v.country]._path) {
                                    markers[v.country]._path.classList.add('pulse');
                                    lastPulseMarker = markers[v.country];
                                }
                            }
                        }
                    });
                    panel.appendChild(li);
                });
            }

            // ----------- MODAL LOGIC -----------
            function openModal(type) {
                const overlay = document.getElementById('modal-overlay');
                const content = document.getElementById('modal-content');
                let html = '';
                if (type === 'news') {
                    html = `<div class="modal-title"><i class="fa-solid fa-newspaper"></i> Actualités détaillées</div>
                        <div class="modal-section">
                            <div class="news-search-bar">
                                <i class="fa-solid fa-magnifying-glass"></i>
                                <input type="text" id="modal-news-search-input" placeholder="Rechercher une actualité..."/>
                            </div>
                            <ul class="news-list" id="modal-news-list"></ul>
                        </div>`;
                } else if (type === 'cves') {
                    html = `<div class="modal-title"><i class="fa-solid fa-bug"></i> Toutes les CVE critiques</div>
                        <div class="modal-section">
                            <div class="cve-sort">
                                <label for="modal-cve-sort-select">Trier par :</label>
                                <select id="modal-cve-sort-select">
                                    <option value="date-desc" selected>Date (du plus récent au plus ancien)</option>
                                    <option value="date-asc">Date (du plus ancien au plus récent)</option>
                                    <option value="score-desc">Score CVSS (du plus haut au plus bas)</option>
                                    <option value="score-asc">Score CVSS (du plus bas au plus haut)</option>
                                </select>
                            </div>
                            <ul class="cve-list" id="modal-cve-list"></ul>
                        </div>`;
                } else if (type === 'ransomware') {
                    html = `<div class="modal-title"><i class="fa-solid fa-skull-crossbones"></i> Victimes ransomware détaillées</div>
                        <div class="modal-section">
                            <ul class="victims-list" id="modal-victims-list"></ul>
                        </div>`;
                } else if (type === 'markets') {
                    html = `<div class="modal-title"><i class="fa-solid fa-chart-line"></i> Marchés surveillés</div>
                        <div class="modal-section">
                            <div class="markets-row" id="modal-markets-row"></div>
                        </div>`;
                }
                content.innerHTML = `<button class="modal-close-btn" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></button>` + html;
                overlay.classList.add('active');
                document.body.style.overflow = 'hidden';
                // Remplir contenu selon type
                if (type === 'news') {
                    function renderModalNews() {
                        const search = (document.getElementById('modal-news-search-input')?.value || '').toLowerCase();
                        let filtered = NEWS;
                        if (search.length > 0) {
                            filtered = NEWS.filter(item =>
                                item.title.toLowerCase().includes(search) ||
                                item.source.toLowerCase().includes(search)
                            );
                        }
                        const ul = document.getElementById('modal-news-list');
                        ul.innerHTML = '';
                        filtered.forEach(item => {
                            const li = document.createElement('li');
                            li.innerHTML = `
                                <a class="news-link" href="${item.link}" target="_blank">${item.title}</a>
                                <div class="meta">
                                    <span class="badge">${item.source}</span>
                                    <span class="date" data-date="${item.published}">${item.published}</span>
                                </div>
                            `;
                            ul.appendChild(li);
                        });
                        document.querySelectorAll('.date[data-date]').forEach(function(el) {
                            const d = new Date(el.getAttribute('data-date'));
                            if (!isNaN(d)) {
                                el.textContent = d.toLocaleString('fr-FR', {
                                    year: 'numeric', month: 'short', day: 'numeric',
                                    hour: '2-digit', minute: '2-digit'
                                });
                            }
                        });
                    }
                    renderModalNews();
                    document.getElementById('modal-news-search-input').addEventListener('input', renderModalNews);
                } else if (type === 'cves') {
                    function renderModalCVEs() {
                        const sortValue = document.getElementById('modal-cve-sort-select').value;
                        let cves = [...CVES];
                        if (sortValue === "date-desc") {
                            cves.sort((a, b) => new Date(b.published) - new Date(a.published));
                        } else if (sortValue === "date-asc") {
                            cves.sort((a, b) => new Date(a.published) - new Date(b.published));
                        } else if (sortValue === "score-desc") {
                            cves.sort((a, b) => b.score - a.score);
                        } else if (sortValue === "score-asc") {
                            cves.sort((a, b) => a.score - b.score);
                        }
                        const ul = document.getElementById('modal-cve-list');
                        ul.innerHTML = '';
                        if (cves.length === 0) {
                            ul.innerHTML = '<li>Aucune CVE critique récente.</li>';
                        } else {
                            cves.forEach(cve => {
                                const li = document.createElement('li');
                                li.innerHTML = `
                                    <a class="cve-id" href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank">${cve.id}</a>
                                    <span class="cve-score">CVSS ${cve.score.toFixed(1)}</span>
                                    <span class="cve-date" data-date="${cve.published}">${cve.published}</span>
                                    <div class="cve-desc">${cve.description}</div>
                                `;
                                ul.appendChild(li);
                            });
                        }
                        document.querySelectorAll('.cve-date[data-date]').forEach(function(el) {
                            const d = new Date(el.getAttribute('data-date'));
                            if (!isNaN(d)) {
                                el.textContent = d.toLocaleString('fr-FR', {
                                    year: 'numeric', month: 'short', day: 'numeric',
                                    hour: '2-digit', minute: '2-digit'
                                });
                            }
                        });
                    }
                    renderModalCVEs();
                    document.getElementById('modal-cve-sort-select').addEventListener('change', renderModalCVEs);
                } else if (type === 'ransomware') {
                    // Victimes ransomware détaillées
                    const panel = document.getElementById('modal-victims-list');
                    panel.innerHTML = '';
                    if (ALL_VICTIMS.length === 0) {
                        panel.innerHTML = '<li>Aucune victime récente.</li>';
                    } else {
                        ALL_VICTIMS.forEach((v, idx) => {
                            const li = document.createElement('li');
                            li.className = 'victim-item';
                            let dateOnly = v.date ? v.date.slice(0, 10) : '';
                            li.innerHTML = `
                                <span class="victim-title">${v.victim}</span>
                                <span class="victim-group">(${v.group})</span>
                                <span class="victim-country">${v.country_name}</span>
                                <span class="victim-date">${dateOnly}</span>
                                <div style="margin-top:0.3em; color:#bdbdb7;">${v.activity}</div>
                            `;
                            panel.appendChild(li);
                        });
                    }
                } else if (type === 'markets') {
                    // Affiche tous les marchés avec graphiques
                    const container = document.getElementById('modal-markets-row');
                    container.innerHTML = '';
                    MARKETS.forEach(asset => {
                        const card = document.createElement('div');
                        card.className = 'market-card';
                        card.innerHTML = `
                            <div class="market-symbol">${asset.name} (${asset.symbol})</div>
                            <div class="market-price">${asset.price !== null ? asset.price.toLocaleString('fr-FR', {maximumFractionDigits: 2}) : 'N/A'}
                                <span class="market-currency">${asset.currency}</span>
                            </div>
                            <canvas id="modal-chart-${asset.symbol.replace(/[^a-zA-Z0-9]/g,'')}" class="market-chart" width="220" height="80"></canvas>
                        `;
                        container.appendChild(card);
                        if (asset.history && asset.history.length > 1) {
                            const ctx = card.querySelector('canvas').getContext('2d');
                            let history = asset.history.filter(h => h.price !== null);
                            if (history.length > 30) {
                                const step = Math.max(1, Math.floor(history.length / 30));
                                history = history.filter((_, i) => i % step === 0);
                            }
                            const labels = history.map(h => h.date);
                            const data = history.map(h => h.price);
                            new Chart(ctx, {
                                type: 'line',
                                data: {
                                    labels: labels,
                                    datasets: [{
                                        label: asset.symbol,
                                        data: data,
                                        borderColor: '#e63a30',
                                        backgroundColor: 'rgba(230,58,48,0.08)',
                                        tension: 0.2,
                                        pointRadius: 0,
                                    }]
                                },
                                options: {
                                    plugins: {
                                        legend: { display: false },
                                        tooltip: {
                                            enabled: true,
                                            callbacks: {
                                                label: function(context) {
                                                    return 'Prix: ' + context.parsed.y.toLocaleString('fr-FR', {maximumFractionDigits: 2});
                                                }
                                            },
                                            backgroundColor: '#232320',
                                            titleColor: '#e63a30',
                                            bodyColor: '#f7f6f1',
                                            borderColor: '#e63a30',
                                            borderWidth: 1,
                                        }
                                    },
                                    scales: {
                                        x: { display: false },
                                        y: { display: false }
                                    },
                                    elements: { line: { borderWidth: 2 } },
                                    responsive: false,
                                    maintainAspectRatio: false,
                                    hover: { mode: 'nearest', intersect: false }
                                }
                            });
                        }
                    });
                }
            }
            function closeModal() {
                document.getElementById('modal-overlay').classList.remove('active');
                document.body.style.overflow = '';
            }
            // Fermer la modal si clic sur overlay
            document.addEventListener('DOMContentLoaded', function() {
                document.getElementById('modal-overlay').addEventListener('click', function(e) {
                    if (e.target === this) closeModal();
                });
                document.addEventListener('keydown', function(e) {
                    if (e.key === "Escape") closeModal();
                });
            });
            // ----------- FIN MODAL LOGIC -----------

            // Affichage dynamique des raccourcis
            function renderShortcuts() {
                const container = document.getElementById('shortcuts-list');
                if (!container) return;
                container.innerHTML = '';
                if (SHORTCUTS.length === 0) {
                    container.innerHTML = '<span style="color:#bdbdb7;">Aucun raccourci défini.</span>';
                    return;
                }
                SHORTCUTS.forEach(item => {
                    const a = document.createElement('a');
                    a.className = 'shortcut-item';
                    a.href = item.url;
                    a.target = '_blank';
                    a.innerHTML = `<span class="shortcut-icon"><i class="${item.icon}"></i></span> ${item.name}`;
                    container.appendChild(a);
                });
            }

            // Barre de recherche Google
            function setupGoogleSearchBar() {
                const input = document.getElementById('google-search-input');
                if (!input) return;
                input.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') {
                        const q = input.value.trim();
                        if (q.length > 0) {
                            window.open('https://www.google.com/search?q=' + encodeURIComponent(q), '_blank');
                        }
                    }
                });
            }

            document.addEventListener('DOMContentLoaded', function() {
                // Suppression dashboard cards
                // document.getElementById('dash-news').textContent = DASH.news;
                // document.getElementById('dash-cves').textContent = DASH.cves;
                // document.getElementById('dash-ransom').textContent = DASH.ransomware;
                // document.getElementById('dash-markets').textContent = DASH.markets;
                // News, CVE, Markets
                renderNews();
                renderCVEs();
                renderMarkets();
                // Recherche dynamique news
                const searchInput = document.getElementById('news-search-input');
                if (searchInput) {
                    searchInput.addEventListener('input', renderNews);
                }
                // Carte ransomware + markers
                if (document.getElementById('ransom-map')) {
                    map = L.map('ransom-map', {scrollWheelZoom: false, zoomControl: true, attributionControl: false}).setView([48, 8], 4.1);
                    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                        attribution: '',
                        maxZoom: 8,
                        minZoom: 2,
                    }).addTo(map);
                    RANSOMWARE.forEach(item => {
                        const marker = L.circleMarker(item.coords, {
                            radius: getRadius(item.count),
                            color: "#e63a30",
                            fillColor: "#e63a30",
                            fillOpacity: 0.55,
                            weight: 2,
                            className: "ransom-marker"
                        }).addTo(map);
                        marker.bindTooltip(`${item.country_name}: ${item.count} victime${item.count>1?'s':''}`, {permanent: false, direction: 'top', offset: [0,-2]});
                        marker.bindPopup(popupContent(item.country_name, item.victims));
                        markers[item.country] = marker;
                        marker.on('click', function() {
                            marker.openPopup();
                            // Pulse sur marker
                            if (lastPulseMarker && lastPulseMarker._path) lastPulseMarker._path.classList.remove('pulse');
                            if (marker._path) {
                                marker._path.classList.add('pulse');
                                lastPulseMarker = marker;
                            }
                        });
                    });
                }
                // Panneau victimes
                renderVictimsPanel();
                // Tri CVE
                document.getElementById('cve-sort-select').addEventListener('change', renderCVEs);
                // Scroll to top button
                const scrollBtn = document.getElementById('scrollTopBtn');
                window.addEventListener('scroll', function() {
                    if (window.scrollY > 200) {
                        scrollBtn.style.display = 'block';
                    } else {
                        scrollBtn.style.display = 'none';
                    }
                });
                scrollBtn.addEventListener('click', function() {
                    window.scrollTo({top: 0, behavior: 'smooth'});
                });
                // Ajout ouverture modale sur clic titre
                document.getElementById('markets-title').addEventListener('click', function() { openModal('markets'); });
                document.getElementById('news-title').addEventListener('click', function() { openModal('news'); });
                document.getElementById('cves-title').addEventListener('click', function() { openModal('cves'); });
                document.getElementById('ransomware-title').addEventListener('click', function() { openModal('ransomware'); });
                // Raccourcis
                renderShortcuts();
                // Barre de recherche Google
                setupGoogleSearchBar();
            });
        </script>
    </head>
    <body>
        <!-- Suppression du header -->

        <!-- Suppression du bloc dashboard-cards -->
        <!--
        <div class="dashboard-cards">
            ... supprimé ...
        </div>
        -->

        <!-- Déplacement de la barre de recherche Google ici -->
        <div class="google-search-bar-container">
            <form class="google-search-bar" onsubmit="event.preventDefault(); if(googleSearchInput.value.trim().length>0){window.open('https://www.google.com/search?q='+encodeURIComponent(googleSearchInput.value.trim()),'_blank');}">
                <i class="fa-solid fa-magnifying-glass"></i>
                <input type="text" id="google-search-input" name="googleSearchInput" placeholder="Recherche Google..."/>
            </form>
        </div>
        <!-- Déplacement de la carte ransomware juste après -->
        <div class="ransomware-map-container">
            <div class="ransomware-map-section">
                <div id="ransom-map"></div>
            </div>
            <div class="victims-panel">
                <div class="victims-panel-title card-title" id="ransomware-title" tabindex="0">
                    <i class="fa-solid fa-skull-crossbones"></i> Victimes ransomware
                    <span class="recap-count" id="recap-ransomware">{{ ransomware|length }}</span>
                </div>
                <ul class="victims-list" id="victims-list"></ul>
            </div>
        </div>
        <div class="dashboard-main" style="display:flex; gap:2em; max-width:1200px; margin:0 auto 2em auto; align-items:flex-start;">
            <div class="dashboard-left">
                <div class="card">
                    <div class="card-title" id="markets-title" tabindex="0">
                        <i class="fa-solid fa-chart-line"></i> Marchés surveillés
                        <span class="recap-count" id="recap-markets">{{ markets|length }}</span>
                    </div>
                    <div class="markets-row" id="markets-row"></div>
                </div>
            </div>
            <!-- Colonne centrale pour les raccourcis -->
            <div class="dashboard-center" style="flex:0.7 1 0; min-width:220px; max-width:320px; display:flex; flex-direction:column; gap:2em;">
                <div class="shortcuts-card">
                    <div class="shortcuts-title" id="shortcuts-title">
                        <i class="fa-solid fa-bolt"></i> Raccourcis personnalisés
                        <span class="recap-count" id="recap-shortcuts">{{ shortcuts|length }}</span>
                    </div>
                    <div class="shortcuts-list" id="shortcuts-list"></div>
                </div>
            </div>
            <div class="dashboard-right">
                <div class="card" style="flex:1 1 0; min-height:220px;">
                    <div class="card-title" id="news-title" tabindex="0">
                        <i class="fa-solid fa-newspaper"></i> Dernières actualités
                        <span class="recap-count" id="recap-news">{{ news|length }}</span>
                    </div>
                    <div class="news-search-bar">
                        <i class="fa-solid fa-magnifying-glass"></i>
                        <input type="text" id="news-search-input" placeholder="Rechercher une actualité..."/>
                    </div>
                    <div class="card-content-scroll">
                        <ul class="news-list" id="news-list"></ul>
                    </div>
                </div>
                <div class="card" style="flex:1 1 0; min-height:220px;">
                    <div class="card-title" id="cves-title" tabindex="0">
                        <i class="fa-solid fa-bug"></i> CVE critiques récentes
                        <span class="recap-count" id="recap-cves">{{ cves|length }}</span>
                    </div>
                    <div class="cve-sort">
                        <label for="cve-sort-select">Trier par :</label>
                        <select id="cve-sort-select">
                            <option value="date-desc" selected>Date (du plus récent au plus ancien)</option>
                            <option value="date-asc">Date (du plus ancien au plus récent)</option>
                            <option value="score-desc">Score CVSS (du plus haut au plus bas)</option>
                            <option value="score-asc">Score CVSS (du plus bas au plus haut)</option>
                        </select>
                    </div>
                    <div class="card-content-scroll">
                        <ul class="cve-list" id="cve-list"></ul>
                    </div>
                </div>
            </div>
        </div>
        <button id="scrollTopBtn" title="Remonter"><i class="fa-solid fa-arrow-up"></i></button>
        <!-- MODAL OVERLAY -->
        <div class="modal-overlay" id="modal-overlay">
            <div class="modal-content" id="modal-content"></div>
        </div>
        <!-- Ajout du footer -->
        <div class="footer-madeby">
            made with <span class="heart">&lt;3</span> by jobl1n0urs
        </div>
    </body>
    </html>
    """
    return render_template_string(
        html,
        news=news_cache,
        cves=cves,
        ransomware=ransomware,
        markets=markets,
        shortcuts=shortcuts,
    )


if __name__ == "__main__":
    Thread(target=background_fetch, daemon=True).start()
    fetch_news()
    app.run(host="0.0.0.0", port=5000)
