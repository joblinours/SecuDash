from flask import Flask, jsonify
import requests
from datetime import datetime, timedelta

app = Flask(__name__)


def fetch_critical_cves():
    end_date = datetime.utcnow().replace(microsecond=0)
    start_date = end_date - timedelta(days=1)
    start_iso = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
    end_iso = end_date.strftime("%Y-%m-%dT23:59:59.999Z")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    params = {"pubStartDate": start_iso, "pubEndDate": end_iso}
    headers = {"User-Agent": "Python CVE Fetcher"}
    response = requests.get(url, params=params, headers=headers)
    cves = []
    if response.status_code == 200:
        data = response.json()
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "N/A")
            published = cve_data.get("published", "N/A")
            metrics = cve_data.get("metrics", {})
            score = None
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            if score is not None and score >= 8.0:
                descriptions = cve_data.get("descriptions", [])
                desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                if not desc and descriptions:
                    desc = descriptions[0].get("value", "")
                max_len = 120
                if len(desc) > max_len:
                    desc = desc[:max_len].rstrip() + "..."
                cves.append(
                    {
                        "id": cve_id,
                        "score": score,
                        "published": published,
                        "description": desc,
                    }
                )
    return cves


@app.route("/cves")
def get_cves():
    cves = fetch_critical_cves()
    return jsonify(cves)


if __name__ == "__main__":
    app.run(port=5001)
