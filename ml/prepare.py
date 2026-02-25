# prepare.py
import csv
import gzip
import logging
import time
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
OUTPUT_CSV = DATA_DIR / "dataset.csv"

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EPSS_THRESHOLD = 0.7

CVSS_MAP = {
    "AV": {"N": 3, "A": 2, "L": 1, "P": 0},
    "AC": {"L": 1, "H": 0},
    "PR": {"N": 2, "L": 1, "H": 0},
    "UI": {"N": 1, "R": 0},
    "S": {"U": 0, "C": 1},
    "CIA": {"H": 2, "L": 1, "N": 0},
}

FEATURES_LIST = [
    "base_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality",
    "integrity",
    "availability",
    "vendors",
    "products",
    "epss",
    "in_kev",
]


def download_epss():
    logger.info("Downloading EPSS data...")
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        r = client.get(EPSS_URL)
        r.raise_for_status()
        content = gzip.decompress(r.content).decode("utf-8")

    scores = {}
    for line in content.splitlines():
        if line.startswith(("#", "cve")):
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            scores[parts[0]] = float(parts[1])
    return scores


def download_kev():
    logger.info("Downloading KEV catalog...")
    with httpx.Client(timeout=60) as client:
        r = client.get(KEV_URL)
        r.raise_for_status()
        return {v["cveID"] for v in r.json().get("vulnerabilities", [])}


def fetch_nvd_data():
    all_vulns = []
    start_index = 0
    results_per_page = 2000

    logger.info("Downloading NVD data...")

    with httpx.Client(timeout=90) as client:
        while True:
            try:
                r = client.get(
                    NVD_API, params={"startIndex": start_index, "resultsPerPage": results_per_page}
                )
                if r.status_code == 403:
                    time.sleep(30)
                    continue
                r.raise_for_status()
                data = r.json()

                batch = data.get("vulnerabilities", [])
                if not batch:
                    break

                all_vulns.extend(batch)
                total = data.get("totalResults", 0)
                logger.info(f"Fetched {len(all_vulns)} / {total}")

                start_index += results_per_page
                if start_index >= total:
                    break
                time.sleep(6.5)

            except Exception as e:
                logger.error(f"HTTP Error: {e}")
                time.sleep(10)
    return all_vulns


def extract_features(item):
    metrics = item.get("cve", {}).get("metrics", {})
    res = None

    for v_key in ("cvssMetricV31", "cvssMetricV30"):
        if m_list := metrics.get(v_key):
            m = m_list[0]
            d = m.get("cvssData", {})
            vec = d.get("vectorString", "")

            p = {}
            for part in vec.split("/"):
                if ":" in part:
                    k, v = part.split(":", 1)
                    p[k] = v

            try:
                res = {
                    "base_score": float(d.get("baseScore", 0)),
                    "attack_vector": CVSS_MAP["AV"].get(p.get("AV"), -1),
                    "attack_complexity": CVSS_MAP["AC"].get(p.get("AC"), -1),
                    "privileges_required": CVSS_MAP["PR"].get(p.get("PR"), -1),
                    "user_interaction": CVSS_MAP["UI"].get(p.get("UI"), -1),
                    "scope": CVSS_MAP["S"].get(p.get("S"), -1),
                    "confidentiality": CVSS_MAP["CIA"].get(p.get("C"), -1),
                    "integrity": CVSS_MAP["CIA"].get(p.get("I"), -1),
                    "availability": CVSS_MAP["CIA"].get(p.get("A"), -1),
                }

                if any(val == -1 for val in res.values()):
                    res = None
            except Exception:
                res = None
            break

    if not res:
        return None

    vendors = set()
    products = set()
    for config in item.get("cve", {}).get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe23 = match.get("criteria", "")
                parts = cpe23.split(":")
                if len(parts) >= 5:
                    vendors.add(parts[3])
                    products.add(parts[4])

    res["vendors"] = " ".join(vendors)
    res["products"] = " ".join(products)

    return res


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    epss_data = download_epss()
    kev_data = download_kev()
    nvd_raw = fetch_nvd_data()

    dataset = []
    skipped_cvss = 0

    for item in nvd_raw:
        cve_id = item.get("cve", {}).get("id", "")
        feats = extract_features(item)

        if not feats:
            skipped_cvss += 1
            continue

        epss_val = epss_data.get(cve_id, 0.0)
        in_kev = 1 if cve_id in kev_data else 0
        label = 1 if (in_kev or epss_val > EPSS_THRESHOLD) else 0

        dataset.append(
            {"cve_id": cve_id, **feats, "epss": epss_val, "in_kev": in_kev, "label": label}
        )

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id"] + FEATURES_LIST + ["label"])
        writer.writeheader()
        writer.writerows(dataset)

    logger.info(f"Total entries: {len(dataset)}. Skipped due to missing CVSS v3: {skipped_cvss}")


if __name__ == "__main__":
    main()
