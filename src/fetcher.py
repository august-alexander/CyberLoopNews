"""NIST NVD CVE fetcher — standard library only (Lambda-friendly, no deps)."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

# NVD intermittently returns 503s / slow reads, especially over a large window.
# Retry transient failures with exponential backoff so one blip doesn't fail the
# whole run (which would leave the state marker un-advanced and grow the next
# window even larger).
REQUEST_MAX_RETRIES = 3
REQUEST_BACKOFF_SECONDS = 2

# NVD 2.0 caps results at 2000 per page. With an API key the rate limit is
# 50 requests / 30s; without one it's 5 / 30s. We sleep between pages to stay
# comfortably under either.
RESULTS_PER_PAGE = 2000
PAGE_DELAY_SECONDS = 1.0

# The NVD 2.0 API ONLY accepts ISO-8601 for pubStartDate/pubEndDate and rejects
# anything else. This is mandated by NIST and is separate from the
# %Y%m%d%H%M%S convention we use for our own S3 keys / state file.
NVD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000"

# CVE.org (MITRE) record API. NVD's `configurations` (CPE) data is only filled
# in during NVD's own analysis, so brand-new CVEs carry no product/OS info
# there. The CVE.org record, however, exposes the CNA's `affected[]` list at
# publish time — vendor/product/versions are populated immediately. We enrich
# each fetched CVE with that so the report has a signal for fresh CVEs.
CVE_ORG_API = "https://cveawg.mitre.org/api/cve/"
ENRICH_DELAY_SECONDS = 0.34


def _request(base_url, params, api_key, timeout=30):
    """Perform a single GET against the NVD API and return parsed JSON.

    Retries transient failures (HTTP 429/5xx, connection/read timeouts) with
    exponential backoff before giving up.
    """
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "CyberLoopNews/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    for attempt in range(REQUEST_MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # Only 429/5xx are worth retrying; 4xx (bad request) would just repeat.
            if exc.code not in (429, 500, 502, 503, 504) or attempt == REQUEST_MAX_RETRIES - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == REQUEST_MAX_RETRIES - 1:
                raise
        time.sleep(REQUEST_BACKOFF_SECONDS * (2**attempt))


def fetch_cves_by_pub_date(base_url, api_key, pub_start, pub_end):
    """Fetch all CVEs *published* within [pub_start, pub_end].

    Args:
        base_url: NVD 2.0 endpoint.
        api_key: NIST NVD API key (may be None).
        pub_start / pub_end: datetime objects (treated as UTC by NVD).

    Returns:
        (total_results, vulnerabilities) where vulnerabilities is the combined
        list across all pages.
    """
    base_params = {
        "pubStartDate": pub_start.strftime(NVD_DATE_FORMAT),
        "pubEndDate": pub_end.strftime(NVD_DATE_FORMAT),
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    vulnerabilities = []
    start_index = 0
    total_results = 0

    while True:
        params = dict(base_params, startIndex=start_index)
        data = _request(base_url, params, api_key)

        total_results = data.get("totalResults", 0)
        page = data.get("vulnerabilities", [])
        vulnerabilities.extend(page)

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results or not page:
            break

        time.sleep(PAGE_DELAY_SECONDS)

    return total_results, vulnerabilities


def fetch_cna_affected(cve_id, timeout=15):
    """Return the CNA-supplied affected products for one CVE from CVE.org.

    Reads containers.cna.affected[] and returns a deduped list of
    {"vendor", "product"} dicts. Best-effort: any network/parse error (or a CVE
    not yet mirrored by CVE.org) yields []. Placeholder products like "n/a" are
    dropped so they don't pollute the breakdown.
    """
    url = f"{CVE_ORG_API}{urllib.parse.quote(cve_id)}"
    req = urllib.request.Request(url, headers={"User-Agent": "CyberLoopNews/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            record = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []

    affected = record.get("containers", {}).get("cna", {}).get("affected", []) or []
    products = []
    seen = set()
    for entry in affected:
        vendor = (entry.get("vendor") or "").strip()
        product = (entry.get("product") or "").strip()
        if not product or product.lower() in ("n/a", "unknown"):
            continue
        key = (vendor.lower(), product.lower())
        if key in seen:
            continue
        seen.add(key)
        products.append({"vendor": vendor, "product": product})
    return products


def enrich_with_cna_affected(vulnerabilities):
    """Attach CNA-supplied affected products to each vuln, in place.

    Sets cve["cnaAffected"] = [{"vendor", "product"}, ...]. One CVE.org request
    per CVE, throttled by ENRICH_DELAY_SECONDS. For the daily delta this is a
    modest number of requests; if the fetch window is ever very large, budget
    Lambda timeout accordingly.
    """
    last = len(vulnerabilities) - 1
    for i, vuln in enumerate(vulnerabilities):
        cve = vuln.get("cve")
        if not cve or "id" not in cve:
            continue
        cve["cnaAffected"] = fetch_cna_affected(cve["id"])
        if i < last:
            time.sleep(ENRICH_DELAY_SECONDS)
    return vulnerabilities


def extract_cve_ids(vulnerabilities):
    """Pull the list of CVE IDs from a vulnerabilities payload."""
    return [v["cve"]["id"] for v in vulnerabilities if "cve" in v]
