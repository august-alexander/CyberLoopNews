"""NIST NVD CVE fetcher — standard library only (Lambda-friendly, no deps)."""

import json
import time
import urllib.parse
import urllib.request

# NVD 2.0 caps results at 2000 per page. With an API key the rate limit is
# 50 requests / 30s; without one it's 5 / 30s. We sleep between pages to stay
# comfortably under either.
RESULTS_PER_PAGE = 2000
PAGE_DELAY_SECONDS = 1.0

# The NVD 2.0 API ONLY accepts ISO-8601 for pubStartDate/pubEndDate and rejects
# anything else. This is mandated by NIST and is separate from the
# %Y%m%d%H%M%S convention we use for our own S3 keys / state file.
NVD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000"


def _request(base_url, params, api_key, timeout=30):
    """Perform a single GET against the NVD API and return parsed JSON."""
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "CyberLoopNews/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


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


def extract_cve_ids(vulnerabilities):
    """Pull the list of CVE IDs from a vulnerabilities payload."""
    return [v["cve"]["id"] for v in vulnerabilities if "cve" in v]
