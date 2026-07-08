"""SEC EDGAR fetcher — 8-K Item 1.05 material cybersecurity incident disclosures.

Standard library only (Lambda-friendly, no deps). Uses EDGAR's full-text search
API (efts.sec.gov). SEC REQUIRES a descriptive User-Agent with contact info or
it returns HTTP 403.

Item 1.05 ("Material Cybersecurity Incidents") was added to Form 8-K by the SEC
in Dec 2023, so this is effectively a live feed of public companies disclosing a
material breach. Volume is low (a handful per month), so a single search page
comfortably covers any daily window — no pagination needed.
"""

import json
import urllib.parse
import urllib.request

# Official title of 8-K Item 1.05; used to pre-filter the full-text search so we
# don't page through every 8-K. We still confirm the item list below, because
# the phrase can appear in related/amended filings that aren't themselves 1.05.
FTS_QUERY = '"Material Cybersecurity Incidents"'
FORM_TYPE = "8-K"
TARGET_ITEM = "1.05"


def _request(url, user_agent, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _parse_cik(display_name):
    """Extract the integer CIK from a display_name such as
    'NAVIENT CORP  (JSM, NAVI)  (CIK 0001593538)'. Returns None if not found.
    """
    marker = "CIK "
    idx = display_name.rfind(marker)
    if idx == -1:
        return None
    digits = display_name[idx + len(marker):].rstrip(") ")
    return int(digits) if digits.isdigit() else None


def _filing_url(hit):
    """Build the primary-document URL from a hit's _id ('accession:filename')
    and its CIK. Returns None if any piece is missing.
    """
    accession, _, filename = hit.get("_id", "").partition(":")
    names = hit.get("_source", {}).get("display_names", [])
    cik = _parse_cik(names[0]) if names else None
    if not accession or not filename or cik is None:
        return None
    return (
        "https://www.sec.gov/Archives/edgar/data/"
        f"{cik}/{accession.replace('-', '')}/{filename}"
    )


def fetch_incident_filings(base_url, user_agent, start, end):
    """Fetch 8-K filings reporting Item 1.05 filed within [start, end].

    Args:
        base_url: EDGAR full-text search endpoint.
        user_agent: descriptive UA with contact info (SEC requirement).
        start / end: datetime objects; only the date component is used.

    Returns:
        (total_hits, filings) where filings is a list of normalized dicts:
        {company, cik, file_date, items, accession, url}. Only filings whose
        item list actually includes 1.05 are kept.
    """
    params = {
        "q": FTS_QUERY,
        "forms": FORM_TYPE,
        "startdt": start.strftime("%Y-%m-%d"),
        "enddt": end.strftime("%Y-%m-%d"),
    }
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    data = _request(url, user_agent)

    hits = data.get("hits", {}).get("hits", [])
    filings = []
    for hit in hits:
        source = hit.get("_source", {})
        if TARGET_ITEM not in (source.get("items") or []):
            continue
        names = source.get("display_names", [])
        company = names[0] if names else "(unknown)"
        filings.append(
            {
                "company": company,
                "cik": _parse_cik(company) if names else None,
                "file_date": source.get("file_date"),
                "items": source.get("items", []),
                "accession": hit.get("_id", "").partition(":")[0],
                "url": _filing_url(hit),
            }
        )

    total = data.get("hits", {}).get("total", {}).get("value", len(filings))
    return total, filings
