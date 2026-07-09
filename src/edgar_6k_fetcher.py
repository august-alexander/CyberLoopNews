"""SEC EDGAR fetcher — 6-K material cybersecurity incident disclosures.

Standard library only (Lambda-friendly, no deps). Uses EDGAR's full-text search
API (efts.sec.gov). SEC REQUIRES a descriptive User-Agent with contact info or
it returns HTTP 403.

Form 6-K is how *foreign private issuers* furnish material information. Unlike
domestic 8-K filers, they are NOT subject to the itemized Item 1.05 cyber-
incident requirement — a 6-K has no item structure at all. So we cannot filter
on an item code the way the 8-K fetcher does; the full-text phrase IS the filter.

The phrase is deliberately the active, past-tense disclosure language
("...experienced a cybersecurity incident...") rather than the noun phrase
"material cybersecurity incident". The latter appears verbatim in the risk-factor
boilerplate of routine earnings 6-Ks (e.g. shipping FPIs listing every
hypothetical risk), which produced mostly false positives. The active phrase
keeps real breach disclosures and drops the boilerplate.
"""

import json
import urllib.parse
import urllib.request

# Reuse the shared EDGAR helpers from the 8-K fetcher (same API, same hit shape).
try:
    from edgar_fetcher import _filing_url, _parse_cik
except ImportError:  # pragma: no cover - local/dev path
    from src.edgar_fetcher import _filing_url, _parse_cik

FTS_QUERY = '"experienced a cybersecurity incident"'
FORM_TYPE = "6-K"


def _request(url, user_agent, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_incident_filings(base_url, user_agent, start, end):
    """Fetch 6-K filings disclosing a cybersecurity incident filed within
    [start, end].

    Args:
        base_url: EDGAR full-text search endpoint.
        user_agent: descriptive UA with contact info (SEC requirement).
        start / end: datetime objects; only the date component is used.

    Returns:
        (total_hits, filings) where filings is a list of normalized dicts:
        {company, cik, file_date, form, accession, url}. There is no item filter
        (6-K has no items) — the full-text phrase is the only selector.
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
        names = source.get("display_names", [])
        company = names[0] if names else "(unknown)"
        filings.append(
            {
                "company": company,
                "cik": _parse_cik(company) if names else None,
                "file_date": source.get("file_date"),
                "form": source.get("form", FORM_TYPE),
                "accession": hit.get("_id", "").partition(":")[0],
                "url": _filing_url(hit),
            }
        )

    total = data.get("hits", {}).get("total", {}).get("value", len(filings))
    return total, filings
