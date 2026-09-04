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

# Reuse the shared EDGAR helpers from the 8-K fetcher (same API, same hit shape).
# Paging, record shape and accession dedup are identical for both forms — only
# the SELECTOR differs, and that difference is the whole point of this module.
try:
    from edgar_fetcher import _dedupe, _paged_hits, _record
except ImportError:  # pragma: no cover - local/dev path
    from src.edgar_fetcher import _dedupe, _paged_hits, _record

FTS_QUERY = '"experienced a cybersecurity incident"'
FORM_TYPE = "6-K"


def fetch_incident_filings(base_url, user_agent, start, end):
    """Fetch 6-K filings disclosing a cybersecurity incident filed within
    [start, end].

    Args:
        base_url: EDGAR full-text search endpoint.
        user_agent: descriptive UA with contact info (SEC requirement).
        start / end: datetime objects; only the date component is used.

    Returns:
        (total_hits, filings) where filings is a list of normalized dicts,
        deduped by accession. There is no item filter (6-K has no items) — the
        full-text phrase is the only selector, so unlike the 8-K feed there is
        no exact field to fall back on and the phrase choice IS the precision.

    Dedup matters more here than on the 8-K side: a 6-K carries its substance in
    exhibits, so one filing routinely matches on several documents at once.
    """
    params = {
        "q": FTS_QUERY,
        "forms": FORM_TYPE,
        "startdt": start.strftime("%Y-%m-%d"),
        "enddt": end.strftime("%Y-%m-%d"),
    }
    hits, total = _paged_hits(base_url, user_agent, params)
    return total, _dedupe(_record(hit, FORM_TYPE) for hit in hits)
