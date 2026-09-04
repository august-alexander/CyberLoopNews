"""SEC EDGAR fetcher — 8-K Item 1.05 material cybersecurity incident disclosures.

Standard library only (Lambda-friendly, no deps). Uses EDGAR's full-text search
API (efts.sec.gov). SEC REQUIRES a descriptive User-Agent with contact info or
it returns HTTP 403.

Item 1.05 ("Material Cybersecurity Incidents") was added to Form 8-K by the SEC
in Dec 2023, so this is effectively a live feed of public companies disclosing a
material breach. Volume is low — a handful per month, ~80 in total since the rule
took effect — but a wide backfill window still exceeds one page, so the search is
paged (see _paged_hits).

SELECTING FILINGS: EDGAR indexes the 8-K item list as a queryable field, so we
ask for `items=1.05` directly rather than full-text searching for the item's
title. That matters — this used to search the phrase "Material Cybersecurity
Incidents" and keep the hits whose item list contained 1.05, which found only 70
of the 82 filings that actually exist: a filing is not obliged to spell the
item's official title anywhere in its text. The item filter is both complete
(every 1.05 filing carries the code) and exact (it returns nothing else), which
is why the phrase constant and the leftover false-positive filtering are gone.
"""

import json
import time
import urllib.parse
import urllib.request

FORM_TYPE = "8-K"
TARGET_ITEM = "1.05"

# EDGAR full-text search returns at most 100 hits per request and pages with
# `from`. Elasticsearch refuses a `from` past 10000, which is the real ceiling on
# any one query — far above anything this feed produces, but a runaway loop
# against SEC infrastructure is not the way to discover that.
PAGE_SIZE = 100
MAX_HITS = 10000

# SEC asks for no more than 10 requests/second. One page every 0.3s is polite and
# still drains the entire historical backfill in a couple of seconds.
PAGE_DELAY_SECONDS = 0.3


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


def _paged_hits(base_url, user_agent, params):
    """Every hit for `params`, following EDGAR's `from` pagination.

    Returns (hits, total). A daily window is one page; the historical backfill is
    a handful. Stops on a short page as well as on the reported total, so a
    disagreement between the two ends the loop rather than spinning.
    """
    hits, offset = [], 0
    while True:
        page_params = dict(params, **({"from": offset} if offset else {}))
        url = f"{base_url}?{urllib.parse.urlencode(page_params)}"
        data = _request(url, user_agent)

        page = data.get("hits", {}).get("hits", []) or []
        hits.extend(page)
        total = data.get("hits", {}).get("total", {}).get("value", len(hits))

        offset += PAGE_SIZE
        if len(page) < PAGE_SIZE or offset >= min(total, MAX_HITS):
            return hits, total
        time.sleep(PAGE_DELAY_SECONDS)


def _record(hit, default_form):
    """Normalise one search hit into the filing shape we store."""
    source = hit.get("_source", {})
    names = source.get("display_names") or []
    company = names[0] if names else "(unknown)"
    locations = source.get("biz_locations") or []
    return {
        "company": company,
        "cik": _parse_cik(company) if names else None,
        "file_date": source.get("file_date"),
        # "8-K/A" is an AMENDMENT to an earlier disclosure — a quarter of the
        # 1.05 filings are one, and they are usually where the incident's actual
        # impact lands, the original often being little more than "we are
        # investigating". Worth distinguishing rather than showing as a repeat.
        "form": source.get("form") or default_form,
        "items": source.get("items") or [],
        # Free from the response and genuinely useful for scanning the archive.
        "location": locations[0] if locations else None,
        "accession": hit.get("_id", "").partition(":")[0],
        "url": _filing_url(hit),
    }


def _dedupe(records):
    """One record per accession, keeping the first (best-ranked) hit.

    A single filing indexes each of its documents separately, so a filing whose
    disclosure sits in an exhibit returns several hits — the 6-K feed is roughly
    a third duplicates by document. Collapsing here keeps the stored dump an
    honest list of FILINGS; `totalResults` still reports the raw hit count.
    """
    seen, out = set(), []
    for record in records:
        accession = record.get("accession")
        if not accession or accession in seen:
            continue
        seen.add(accession)
        out.append(record)
    return out


def fetch_incident_filings(base_url, user_agent, start, end):
    """Fetch 8-K filings reporting Item 1.05 filed within [start, end].

    Args:
        base_url: EDGAR full-text search endpoint.
        user_agent: descriptive UA with contact info (SEC requirement).
        start / end: datetime objects; only the date component is used.

    Returns:
        (total_hits, filings) where filings is a list of normalized dicts:
        {company, cik, file_date, form, items, location, accession, url},
        deduped by accession.
    """
    params = {
        "forms": FORM_TYPE,
        "items": TARGET_ITEM,
        "startdt": start.strftime("%Y-%m-%d"),
        "enddt": end.strftime("%Y-%m-%d"),
    }
    hits, total = _paged_hits(base_url, user_agent, params)

    # EDGAR's item filter is exact, so this keeps nothing out today. It stays as
    # a cheap guard: the one thing this archive must never do is record a filing
    # as a breach disclosure when it isn't one.
    filings = _dedupe(
        _record(hit, FORM_TYPE)
        for hit in hits
        if TARGET_ITEM in (hit.get("_source", {}).get("items") or [])
    )
    return total, filings
