"""Search Lambda: the read-only query endpoint behind the site's filter panel.

This is the "query Lambda" the CVE table was built for (see dynamodb.tf). The
static page can't ask DynamoDB a question directly, so this sits in front of the
table and answers three — and only three — shapes of question, each of which is a
single indexed Query or GetItem. It NEVER Scans: the whole point of the table is
to avoid the bucket-listing the ranking/dashboard Lambdas do, and a Scan would
throw that away and hand a visitor a way to run up the bill.

Exposed as a Lambda Function URL, reached same-origin through CloudFront at
/api/search (see frontend.tf), so the browser needs no CORS and identical queries
are cached at the edge.

Query params (all on GET /api/search):
  cve=CVE-2026-1234        exact lookup            -> GetItem on the base table
  q=azure                  vendor OR product       -> terms table, by_score LSI
  days=7                   recent window (default) -> by_day GSI, newest N days
  min_score=75             floor on LoopScore      -> score_sk >= N key condition
  limit=25                 page size               -> capped, see Config

`q` searches the TERMS table, not the vendor index. The CVE table indexes one
vendor per CVE, so `vendor=microsoft` could never find a CVE by its product —
"azure" and "gcp" matched nothing at all. The terms table holds a row per
searchable word (see terms.py), which is a strict superset of the vendor names,
so `vendor=` is kept as an alias for `q=` and now returns more, not less. A
multi-word query is INTERSECTED across its words, so "microsoft azure" narrows.

`q` and `cve` are mutually exclusive with the day window; if neither is given we
browse the recent window. `min_score` refines the term/day modes (it's a
sort-key condition, so it stays a single Query per term). Anything that would
require a Scan is rejected with 400 rather than served slowly.
"""

import json
import logging
from datetime import timedelta
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

try:
    from config import Config
    from ranking_handler import _utcnow
    from terms import query_terms
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.ranking_handler import _utcnow
    from src.terms import query_terms

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)

# The fields the filter panel renders. We trim to these so the response stays
# small and we never leak the raw model-judgment internals (prevalence/
# exploitability rationales) the table happens to also carry.
DISPLAY_FIELDS = (
    "cve_id",
    "vendor",
    "loop_score",
    "priority",
    "severity",
    "cvss",
    "published",
    "summary",
)


class BadRequest(Exception):
    """A client error — surfaced to the caller as a 400, not a 500."""


def _table():
    return boto3.resource("dynamodb", region_name=Config.AWS_REGION).Table(
        Config.CVE_TABLE
    )


def _terms_table():
    return boto3.resource("dynamodb", region_name=Config.AWS_REGION).Table(
        Config.TERMS_TABLE
    )


def _primary_vendor(item):
    """Human-facing vendor name for a row.

    Items store `vendors` as "Vendor: Product" strings (analyzer._vendors) plus a
    lowercased `vendor_key` for the index. Prefer the nicely-cased vendor half of
    the first `vendors` entry; fall back to the index key, then "Unknown".
    """
    vendors = item.get("vendors") or []
    if vendors:
        vendor = (vendors[0] or "").split(":", 1)[0].strip()
        if vendor:
            return vendor
    return item.get("vendor_key") or "Unknown"


def _row(item):
    """Trim one table item to the display fields the panel reads."""
    row = {k: item.get(k) for k in DISPLAY_FIELDS if k != "vendor"}
    row["vendor"] = _primary_vendor(item)
    return row


def _int(params, name, default, lo, hi):
    """Parse a bounded integer query param, clamping into [lo, hi]."""
    raw = params.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise BadRequest(f"{name} must be an integer")
    return max(lo, min(hi, value))


def _lookup_cve(cve_id):
    """Exact CVE lookup: one GetItem on the base table."""
    resp = _table().get_item(Key={"cve_id": cve_id})
    item = resp.get("Item")
    return [item] if item else []


def _query_one_term(term, min_score, limit):
    """All CVEs carrying one search term, worst-first: one Query on by_score."""
    cond = Key("term").eq(term) & Key("score_sk").gte(Decimal(min_score))
    resp = _terms_table().query(
        IndexName="by_score",
        KeyConditionExpression=cond,
        ScanIndexForward=False,  # highest score_sk first
        Limit=limit,
    )
    return resp.get("Items", [])


def _has_term(term, cve_ids):
    """Which of `cve_ids` also carry `term`: one BatchGetItem on the exact keys.

    A membership test, not a second search. Querying the other term and
    intersecting two top-N lists would silently drop real matches — "microsoft"
    alone has far more than one page of rows, so a CVE could carry both words and
    still miss the cut on the second list. (term, cve_id) is the table's full
    key, so asking for exactly these rows is one request and always right.
    """
    keys = [{"term": term, "cve_id": cve_id} for cve_id in cve_ids if cve_id]
    if not keys:
        return set()
    resp = boto3.resource("dynamodb", region_name=Config.AWS_REGION).batch_get_item(
        RequestItems={
            Config.TERMS_TABLE: {"Keys": keys, "ProjectionExpression": "cve_id"}
        }
    )
    found = resp.get("Responses", {}).get(Config.TERMS_TABLE, [])
    return {it["cve_id"] for it in found}


def _query_terms(terms, min_score, limit):
    """CVEs matching EVERY given term, worst-first.

    The first term is the search — one Query, already score-ordered and carrying
    every display field. Each further term only narrows that page, so
    "microsoft azure" returns CVEs carrying both words rather than everything
    Microsoft ships.
    """
    rows = _query_one_term(terms[0], min_score, limit)
    for term in terms[1:]:
        if not rows:
            break
        keep = _has_term(term, [it.get("cve_id") for it in rows])
        rows = [it for it in rows if it.get("cve_id") in keep]
    return rows


def _query_recent(days, min_score, limit):
    """Recent window, worst-first: one Query per day on by_day, then merge.

    Each day is its own partition, so this is `days` small Queries — never a
    Scan. We pull up to `limit` per day (already score-sorted within a day), then
    globally sort the merged set by score and truncate, so the caller gets the
    top `limit` across the whole window.
    """
    now = _utcnow()
    items = []
    for d in range(days):
        day = (now - timedelta(days=d)).strftime("%Y-%m-%d")
        cond = Key("published_day").eq(day) & Key("score_sk").gte(Decimal(min_score))
        resp = _table().query(
            IndexName="by_day",
            KeyConditionExpression=cond,
            ScanIndexForward=False,
            Limit=limit,
        )
        items.extend(resp.get("Items", []))
    items.sort(key=lambda it: it.get("score_sk", Decimal(-1)), reverse=True)
    return items[:limit]


def _search(params):
    """Route the request to exactly one indexed access pattern."""
    limit = _int(params, "limit", Config.SEARCH_DEFAULT_LIMIT, 1, Config.SEARCH_MAX_LIMIT)
    # min_score defaults to 0 so UNSCORED rows (score_sk == -1) are excluded and
    # every mode carries a sort-key condition — keeping each read a single Query.
    min_score = _int(params, "min_score", 0, 0, 100)

    cve = (params.get("cve") or "").strip().upper()
    # `vendor` is the old name for this parameter, kept so existing links and the
    # cached edge responses keep working; both now search terms, not the vendor
    # index.
    text = (params.get("q") or params.get("vendor") or "").strip()

    if cve:
        return _lookup_cve(cve), {"cve": cve}
    if text:
        terms = query_terms(text)
        if not terms:
            # Everything the user typed was punctuation or a stopword — there is
            # no term to query, and falling through to the day window would
            # silently answer a different question.
            return [], {"q": text, "terms": [], "min_score": min_score, "limit": limit}
        return _query_terms(terms, min_score, limit), {
            "q": text,
            "terms": terms,
            "min_score": min_score,
            "limit": limit,
        }
    days = _int(params, "days", Config.SEARCH_DEFAULT_DAYS, 1, Config.SEARCH_MAX_DAYS)
    return _query_recent(days, min_score, limit), {
        "days": days,
        "min_score": min_score,
        "limit": limit,
    }


class _DecimalEncoder(json.JSONEncoder):
    """DynamoDB numbers come back as Decimal; render them as int/float in JSON."""

    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o % 1 == 0 else float(o)
        return super().default(o)


def _response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            # Identical queries are cheap to reserve at the edge; 30s matches the
            # rest of the site so a fresh scored CVE shows up quickly.
            "Cache-Control": "public, max-age=30",
        },
        "body": json.dumps(body, cls=_DecimalEncoder),
    }


def lambda_handler(event, context):
    event = event or {}
    method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod")
        or "GET"
    )
    if method not in ("GET", "HEAD"):
        return _response(405, {"error": "method not allowed"})

    params = event.get("queryStringParameters") or {}
    try:
        items, echo = _search(params)
    except BadRequest as e:
        return _response(400, {"error": str(e)})
    except Exception:
        logger.exception("search failed for params=%s", params)
        return _response(500, {"error": "internal error"})

    rows = [_row(it) for it in items]
    logger.info("search %s -> %d rows", echo, len(rows))
    return _response(200, {"query": echo, "count": len(rows), "results": rows})
