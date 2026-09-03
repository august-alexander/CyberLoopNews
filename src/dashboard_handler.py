"""Dashboard data Lambda: publish everything the static page charts, in one file.

Single responsibility — it builds the one small summary object the dashboard
reads, and nothing else. It writes DASHBOARD_KEY into the SITE bucket,
same-origin with index.html, so the browser fetches it with no CORS.

WHAT IT PUBLISHES (and why it's one object):
  windows  — the top CVEs by LoopScore for each timeframe the page offers
             (today / 7d / 30d), each up to DASHBOARD_MAX_N. All of them, every
             run, so the page's timeframe and top-N buttons re-render instantly
             from data it already holds instead of a fetch per click.
  days     — CVEs published per day over DASHBOARD_TREND_DAYS, for the sparkline.
  last_24h — a rolling 24-hour count, the "is today a flood?" number.

WHERE THE DATA COMES FROM: the by_day index on the CVE table, the same index
search_handler._query_recent uses. This Lambda used to list analysis/ in S3 and
GET every object in a fixed window — fine for 24 hours, unaffordable for 30 days
(thousands of GETs an hour). Against the index a day is one small Query, so the
whole 30-day picture is ~60 Queries.

That index change also changes what a "window" MEANS. It is now the CVE's
PUBLISHED date, not when we happened to score it — which is what lets the page
state its timeframe honestly ("published in the last 7 days") and is the only
definition the per-day trend can share.

Runs hourly via EventBridge. Written with Cache-Control: max-age=30 to match the
dashboard HTML, so a fresh publish shows within 30s with no CloudFront
invalidation.

Manual override (for testing):
  {"trend_days": N} -> build an N-day trend instead of the configured window
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
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.ranking_handler import _utcnow

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)

# Sort-key floors on by_day. Unscored CVEs carry score_sk == -1
# (analysis_handler.UNSCORED_SK), so ANY includes them and SCORED excludes them:
# the chart ranks by LoopScore and can only show CVEs that have one, while the
# daily counts are "how many CVEs landed", scored or not.
SK_ANY = Decimal(-1)
SK_SCORED = Decimal(0)


def _vendor(result):
    """Primary vendor for the chart's x-axis, from the analyzer's `vendors` list.

    Each entry is a "Vendor: Product" string (see analyzer._vendors). We take the
    vendor half of the first entry; a multi-vendor CVE lands in its primary
    vendor's column. Falls back to "Unknown" when there's no vendor data.
    """
    vendors = result.get("vendors") or []
    if not vendors:
        return "Unknown"
    vendor = vendors[0].split(":", 1)[0].strip()
    return vendor or "Unknown"


def _to_chart(result):
    """Trim one scored result to the three fields the bar chart reads."""
    score = result.get("loop_score")
    return {
        "cve": result.get("cve_id"),
        "vendor": _vendor(result),
        # Table numbers come back as Decimal; json can't serialise those.
        "score": float(score) if isinstance(score, Decimal) else score,
    }


def _days_back(now, count):
    """The last `count` day-partition keys, newest first."""
    return [(now - timedelta(days=d)).strftime("%Y-%m-%d") for d in range(count)]


def _top_for_day(table, day, limit):
    """That day's worst scored CVEs: one Query on by_day, highest score first."""
    resp = table.query(
        IndexName="by_day",
        KeyConditionExpression=Key("published_day").eq(day) & Key("score_sk").gte(SK_SCORED),
        ScanIndexForward=False,  # highest score_sk first
        Limit=limit,
        # Aliased, like the projection in _rolling_24h — DynamoDB's reserved-word
        # list is long enough that naming attributes directly is a latent break.
        ProjectionExpression="#id, #v, #s",
        ExpressionAttributeNames={"#id": "cve_id", "#v": "vendors", "#s": "loop_score"},
    )
    return resp.get("Items", [])


def _count_for_day(table, day):
    """How many CVEs we hold for that day, scored or not: one COUNT Query.

    Select=COUNT so DynamoDB returns a number instead of the items — a day can
    hold hundreds of CVEs and none of their content is wanted here.
    """
    count, start_key = 0, None
    while True:
        kwargs = {
            "IndexName": "by_day",
            "KeyConditionExpression": Key("published_day").eq(day) & Key("score_sk").gte(SK_ANY),
            "Select": "COUNT",
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.query(**kwargs)
        count += resp.get("Count", 0)
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            return count


def _rolling_24h(table, now):
    """CVEs published in the last 24 hours — a real rolling count, not "today".

    A rolling window straddles two day partitions, so this reads today's and
    yesterday's rows and compares timestamps. `published` is projected on its own
    (it isn't a key attribute, but by_day projects ALL), which keeps this to two
    small Queries even on a busy day.
    """
    cutoff = (now - timedelta(hours=24)).isoformat()
    count = 0
    for day in _days_back(now, 2):
        start_key = None
        while True:
            kwargs = {
                "IndexName": "by_day",
                "KeyConditionExpression": Key("published_day").eq(day) & Key("score_sk").gte(SK_ANY),
                # #p, not "published": DynamoDB rejects a projection that names a
                # reserved word directly, and the reserved list is long enough
                # that aliasing is the safe habit.
                "ProjectionExpression": "#p",
                "ExpressionAttributeNames": {"#p": "published"},
            }
            if start_key:
                kwargs["ExclusiveStartKey"] = start_key
            resp = table.query(**kwargs)
            # NVD publishes naive-UTC timestamps ("2026-09-03T14:03:00.000"), so
            # they compare correctly as strings against an ISO cutoff of the same
            # shape. Anything unparseable/missing sorts low and is left out.
            count += sum(1 for it in resp.get("Items", []) if (it.get("published") or "") >= cutoff)
            start_key = resp.get("LastEvaluatedKey")
            if not start_key:
                break
    return count


def _windows(per_day, day_keys, sizes, limit):
    """Top `limit` CVEs for each window size, from the already-read per-day tops.

    Correct without re-querying: the top N over a range of days is always a
    subset of the union of each day's own top N, so merging the per-day lists and
    re-sorting gives the same answer the whole-range query would.
    """
    out = {}
    for size in sizes:
        merged = [item for day in day_keys[:size] for item in per_day.get(day, [])]
        merged.sort(key=lambda it: it.get("loop_score") or 0, reverse=True)
        out[str(size)] = [_to_chart(it) for it in merged[:limit]]
    return out


def lambda_handler(event, context):
    event = event or {}
    if not Config.CVE_TABLE:
        return {"error": "CVE_TABLE not configured; the dashboard reads the index"}

    now = _utcnow()
    limit = Config.DASHBOARD_MAX_N
    sizes = sorted(int(w) for w in Config.DASHBOARD_WINDOWS.split(",") if w.strip())
    trend_days = int(event.get("trend_days") or Config.DASHBOARD_TREND_DAYS)
    # Read back far enough to cover both the trend and the widest window.
    span = max([trend_days] + sizes)

    table = boto3.resource("dynamodb", region_name=Config.AWS_REGION).Table(Config.CVE_TABLE)
    day_keys = _days_back(now, span)

    per_day = {day: _top_for_day(table, day, limit) for day in day_keys}
    counts = {day: _count_for_day(table, day) for day in day_keys[:trend_days]}

    payload = {
        "generated_at": now.isoformat(),
        "last_24h": _rolling_24h(table, now),
        # Oldest first: a sparkline reads left-to-right through time.
        "days": [{"day": d, "count": counts[d]} for d in reversed(day_keys[:trend_days])],
        "windows": _windows(per_day, day_keys, sizes, limit),
    }

    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    s3.put_object(
        Bucket=Config.SITE_BUCKET,
        Key=Config.DASHBOARD_KEY,
        Body=json.dumps(payload, indent=2),
        ContentType="application/json",
        CacheControl="max-age=30",
    )
    written = {w: len(rows) for w, rows in payload["windows"].items()}
    logger.info(
        "wrote s3://%s/%s — windows=%s last_24h=%d trend=%dd",
        Config.SITE_BUCKET, Config.DASHBOARD_KEY, written, payload["last_24h"], trend_days,
    )
    return {
        "key": Config.DASHBOARD_KEY,
        "windows": written,
        "last_24h": payload["last_24h"],
        "trend_days": trend_days,
    }
