"""Dashboard data Lambda: publish the top-N LoopScore CVEs as the dashboard's JSON.

Single responsibility — it builds the one small summary file the static dashboard
reads, and nothing else. It reads the per-CVE scored results the analyzer wrote to
the analysis bucket (analysis/<id>.json), ranks the top N by LoopScore over a
fixed lookback window, trims each to the three fields the bar chart needs
({cve, vendor, score}), and writes them to data/top10.json in the SITE bucket —
same-origin with index.html, so the browser fetches it with no CORS.

The rank/read helpers are shared with the ranking alert (ranking_handler) so the
two agree on "top N by LoopScore". The difference is the window: the alert ranks
the delta "since the last alert" (and can be sparse on a quiet window), whereas
this ranks a fixed DASHBOARD_LOOKBACK_HOURS so the chart always shows a full,
current top N. Runs hourly via EventBridge.

The object is written with Cache-Control: max-age=30 to match the dashboard HTML,
so a fresh publish shows on the site within 30s without a CloudFront invalidation.

Manual override (for testing):
  {"lookback_hours": N} -> rank the last N hours instead of the default window
"""

import json
import logging
from datetime import timedelta

import boto3

try:
    from config import Config
    from ranking_handler import _rank, _scored_since, _utcnow
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.ranking_handler import _rank, _scored_since, _utcnow

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)


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
    return {
        "cve": result.get("cve_id"),
        "vendor": _vendor(result),
        "score": result.get("loop_score"),
    }


def lambda_handler(event, context):
    event = event or {}
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    now = _utcnow()

    hours = float(event.get("lookback_hours") or Config.DASHBOARD_LOOKBACK_HOURS)
    cutoff = now - timedelta(hours=hours)

    results = _scored_since(s3, Config.OUTPUT_BUCKET, Config.OUTPUT_PREFIX, cutoff)
    ranked = _rank(results, Config.RANKING_TOP_N)
    chart = [_to_chart(r) for r in ranked]

    s3.put_object(
        Bucket=Config.SITE_BUCKET,
        Key=Config.DASHBOARD_KEY,
        Body=json.dumps(chart, indent=2),
        ContentType="application/json",
        CacheControl="max-age=30",
    )
    logger.info(
        "wrote %d CVEs to s3://%s/%s (%d scored in last %sh)",
        len(chart), Config.SITE_BUCKET, Config.DASHBOARD_KEY, len(results), hours,
    )
    return {
        "written": len(chart),
        "scored_in_window": len(results),
        "key": Config.DASHBOARD_KEY,
    }
