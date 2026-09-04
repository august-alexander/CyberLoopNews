"""EDGAR fetcher Lambda: fetch recent 8-K Item 1.05 cyber-incident filings and
store them in S3.

Single responsibility — fetch and save only. Writes the raw payload to
edgar/<timestamp>/filings.json. It does NOT report; the reporter Lambda merges
this with the CVE data into one daily email.

Triggered daily by EventBridge, before the reporter runs.
"""

import json
from datetime import datetime, timedelta, timezone

import boto3

# Support both the packaged Lambda layout (flat modules at the zip root) and
# local imports (from the src package).
try:
    from config import Config
    from edgar_fetcher import fetch_incident_filings
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.edgar_fetcher import fetch_incident_filings

# Same timestamp convention as the CVE fetcher's S3 keys.
KEY_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_day(value):
    """A 'YYYY-MM-DD' string as a UTC datetime, or None if absent."""
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def _window(event, now):
    """The [start, end] window to fetch.

    Default is the daily lookback, which is what the schedule fires. Explicit
    dates make the same Lambda a one-off BACKFILL — the reason no separate
    backfill job exists:

      {"start": "2023-12-01"}                      -> that date through now
      {"start": "2001-01-01", "end": "2024-01-01"} -> an explicit slice

    The fetcher pages, so a multi-year window is a normal run rather than a
    special mode, and the dump it writes is picked up by the dashboard publisher
    exactly like any daily dump.
    """
    end = _parse_day(event.get("end")) or now
    start = _parse_day(event.get("start")) or (
        end - timedelta(days=Config.EDGAR_LOOKBACK_DAYS)
    )
    return start, end



def _store(s3, bucket, now, total, filings):
    """Dump the fetched filings to edgar/<timestamp>/filings.json."""
    key = f"{Config.EDGAR_PREFIX}{now.strftime(KEY_TIMESTAMP_FORMAT)}/filings.json"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps({"totalResults": total, "filings": filings}, indent=2),
        ContentType="application/json",
    )
    return key


def lambda_handler(event, context):
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)

    now = _utcnow()
    start, end = _window(event or {}, now)

    total, filings = fetch_incident_filings(
        Config.EDGAR_FTS_URL, Config.EDGAR_USER_AGENT, start, end
    )

    key = _store(s3, Config.S3_BUCKET, now, total, filings)

    result = {
        "filing_count": len(filings),
        "total_hits": total,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "edgar_key": key,
    }
    print(json.dumps(result))
    return result
