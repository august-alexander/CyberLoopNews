"""EDGAR 6-K fetcher Lambda: fetch recent 6-K cybersecurity incident disclosures
(foreign private issuers) and store them in S3.

Single responsibility — fetch and save only. Writes the raw payload to
edgar6k/<timestamp>/filings.json. It does NOT report; the reporter Lambda merges
this with the CVE and 8-K data into one daily email.

Triggered daily by EventBridge, before the reporter runs.
"""

import json
from datetime import datetime, timedelta, timezone

import boto3

# Support both the packaged Lambda layout (flat modules at the zip root) and
# local imports (from the src package).
try:
    from config import Config
    from edgar_6k_fetcher import fetch_incident_filings
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.edgar_6k_fetcher import fetch_incident_filings

# Same timestamp convention as the CVE and 8-K fetchers' S3 keys.
KEY_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"


def _utcnow():
    return datetime.now(timezone.utc)


def _store(s3, bucket, now, total, filings):
    """Dump the fetched filings to edgar6k/<timestamp>/filings.json."""
    key = f"{Config.EDGAR_6K_PREFIX}{now.strftime(KEY_TIMESTAMP_FORMAT)}/filings.json"
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
    start = now - timedelta(days=Config.EDGAR_LOOKBACK_DAYS)

    total, filings = fetch_incident_filings(
        Config.EDGAR_FTS_URL, Config.EDGAR_USER_AGENT, start, now
    )

    key = _store(s3, Config.S3_BUCKET, now, total, filings)

    result = {
        "filing_count": len(filings),
        "window_start": start.isoformat(),
        "window_end": now.isoformat(),
        "edgar_6k_key": key,
    }
    print(json.dumps(result))
    return result
