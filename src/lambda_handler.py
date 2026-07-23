"""Fetcher Lambda: fetch newly-published CVEs and store them in S3.

Single responsibility — this Lambda only fetches and saves. It writes the raw
payload to raw/<timestamp>/cves.json and advances the last-fetch state marker.
It does NOT alert or report (the report Lambda owns outbound email), and it does
NOT enrich (the enricher Lambda owns the CVE.org vendor/product lookup).

Work per invocation is bounded by construction: at most MAX_WINDOWS_PER_RUN
windows of FETCH_WINDOW_HOURS each, so no upstream outage can grow the cost of a
single run. See lambda_handler() for why that matters.

Triggered hourly by EventBridge.
"""

import json
from datetime import datetime, timedelta, timezone

import boto3

# Support both the packaged Lambda layout (flat modules at the zip root) and
# local imports (from the src package).
try:
    from config import Config
    from fetcher import fetch_cves_by_pub_date
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.fetcher import fetch_cves_by_pub_date

# Timestamp convention for our own S3 keys + state file (matches test_nvd.py).
KEY_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"


def _utcnow():
    return datetime.now(timezone.utc)


def _load_state(s3, bucket, key):
    """Return the parsed state dict, or None if no state file exists yet."""
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        return json.loads(resp["Body"].read())
    except s3.exceptions.NoSuchKey:
        return None
    except Exception as exc:  # ClientError for missing key on some setups
        if getattr(exc, "response", {}).get("Error", {}).get("Code") in (
            "NoSuchKey",
            "404",
        ):
            return None
        raise


def _save_state(s3, bucket, key, now, new_count, cumulative):
    """Persist the last-fetch marker. Stores both the ISO value (to feed the
    next NVD query) and the %Y%m%d%H%M%S string (human-readable, matches keys).
    """
    state = {
        "last_fetch_iso": now.isoformat(),
        "last_fetch_timestamp": now.strftime(KEY_TIMESTAMP_FORMAT),
        "last_new_count": new_count,
        "cumulative_cve_count": cumulative,
    }
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(state, indent=2),
        ContentType="application/json",
    )
    return state


def _store_raw(s3, bucket, now, total_results, vulnerabilities):
    """Dump the fetched payload to raw/<timestamp>/cves.json (test convention)."""
    key = f"raw/{now.strftime(KEY_TIMESTAMP_FORMAT)}/cves.json"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(
            {"totalResults": total_results, "vulnerabilities": vulnerabilities},
            indent=2,
        ),
        ContentType="application/json",
    )
    return key


def lambda_handler(event, context):
    """Advance the ingest by up to MAX_WINDOWS_PER_RUN fixed-size windows.

    Each step covers exactly FETCH_WINDOW_HOURS and is committed independently:
    fetch -> write raw -> advance the state marker. That fixed size is the whole
    point. The previous version fetched `last_success -> now`, so any failure
    widened the next attempt, which made the retry more expensive than the thing
    that had just failed — a two-day outage in July 2026 wedged the fetcher
    permanently that way. With a fixed step, a failure costs the same to retry
    no matter how long we have been down: an outage makes us fall BEHIND, but it
    can never make a single invocation bigger. Backlog is drained a few windows
    at a time instead of attempted in one impossible gulp.
    """
    Config.validate()

    s3 = boto3.client("s3", region_name=Config.AWS_REGION)

    now = _utcnow()
    state = _load_state(s3, Config.S3_BUCKET, Config.STATE_KEY)

    if state and state.get("last_fetch_iso"):
        window_start = datetime.fromisoformat(state["last_fetch_iso"])
        cumulative = state.get("cumulative_cve_count", 0)
    else:
        # First run: bounded look-back so we don't pull the entire backlog.
        window_start = now - timedelta(hours=Config.LOOKBACK_HOURS)
        cumulative = 0

    step = timedelta(hours=Config.FETCH_WINDOW_HOURS)
    windows = []

    for _ in range(Config.MAX_WINDOWS_PER_RUN):
        if window_start >= now:
            break
        window_end = min(window_start + step, now)

        total_results, vulnerabilities = fetch_cves_by_pub_date(
            Config.NIST_API_BASE_URL, Config.NIST_API_KEY, window_start, window_end
        )

        # Commit BEFORE anything optional runs. The raw NVD payload is complete
        # and useful on its own; product enrichment is a separate concern and
        # now lives in its own Lambda (enrich_handler.py) precisely so it can
        # never again stand between a successful fetch and its durable write.
        raw_key = None
        if total_results > 0:
            raw_key = _store_raw(
                s3, Config.S3_BUCKET, window_end, total_results, vulnerabilities
            )

        cumulative += total_results
        _save_state(
            s3, Config.S3_BUCKET, Config.STATE_KEY, window_end, total_results, cumulative
        )

        windows.append(
            {
                "new_cve_count": total_results,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "raw_key": raw_key,
            }
        )
        window_start = window_end

    result = {
        "windows_processed": len(windows),
        "new_cve_count": sum(w["new_cve_count"] for w in windows),
        "caught_up": window_start >= now,
        "windows": windows,
    }
    print(json.dumps(result))
    return result
