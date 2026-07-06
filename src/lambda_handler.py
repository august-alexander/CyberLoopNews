"""Lambda entry point: fetch newly-published CVEs, store them, and alert on new.

Triggered daily by EventBridge. Sends exactly ONE summary SMS per run (only
when new CVEs are found) so the phone never gets flooded regardless of volume.
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


def _send_alert(sns, topic_arn, new_count):
    """Publish a single count-only SMS: 'something new appeared'."""
    message = f"CyberLoop: {new_count} new CVE(s) detected since last check."
    sns.publish(
        TopicArn=topic_arn,
        Message=message,
        Subject="CyberLoop CVE Alert",
        MessageAttributes={
            # Transactional = higher delivery priority/reliability for alerts.
            "AWS.SNS.SMS.SMSType": {
                "DataType": "String",
                "StringValue": "Transactional",
            }
        },
    )
    return message


def lambda_handler(event, context):
    Config.validate()

    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    sns = boto3.client("sns", region_name=Config.AWS_REGION)

    now = _utcnow()
    state = _load_state(s3, Config.S3_BUCKET, Config.STATE_KEY)

    if state and state.get("last_fetch_iso"):
        window_start = datetime.fromisoformat(state["last_fetch_iso"])
        cumulative = state.get("cumulative_cve_count", 0)
    else:
        # First run: bounded look-back so we don't pull the entire backlog.
        window_start = now - timedelta(hours=Config.LOOKBACK_HOURS)
        cumulative = 0

    total_results, vulnerabilities = fetch_cves_by_pub_date(
        Config.NIST_API_BASE_URL, Config.NIST_API_KEY, window_start, now
    )

    result = {
        "new_cve_count": total_results,
        "window_start": window_start.isoformat(),
        "window_end": now.isoformat(),
        "alerted": False,
        "raw_key": None,
    }

    if total_results > 0:
        result["raw_key"] = _store_raw(
            s3, Config.S3_BUCKET, now, total_results, vulnerabilities
        )

        if Config.SNS_TOPIC_ARN:
            result["message"] = _send_alert(sns, Config.SNS_TOPIC_ARN, total_results)
            result["alerted"] = True

    cumulative += total_results
    _save_state(s3, Config.S3_BUCKET, Config.STATE_KEY, now, total_results, cumulative)

    print(json.dumps(result))
    return result
