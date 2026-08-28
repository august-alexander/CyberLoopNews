"""Broadcast Lambda: gather the day's material, have Bedrock write the script,
email it.

Single responsibility — it assembles source material and sends the finished
script. It scores nothing (that's the analyzer) and fetches nothing from the
outside world; every input is already in S3 by the time this runs.

Material comes from two places the pipeline already fills:
  - scored CVEs      analysis/<cve-id>.json in the ANALYSIS bucket
  - breach filings   edgar/<ts>/filings.json and edgar6k/<ts>/filings.json in
                     the DATA bucket

Window: a fixed BROADCAST_LOOKBACK_HOURS, deliberately NOT the ranking alert's
"since the last alert" marker. The two daily slots are only four hours apart, so
a delta window would hand the midday show a nearly empty deck. A fixed window
means every broadcast has a full deck; the resulting overlap between the 9am and
1pm editions is handled in the script itself (see SLOT_FRAMING in broadcast.py),
not by narrowing the data.

Fired by EventBridge Scheduler at 9am and 1pm America/New_York, one schedule per
slot, each passing its own {"slot": ...} input (see terraform/scheduler.tf). The
slot arrives in the event rather than being derived from the clock here, so the
Lambda never has to guess which edition it is.

Manual overrides (for testing):
  {"slot": "morning"|"midday"} -> which edition to write (default: morning)
  {"lookback_hours": N}        -> gather the last N hours instead
  {"dry_run": true}            -> return the script WITHOUT emailing it
"""

import json
import logging
from datetime import timedelta

import boto3

try:
    from config import Config
    from broadcast import trim_cve, trim_filing, write_script
    from ranking_handler import _rank, _scored_since, _utcnow
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.broadcast import trim_cve, trim_filing, write_script
    from src.ranking_handler import _rank, _scored_since, _utcnow

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)

DEFAULT_SLOT = "morning"

# Human-facing edition names, used in the email subject only.
SLOT_LABELS = {"morning": "Morning Edition", "midday": "Midday Edition"}


def _latest_key(s3, bucket, prefix, suffix):
    """Return the newest key under `prefix` ending in `suffix`, or None.

    The EDGAR fetchers write timestamped keys (edgar/<ts>/filings.json), so the
    lexicographically largest matching key is also the most recent. Same
    convention the reporter uses.
    """
    latest = None
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(suffix) and (latest is None or key > latest):
                latest = key
    return latest


def _latest_filings(s3, bucket, prefix):
    """Load the most recent EDGAR dump under `prefix`, newest filing first.

    Best-effort: a missing or unparseable dump yields an empty list rather than
    failing the broadcast. A quiet breach desk is a normal show; no show at all
    because the 6-K fetcher hasn't run yet is not.
    """
    key = _latest_key(s3, bucket, prefix, "/filings.json")
    if key is None:
        return []
    try:
        payload = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
    except Exception:
        logger.exception("could not read EDGAR dump %s; breach desk will be empty", key)
        return []
    filings = payload.get("filings") or []
    filings.sort(key=lambda f: f.get("file_date") or "", reverse=True)
    return [trim_filing(f) for f in filings]


def _gather(s3, slot, hours, now):
    """Assemble everything the writer needs for one broadcast."""
    cutoff = now - timedelta(hours=hours)

    results = _scored_since(s3, Config.OUTPUT_BUCKET, Config.OUTPUT_PREFIX, cutoff)
    ranked = _rank(results, Config.BROADCAST_TOP_N)

    return {
        "slot": slot,
        "date": now.strftime("%Y-%m-%d"),
        "lookback_hours": hours,
        "cves": [trim_cve(r) for r in ranked],
        "filings_8k": _latest_filings(s3, Config.S3_BUCKET, Config.EDGAR_PREFIX),
        "filings_6k": _latest_filings(s3, Config.S3_BUCKET, Config.EDGAR_6K_PREFIX),
        "scored_in_window": len(results),
    }


def lambda_handler(event, context):
    event = event or {}
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    now = _utcnow()

    slot = event.get("slot") or DEFAULT_SLOT
    hours = float(event.get("lookback_hours") or Config.BROADCAST_LOOKBACK_HOURS)

    material = _gather(s3, slot, hours, now)
    logger.info(
        "%s edition: %d CVEs on the deck (%d scored in %sh), %d 8-K + %d 6-K filings",
        slot, len(material["cves"]), material["scored_in_window"], hours,
        len(material["filings_8k"]), len(material["filings_6k"]),
    )

    script = write_script(material)

    if event.get("dry_run"):
        logger.info("dry_run: script written but not emailed")
        return {"sent": False, "dry_run": True, "slot": slot, "script": script}

    sns = boto3.client("sns", region_name=Config.AWS_REGION)
    sns.publish(
        TopicArn=Config.SNS_TOPIC_ARN,
        Subject=f"CyberLoop Broadcast — {SLOT_LABELS.get(slot, slot)}",
        Message=script,
    )

    result = {
        "sent": True,
        "slot": slot,
        "cves_on_deck": len(material["cves"]),
        "filings": len(material["filings_8k"]) + len(material["filings_6k"]),
        "script_chars": len(script),
    }
    logger.info(json.dumps(result))
    return result
