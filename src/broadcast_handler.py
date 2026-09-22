"""Broadcast Lambda: gather the day's material, have Bedrock write the script,
email it.

Single responsibility — it assembles source material and sends the finished
script. It scores nothing (that's the analyzer) and fetches nothing from the
outside world; every input is already in S3 by the time this runs.

Material comes from two places the pipeline already fills:
  - scored CVEs      analysis/<cve-id>.json in the ANALYSIS bucket
  - breach filings   edgar/<ts>/filings.json and edgar6k/<ts>/filings.json in
                     the DATA bucket

Window: everything scored since the previous edition, the same "since last
time" marker pattern the ranking alert uses (its own marker object,
BROADCAST_STATE_KEY). So the 9am show covers 1pm yesterday -> 9am and the 1pm
show covers 9am -> 1pm, and nothing is reported twice. A quiet four hours makes
a short midday deck, which is better than repeating the morning's. The very
first run (no marker yet) looks back BROADCAST_LOOKBACK_HOURS.

Fired by EventBridge Scheduler at 9am and 1pm America/New_York, one schedule per
slot, each passing its own {"slot": ...} input (see terraform/scheduler.tf). The
slot arrives in the event rather than being derived from the clock here, so the
Lambda never has to guess which edition it is.

Manual overrides (for testing):
  {"slot": "morning"|"midday"} -> which edition to write (default: morning)
  {"lookback_hours": N}        -> gather the last N hours instead (marker untouched)
  {"dry_run": true}            -> return the script WITHOUT emailing it (marker untouched)
"""

import json
import logging
from datetime import timedelta

import boto3

try:
    from config import Config
    from broadcast import trim_cve, trim_filing, write_script
    from ranking_handler import _load_marker, _rank, _save_marker, _scored_since, _utcnow
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.broadcast import trim_cve, trim_filing, write_script
    from src.ranking_handler import _load_marker, _rank, _save_marker, _scored_since, _utcnow

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


def _gather(s3, slot, cutoff, now):
    """Assemble everything the writer needs for one broadcast."""
    results = _scored_since(s3, Config.OUTPUT_BUCKET, Config.OUTPUT_PREFIX, cutoff)
    ranked = _rank(results, Config.BROADCAST_TOP_N)

    return {
        "slot": slot,
        "date": now.strftime("%Y-%m-%d"),
        "window_start": cutoff.strftime("%Y-%m-%d %H:%M UTC"),
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

    # Window boundary: explicit override, else the persisted marker, else the
    # first-run look-back.
    if event.get("lookback_hours"):
        cutoff = now - timedelta(hours=float(event["lookback_hours"]))
    else:
        marker = _load_marker(s3, Config.OUTPUT_BUCKET, Config.BROADCAST_STATE_KEY)
        cutoff = marker or (now - timedelta(hours=Config.BROADCAST_LOOKBACK_HOURS))

    material = _gather(s3, slot, cutoff, now)
    logger.info(
        "%s edition: %d CVEs on the deck (%d scored since %s), %d 8-K + %d 6-K filings",
        slot, len(material["cves"]), material["scored_in_window"], cutoff.isoformat(),
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
    if not event.get("lookback_hours"):
        _save_marker(s3, Config.OUTPUT_BUCKET, Config.BROADCAST_STATE_KEY, now, len(material["cves"]))

    result = {
        "sent": True,
        "slot": slot,
        "cves_on_deck": len(material["cves"]),
        "filings": len(material["filings_8k"]) + len(material["filings_6k"]),
        "script_chars": len(script),
    }
    logger.info(json.dumps(result))
    return result
