"""Ranking alert Lambda: email the top-N CVEs by LoopScore, three times a day.

Single responsibility — this Lambda only ranks already-scored CVEs and sends the
digest. It never scores anything (that's the analyzer) and never touches the raw
data bucket; it reads the per-CVE results the analyzer wrote to the analysis
bucket (analysis/<cve-id>.json) and publishes a text digest to SNS.

Window: "since the last alert". A marker object (Config.RANKING_STATE_KEY) in the
analysis bucket records when the previous alert ran; each run ranks only the CVEs
whose analysis object was written after that marker, so every send is fresh with
no repeats. The marker is advanced to the run's start time once the digest is
sent (or when there's nothing new). On the first run — no marker yet — it looks
back Config.RANKING_FIRST_RUN_LOOKBACK_HOURS so the inaugural alert isn't empty.

Fired by EventBridge Scheduler at 9am/1pm/5pm America/New_York (see
terraform/scheduler.tf) so the Eastern times hold across daylight saving.

Manual overrides (for testing):
  {"lookback_hours": N} -> ignore the marker, rank the last N hours instead
  {"dry_run": true}     -> build and return the digest WITHOUT publishing to SNS
                           or advancing the marker
"""

import json
import logging
from datetime import datetime, timedelta, timezone

import boto3

try:
    from config import Config
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)


def _utcnow():
    return datetime.now(timezone.utc)


def _load_marker(s3, bucket, key):
    """Return the last-alert datetime (UTC), or None if no marker exists yet."""
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
    except Exception as exc:  # NoSuchKey / 404 on first ever run
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code in ("NoSuchKey", "404") or exc.__class__.__name__ == "NoSuchKey":
            return None
        raise
    data = json.loads(resp["Body"].read())
    iso = data.get("last_alert_iso")
    return datetime.fromisoformat(iso) if iso else None


def _save_marker(s3, bucket, key, now, sent_count):
    """Advance the last-alert marker to `now`."""
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(
            {"last_alert_iso": now.isoformat(), "last_alert_count": sent_count},
            indent=2,
        ),
        ContentType="application/json",
    )


def _scored_since(s3, bucket, prefix, cutoff):
    """Load every analysis/<id>.json written at or after `cutoff` (UTC).

    S3 has no server-side LastModified filter, so we list the prefix and keep
    only the objects in the window, then fetch just those. The window is a few
    hours between alerts, so this is a small number of GETs.
    """
    results = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json"):
                continue
            if obj["LastModified"] < cutoff:
                continue
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            try:
                result = json.loads(body)
            except json.JSONDecodeError:
                logger.warning("skipping unparseable object %s", key)
                continue
            if isinstance(result, dict) and result.get("cve_id"):
                results.append(result)
    return results


def _rank(results, top_n):
    """Top-N results by LoopScore (highest first); unscored CVEs are excluded."""
    scored = [r for r in results if r.get("loop_score") is not None]
    scored.sort(key=lambda r: r["loop_score"], reverse=True)
    return scored[:top_n]


def _format_entry(i, r):
    """One CVE's block in the digest: score line, affected products, summary."""
    vendors = r.get("vendors") or []
    affects = ", ".join(vendors[:4]) + (" ..." if len(vendors) > 4 else "")
    lines = [
        f"{i:>2}. LoopScore {r['loop_score']:<5} [{r.get('priority', '?')}]  "
        f"{r['cve_id']}  (CVSS {r.get('cvss', '?')} {r.get('severity', '')})".rstrip(),
    ]
    if affects:
        lines.append(f"    Affects: {affects}")
    if r.get("summary"):
        lines.append(f"    {r['summary']}")
    return lines


def _build_message(ranked, total_new, cutoff, now):
    """Assemble the full email body."""
    header = [
        "CyberLoop — Top LoopScore Alert",
        "=" * 40,
        f"{total_new} newly-scored CVE(s) since the last alert.",
        f"Window: {cutoff.strftime('%Y-%m-%d %H:%M')} -> "
        f"{now.strftime('%Y-%m-%d %H:%M')} UTC",
        "",
    ]
    if len(ranked) < total_new:
        header.append(f"Showing the top {len(ranked)} by LoopScore:")
        header.append("")

    body = []
    for i, r in enumerate(ranked, 1):
        body.extend(_format_entry(i, r))
        body.append("")
    return "\n".join(header + body).rstrip() + "\n"


def lambda_handler(event, context):
    event = event or {}
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    now = _utcnow()

    # Window boundary: explicit override, else the persisted marker, else the
    # first-run look-back.
    if event.get("lookback_hours"):
        cutoff = now - timedelta(hours=float(event["lookback_hours"]))
    else:
        marker = _load_marker(s3, Config.OUTPUT_BUCKET, Config.RANKING_STATE_KEY)
        cutoff = marker or (now - timedelta(hours=Config.RANKING_FIRST_RUN_LOOKBACK_HOURS))

    results = _scored_since(s3, Config.OUTPUT_BUCKET, Config.OUTPUT_PREFIX, cutoff)
    ranked = _rank(results, Config.RANKING_TOP_N)
    logger.info(
        "window since %s: %d scored CVEs, sending top %d",
        cutoff.isoformat(), len(results), len(ranked),
    )

    dry_run = bool(event.get("dry_run"))
    body = _build_message(ranked, len(results), cutoff, now)

    if not ranked:
        # Nothing new to report. Still advance the marker (unless dry-run/override)
        # so the window doesn't keep growing.
        if not dry_run and not event.get("lookback_hours"):
            _save_marker(s3, Config.OUTPUT_BUCKET, Config.RANKING_STATE_KEY, now, 0)
        logger.info("no newly-scored CVEs in window; no alert sent")
        return {"sent": False, "new_scored": 0, "reason": "nothing new in window"}

    if dry_run:
        logger.info("dry_run: not publishing or advancing marker")
        return {"sent": False, "dry_run": True, "ranked": len(ranked), "body": body}

    sns = boto3.client("sns", region_name=Config.AWS_REGION)
    sns.publish(
        TopicArn=Config.SNS_TOPIC_ARN,
        Subject=f"CyberLoop Top {len(ranked)} LoopScore Alert",
        Message=body,
    )

    # Advance the marker only after a successful publish, so a send failure
    # replays the same window next run instead of dropping CVEs. Skip advancing
    # when a manual lookback_hours override was used.
    if not event.get("lookback_hours"):
        _save_marker(s3, Config.OUTPUT_BUCKET, Config.RANKING_STATE_KEY, now, len(ranked))

    result = {"sent": True, "new_scored": len(results), "ranked": len(ranked)}
    logger.info(json.dumps(result))
    return result
