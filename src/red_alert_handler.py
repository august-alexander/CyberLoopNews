"""Red-alert Lambda: email the instant a CVE is scored at/above a critical LoopScore.

The analyzer writes one scored result per CVE (analysis/<cve-id>.json). This
Lambda is triggered by the S3 PutObject event for each of those writes: it reads
that single object and, if its LoopScore is at or above Config.RED_ALERT_THRESHOLD
(default 85), emails an immediate alert via SNS. A score that high is rare and
serious enough to warrant its own alert rather than waiting for the thrice-daily
ranking digest.

Event-driven by design — no schedule, no scan, no state marker. The analyzer
writes each CVE's object exactly once (it HeadObject-skips already-scored CVEs),
so each object fires exactly one event, so each CVE is evaluated once and can
email at most once. Dedup is a property of the trigger, not code we maintain.

This Lambda never scores anything and never touches the raw data bucket; it only
reads the scored object named in the event and publishes to SNS.

Manual overrides (for testing, no S3 event needed):
  {"key": "analysis/CVE-2025-1234.json"}  -> evaluate that object in OUTPUT_BUCKET
  {"dry_run": true}                       -> evaluate but do NOT publish to SNS
"""

import json
import logging
import urllib.parse

import boto3

try:
    from config import Config
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)


def _targets(event):
    """Yield (bucket, key) pairs to evaluate from either an S3 event or a manual
    {"key": ...} test invoke."""
    if event.get("key"):  # manual test: key in the analysis (OUTPUT) bucket
        yield Config.OUTPUT_BUCKET, event["key"]
        return
    for record in event.get("Records", []):
        s3 = record.get("s3", {})
        bucket = s3.get("bucket", {}).get("name")
        raw_key = s3.get("object", {}).get("key")
        if not bucket or not raw_key:
            continue
        # S3 URL-encodes the key in event notifications (e.g. spaces -> '+').
        yield bucket, urllib.parse.unquote_plus(raw_key)


def _load(s3, bucket, key):
    """Read and parse one scored analysis object; None if missing/unparseable."""
    try:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception:
        logger.warning("could not read s3://%s/%s", bucket, key)
        return None
    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        logger.warning("skipping unparseable object %s", key)
        return None
    return result if isinstance(result, dict) and result.get("cve_id") else None


def _build_message(r, threshold):
    """Assemble the alert email body for one critical CVE."""
    vendors = r.get("vendors") or []
    affects = ", ".join(vendors[:4]) + (" ..." if len(vendors) > 4 else "")
    lines = [
        f"CyberLoop \U0001F6A8 RED ALERT — LoopScore >= {threshold}",
        "=" * 48,
        f"LoopScore {r['loop_score']} [{r.get('priority', '?')}]  "
        f"{r['cve_id']}  (CVSS {r.get('cvss', '?')} {r.get('severity', '')})".rstrip(),
    ]
    if affects:
        lines.append(f"Affects: {affects}")
    if r.get("summary"):
        lines.append("")
        lines.append(r["summary"])
    return "\n".join(lines).rstrip() + "\n"


def _alert(sns, r, threshold):
    """Publish one red-alert email for a critical CVE."""
    sns.publish(
        TopicArn=Config.SNS_TOPIC_ARN,
        Subject=f"\U0001F6A8 CyberLoop RED ALERT — {r['cve_id']} LoopScore {r['loop_score']}",
        Message=_build_message(r, threshold),
    )


def lambda_handler(event, context):
    event = event or {}
    threshold = Config.RED_ALERT_THRESHOLD
    dry_run = bool(event.get("dry_run"))
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    sns = boto3.client("sns", region_name=Config.AWS_REGION)

    evaluated = alerted = 0
    for bucket, key in _targets(event):
        result = _load(s3, bucket, key)
        if result is None:
            continue
        evaluated += 1
        score = result.get("loop_score")
        cve_id = result.get("cve_id")

        if score is None or score < threshold:
            logger.info("%s loop_score=%s below threshold %s; no alert", cve_id, score, threshold)
            continue

        logger.info("%s loop_score=%s >= %s -> RED ALERT", cve_id, score, threshold)
        if not dry_run:
            _alert(sns, result, threshold)
        alerted += 1

    logger.info(json.dumps({"evaluated": evaluated, "alerted": alerted, "dry_run": dry_run}))
    return {"evaluated": evaluated, "alerted": alerted, "dry_run": dry_run}
