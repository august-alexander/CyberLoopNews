"""Analysis Lambda: LoopScore CVEs and save the results to S3.

Writes analysis/<cve-id>.json to the per-environment analysis bucket
(OUTPUT_BUCKET), so outputs are always bound to the branch. Re-scoring the same
CVE overwrites its object (idempotent).

The handler runs in three modes depending on the event:
  {}  (or an EventBridge scheduled event)  -> BATCH: score every CVE in the
        latest scan that isn't already scored. This is what the hourly schedule
        fires; paired with the hourly fetcher, each run is a small delta.
  {"cve": <nvd cve dict>}                  -> score exactly that CVE (manual)
  {"random": true}                         -> score one random CVE from the
        latest scan (manual smoke test)

Already-scored CVEs are skipped in batch mode (checked via HeadObject) so a
re-run never re-pays Bedrock, and ANALYSIS_MAX_PER_RUN caps how many are scored
per invocation so a burst can't run past the Lambda timeout — leftovers are
picked up next run.
"""

import json
import logging
import random

import boto3

try:
    from config import Config
    from analyzer import score_cve
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.analyzer import score_cve

# INFO-level logging so every scored CVE is traceable in CloudWatch. Silence
# botocore's own INFO chatter so our records stay readable.
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)

# Raw scans the fetcher writes: raw/<timestamp>/cves.json. Timestamped keys sort
# lexicographically, so the largest matching key is the most recent scan.
RAW_PREFIX = "raw/"


def _latest_scan_key(s3, bucket):
    """Return the newest raw/<ts>/cves.json key, or None if there are no scans."""
    latest = None
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=RAW_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/cves.json") and (latest is None or key > latest):
                latest = key
    return latest


def _random_cve(s3):
    """Pick one random CVE from the latest scan in the data bucket.

    Returns (cve_dict, scan_key). Either may be None if no scan/CVE is available.
    """
    key = _latest_scan_key(s3, Config.S3_BUCKET)
    if key is None:
        return None, None
    payload = json.loads(s3.get_object(Bucket=Config.S3_BUCKET, Key=key)["Body"].read())
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return None, key
    return random.choice(vulns).get("cve"), key


def _save(s3, result):
    """Write one scored result to analysis/<cve-id>.json; return the S3 key."""
    key = f"{Config.OUTPUT_PREFIX}{result['cve_id']}.json"
    s3.put_object(
        Bucket=Config.OUTPUT_BUCKET,
        Key=key,
        Body=json.dumps(result, indent=2),
        ContentType="application/json",
    )
    return key


def _already_scored(s3, cve_id):
    """True if analysis/<cve-id>.json already exists in the output bucket."""
    key = f"{Config.OUTPUT_PREFIX}{cve_id}.json"
    try:
        s3.head_object(Bucket=Config.OUTPUT_BUCKET, Key=key)
        return True
    except Exception:
        return False


def _score_one(s3, cve):
    """Score a single CVE, save it, and return a compact summary."""
    result = score_cve(cve)
    key = _save(s3, result)
    logger.info("saved %s -> s3://%s/%s", result["cve_id"], Config.OUTPUT_BUCKET, key)
    return {
        "cve_id": result["cve_id"],
        "loop_score": result["loop_score"],
        "priority": result["priority"],
        "key": key,
    }


def _run_batch(s3):
    """Score every not-yet-scored CVE in the latest scan (up to the per-run cap)."""
    scan_key = _latest_scan_key(s3, Config.S3_BUCKET)
    if scan_key is None:
        logger.warning("batch: no scan found in %s", Config.S3_BUCKET)
        return {"scored": 0, "reason": "no scan in S3"}

    payload = json.loads(s3.get_object(Bucket=Config.S3_BUCKET, Key=scan_key)["Body"].read())
    vulns = payload.get("vulnerabilities", [])
    logger.info("batch: %d CVEs in %s", len(vulns), scan_key)

    scored = skipped = 0
    for v in vulns:
        cve = v.get("cve")
        if not cve or "id" not in cve:
            continue
        if _already_scored(s3, cve["id"]):
            skipped += 1
            continue
        if scored >= Config.ANALYSIS_MAX_PER_RUN:
            logger.info(
                "batch: hit ANALYSIS_MAX_PER_RUN=%d; remaining CVEs score next run",
                Config.ANALYSIS_MAX_PER_RUN,
            )
            break
        _score_one(s3, cve)
        scored += 1

    logger.info("batch done from %s: scored=%d skipped=%d", scan_key, scored, skipped)
    return {"scan_key": scan_key, "total": len(vulns), "scored": scored, "skipped": skipped}


def lambda_handler(event, context):
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)

    # Manual: score exactly this CVE.
    if event.get("cve"):
        return _score_one(s3, event["cve"])

    # Manual smoke test: score one random CVE from the latest scan.
    if event.get("random"):
        cve, scan_key = _random_cve(s3)
        if not cve:
            return {"error": "no scan available for random pick"}
        logger.info("random pick %s from %s", cve.get("id"), scan_key)
        return _score_one(s3, cve)

    # Default (hourly EventBridge schedule / {}): score the whole latest scan.
    return _run_batch(s3)
