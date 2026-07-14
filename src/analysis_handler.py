"""Analysis Lambda: LoopScore a single CVE and save the result to S3.

Single responsibility — one CVE per invocation. The event carries one NVD cve
dict (event['cve'], exactly the shape found under vulnerabilities[].cve in a raw
scan). This handler scores it and writes analysis/<cve-id>.json to the
per-environment analysis bucket (OUTPUT_BUCKET), so outputs are always bound to
the branch. Re-scoring the same CVE overwrites its object (idempotent).

Triggering (per-CVE fan-out via SQS vs a scheduled orchestrator) is deliberately
left to the next increment — this handler is trigger-agnostic. It can be driven
by a console test event two ways:
  {"cve": <nvd cve dict>}  -> score exactly that CVE
  {"random": true}         -> pick a random CVE from the latest scan in S3
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


def lambda_handler(event, context):
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)

    cve = event.get("cve")
    # {"random": true} -> grab a random CVE from the latest scan in S3.
    if not cve and event.get("random"):
        cve, scan_key = _random_cve(s3)
        if cve:
            logger.info("random pick %s from %s", cve.get("id"), scan_key)

    if not cve:
        logger.error("event missing 'cve' and no scan available for random pick")
        return {"error": "provide {'cve': <nvd cve>} or {'random': true} (needs a scan in S3)"}

    result = score_cve(cve)
    key = _save(s3, result)

    logger.info("saved %s -> s3://%s/%s", result["cve_id"], Config.OUTPUT_BUCKET, key)
    return {
        "cve_id": result["cve_id"],
        "loop_score": result["loop_score"],
        "priority": result["priority"],
        "key": key,
    }
