"""Analysis Lambda: LoopScore a single CVE and save the result to S3.

Single responsibility — one CVE per invocation. The event carries one NVD cve
dict (event['cve'], exactly the shape found under vulnerabilities[].cve in a raw
scan). This handler scores it and writes analysis/<cve-id>.json to the
per-environment analysis bucket (OUTPUT_BUCKET), so outputs are always bound to
the branch. Re-scoring the same CVE overwrites its object (idempotent).

Triggering (per-CVE fan-out via SQS vs a scheduled orchestrator) is deliberately
left to the next increment — this handler is trigger-agnostic. For now it can be
driven by a console test event: {"cve": <nvd cve dict>}.
"""

import json
import logging

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
    cve = event.get("cve")
    if not cve:
        logger.error("event missing 'cve'")
        return {"error": "event missing 'cve'"}

    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    result = score_cve(cve)
    key = _save(s3, result)

    logger.info("saved %s -> s3://%s/%s", result["cve_id"], Config.OUTPUT_BUCKET, key)
    return {
        "cve_id": result["cve_id"],
        "loop_score": result["loop_score"],
        "priority": result["priority"],
        "key": key,
    }
