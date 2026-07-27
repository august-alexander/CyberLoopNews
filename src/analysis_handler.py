"""Analysis Lambda: LoopScore CVEs and save the results to S3.

Writes analysis/<cve-id>.json to the per-environment analysis bucket
(OUTPUT_BUCKET), so outputs are always bound to the branch. Re-scoring the same
CVE overwrites its object (idempotent).

Each scored CVE is also mirrored into the CVE_TABLE DynamoDB read-model so the
site can Query it by day or vendor. That mirror is best-effort and derived: the
S3 object stays the record of truth, and the table is rebuildable from it.

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
import time
from decimal import Decimal

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


# Sort key for an UNSCORED CVE (no CVSS base score, so loop_score is null).
# DynamoDB drops an item from an index when its sort key is missing, so these
# need a real number to stay queryable; -1 sorts below every genuine score.
UNSCORED_SK = -1

# Filed under this when the CVE names no vendor, so vendor_key is never missing
# (same reason as UNSCORED_SK — a missing key attribute vanishes from by_vendor).
UNKNOWN_VENDOR = "unknown"

# CNA placeholders that mean "no vendor stated". They're spelled several ways in
# the affected[] data, so they collapse to one key rather than becoming a
# browsable "n/a" vendor on the site.
VENDOR_PLACEHOLDERS = {"", "n/a", "na", "none", "unknown"}

# Wall-clock held back at the end of a backfill run so it can return its resume
# marker instead of being killed mid-page by the Lambda timeout.
BACKFILL_RESERVE_SECONDS = 30


def _vendor_key(vendors):
    """Bare lowercased vendor name for the by_vendor index.

    analyzer._vendors() formats each entry as "vendor: product", so the first
    entry is a PAIR, not a vendor. Indexing on it directly made by_vendor
    useless — the key was "microsoft: microsoft edge (chromium-based)", so
    ?vendor=microsoft matched nothing. Take the part before the first colon.

    Parsed out of the string rather than read from a dedicated field on purpose:
    the backfill rebuilds from existing analysis/*.json, which only ever stored
    the formatted pair. A new field would leave every already-scored CVE wrong
    unless it were re-scored through Bedrock.

    _vendors() emits a bare product (no colon) when the CNA gave a product but
    no vendor. That's indistinguishable from a vendor here, but it doesn't occur
    in practice, and such an entry had no vendor to file under anyway.
    """
    if not vendors:
        return UNKNOWN_VENDOR
    vendor = (vendors[0] or "").split(":", 1)[0].strip().lower()
    return UNKNOWN_VENDOR if vendor in VENDOR_PLACEHOLDERS else vendor


def _item(result):
    """Build the DynamoDB item for one scored result.

    Everything is derived from `result` itself — the table is a projection of
    the analysis object, never a separate source of truth. Floats go through
    Decimal because DynamoDB rejects native floats.
    """
    published = result.get("published") or ""
    vendors = result.get("vendors") or []
    score = result.get("loop_score")

    item = json.loads(json.dumps(result), parse_float=Decimal)
    # published is ISO-8601 ("2026-07-27T14:03:00.000"), so the date is [:10].
    # If NVD gave no publish date, the attribute is OMITTED rather than set to
    # "": DynamoDB rejects an empty string on an index key, which would fail the
    # whole put. A missing key just drops the item from by_day, which is the
    # wanted behaviour — it's still in the base table and in by_vendor.
    if published[:10]:
        item["published_day"] = published[:10]
    # Primary vendor only, matching the dashboard's single-vendor bar chart.
    item["vendor_key"] = _vendor_key(vendors)
    item["score_sk"] = Decimal(str(score)) if score is not None else Decimal(UNSCORED_SK)
    return item


def _mirror(result):
    """Mirror one scored result into the CVE table, if one is configured.

    Best-effort on purpose: the S3 object is already written and is the record
    of truth, so a table hiccup must not fail the batch or re-pay Bedrock. Any
    item lost here comes back with an analyzer backfill.
    """
    if not Config.CVE_TABLE:
        return False
    try:
        table = boto3.resource("dynamodb", region_name=Config.AWS_REGION).Table(
            Config.CVE_TABLE
        )
        table.put_item(Item=_item(result))
        return True
    except Exception:
        logger.exception("dynamo mirror failed for %s (S3 copy is intact)", result["cve_id"])
        return False


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
    mirrored = _mirror(result)
    return {
        "cve_id": result["cve_id"],
        "loop_score": result["loop_score"],
        "priority": result["priority"],
        "key": key,
        "mirrored": mirrored,
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


def _run_backfill(s3, context, start_after=""):
    """Mirror already-scored analysis/ objects into the CVE table.

    This is the rebuild path the table's design depends on. It exists because
    the batch run can never populate the table retroactively: _already_scored()
    skips any CVE that has an analysis object, so everything scored before the
    table existed would otherwise never be mirrored.

    Cheap and safe to re-run — it reads existing S3 objects and puts them, with
    no Bedrock call and no re-scoring, and each put is idempotent on cve_id.

    Bounded by the Lambda's own remaining time (same pattern as the enricher).
    When the budget runs out it returns `next_start_after`; pass that back in to
    resume, since S3 lists keys lexicographically.
    """
    if not Config.CVE_TABLE:
        return {"error": "CVE_TABLE not configured; nothing to backfill into"}

    deadline = time.monotonic() + max(
        0, context.get_remaining_time_in_millis() / 1000.0 - BACKFILL_RESERVE_SECONDS
    )

    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(
        Bucket=Config.OUTPUT_BUCKET,
        Prefix=Config.OUTPUT_PREFIX,
        StartAfter=start_after or Config.OUTPUT_PREFIX,
    )

    mirrored = failed = 0
    last_key = start_after

    for page in pages:
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json"):
                continue
            if time.monotonic() >= deadline:
                logger.info("backfill: budget exhausted, resume after %s", last_key)
                return {
                    "mirrored": mirrored,
                    "failed": failed,
                    "next_start_after": last_key,
                    "done": False,
                }

            body = s3.get_object(Bucket=Config.OUTPUT_BUCKET, Key=key)["Body"].read()
            if _mirror(json.loads(body)):
                mirrored += 1
            else:
                failed += 1
            last_key = key

    logger.info("backfill complete: mirrored=%d failed=%d", mirrored, failed)
    return {"mirrored": mirrored, "failed": failed, "next_start_after": None, "done": True}


def lambda_handler(event, context):
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)

    # Rebuild the DynamoDB read-model from the analysis bucket. No Bedrock and
    # no re-scoring — needed once after the table is created, and any time the
    # table is dropped or drifts behind S3.
    if event.get("backfill"):
        return _run_backfill(s3, context, event.get("start_after", ""))

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
