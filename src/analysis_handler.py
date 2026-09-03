"""Analysis Lambda: LoopScore CVEs and save the results to S3.

Writes analysis/<cve-id>.json to the per-environment analysis bucket
(OUTPUT_BUCKET), so outputs are always bound to the branch. Re-scoring the same
CVE overwrites its object (idempotent).

Each scored CVE is also mirrored into the CVE_TABLE DynamoDB read-model so the
site can Query it by day or vendor, and into TERMS_TABLE as one row per search
term (see terms.py) so it can also be found by product name. Both mirrors are
best-effort and derived: the S3 object stays the record of truth, and both
tables are rebuildable from it with `{"backfill": true}`.

The handler runs in three modes depending on the event:
  {}  (or an EventBridge scheduled event)  -> BATCH: score every CVE in the
        latest scan that isn't already scored. This is what the hourly schedule
        fires; paired with the hourly fetcher, each run is a small delta.
  {"cve": <nvd cve dict>}                  -> score exactly that CVE (manual)
  {"random": true}                         -> score one random CVE from the
        latest scan (manual smoke test)
  {"rescore": true, "lookback_days": N}    -> RESCORE SWEEP: find CVEs we hold
        as UNSCORED that NVD has since given a CVSS base score, and score them.

Already-scored CVEs are skipped in batch mode (checked via HeadObject) so a
re-run never re-pays Bedrock, and ANALYSIS_MAX_PER_RUN caps how many are scored
per invocation so a burst can't run past the Lambda timeout — leftovers are
picked up next run.

That HeadObject skip is also why the rescore sweep has to exist. A CVE published
before NVD finishes its analysis has no CVSS base score, so score_cve() files it
as UNSCORED — but it still writes analysis/<id>.json, which makes _already_scored
true forever after. When NVD later assigns the score, batch mode skips the CVE
and the UNSCORED verdict is permanent. The sweep is the only path back.
"""

import json
import logging
import random
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

try:
    from config import Config
    from analyzer import compute_loop_score, score_cve, trim, _priority_for
    from fetcher import fetch_cves_by_last_mod
    from terms import terms_for
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.analyzer import compute_loop_score, score_cve, trim, _priority_for
    from src.fetcher import fetch_cves_by_last_mod
    from src.terms import terms_for

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


# The fields a term row carries. It answers a search on its own — the panel
# renders straight from it — so it holds what search_handler.DISPLAY_FIELDS
# needs and nothing more. Deliberately NOT the whole item: there is one row per
# term per CVE, so the model's prevalence/exploitability rationales would be
# copied a dozen times over for data the site never shows.
TERM_ROW_FIELDS = (
    "cve_id",
    "vendors",
    "loop_score",
    "priority",
    "severity",
    "cvss",
    "published",
    "summary",
)


def _term_rows(result):
    """One row per search term for this CVE: {term, cve_id, score_sk, ...fields}.

    Keyed (term, cve_id) rather than by score, so a rescore OVERWRITES the row it
    wrote last time. Keying on the score would leave the old row behind at the
    old score every time a CVE is rescored, and the site would show it twice.
    Ordering is the by_score LSI's job instead.
    """
    score = result.get("loop_score")
    base = {k: result.get(k) for k in TERM_ROW_FIELDS if result.get(k) is not None}
    base = json.loads(json.dumps(base), parse_float=Decimal)
    base["score_sk"] = Decimal(str(score)) if score is not None else Decimal(UNSCORED_SK)
    return [dict(base, term=term) for term in terms_for(result)]


def _mirror_terms(result):
    """Write this CVE's search-term rows, if a terms table is configured.

    Best-effort like the main mirror below, and for the same reason. Batched so a
    dozen terms cost one request.
    """
    if not Config.TERMS_TABLE:
        return 0
    rows = _term_rows(result)
    if not rows:
        return 0
    try:
        table = boto3.resource("dynamodb", region_name=Config.AWS_REGION).Table(
            Config.TERMS_TABLE
        )
        with table.batch_writer() as batch:
            for row in rows:
                batch.put_item(Item=row)
        return len(rows)
    except Exception:
        logger.exception("term mirror failed for %s (S3 copy is intact)", result["cve_id"])
        return 0


def _mirror(result):
    """Mirror one scored result into the CVE table, if one is configured.

    Best-effort on purpose: the S3 object is already written and is the record
    of truth, so a table hiccup must not fail the batch or re-pay Bedrock. Any
    item lost here comes back with an analyzer backfill.

    The search-term rows ride along here so every write path — batch, manual,
    rescore, backfill — keeps them in step with the item they describe.
    """
    if not Config.CVE_TABLE:
        return False
    try:
        table = boto3.resource("dynamodb", region_name=Config.AWS_REGION).Table(
            Config.CVE_TABLE
        )
        table.put_item(Item=_item(result))
    except Exception:
        logger.exception("dynamo mirror failed for %s (S3 copy is intact)", result["cve_id"])
        return False
    _mirror_terms(result)
    return True


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
    """Mirror already-scored analysis/ objects into the CVE and terms tables.

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


# NVD rejects a lastMod window wider than 120 days, so the sweep's lookback is
# clamped to it. A longer backfill has to be run as several invocations.
NVD_LASTMOD_MAX_DAYS = 120


def _utcnow():
    return datetime.now(timezone.utc)


def _unscored_ids(days_back):
    """The set of cve_ids we currently hold as UNSCORED, from the by_day index.

    Built from DynamoDB rather than by listing the analysis bucket because
    score_sk == -1 is an exact key condition: each day is one small Query
    returning ONLY the unscored rows, instead of a GetObject per CVE we hold.

    This set is what keeps the sweep cheap. NVD's lastMod window returns every
    CVE modified recently — tens of thousands — and the overwhelming majority
    are ones we either don't hold or already scored. Intersecting in memory
    against this set means S3 is touched only for genuine candidates.
    """
    table = boto3.resource("dynamodb", region_name=Config.AWS_REGION).Table(
        Config.CVE_TABLE
    )
    now = _utcnow()
    ids = set()
    for d in range(days_back):
        day = (now - timedelta(days=d)).strftime("%Y-%m-%d")
        cond = Key("published_day").eq(day) & Key("score_sk").eq(Decimal(UNSCORED_SK))
        start_key = None
        while True:
            kwargs = {
                "IndexName": "by_day",
                "KeyConditionExpression": cond,
                "ProjectionExpression": "cve_id",
            }
            if start_key:
                kwargs["ExclusiveStartKey"] = start_key
            resp = table.query(**kwargs)
            ids.update(it["cve_id"] for it in resp.get("Items", []) if it.get("cve_id"))
            start_key = resp.get("LastEvaluatedKey")
            if not start_key:
                break
    return ids


def _load_analysis(s3, cve_id):
    """Read back analysis/<cve-id>.json, or None if it isn't there."""
    key = f"{Config.OUTPUT_PREFIX}{cve_id}.json"
    try:
        return json.loads(s3.get_object(Bucket=Config.OUTPUT_BUCKET, Key=key)["Body"].read())
    except Exception:
        logger.warning("rescore: could not read %s", key)
        return None


def _rescore(existing, cve):
    """Recompute an UNSCORED result now that NVD has published a CVSS.

    No Bedrock call: score_cve() only returns UNSCORED when the CVSS was
    missing, which happens AFTER the model judgment succeeded, so the stored
    object already carries prevalence and exploitability. Those are properties of
    the vulnerability, not of the CVSS — the only missing input was the base
    score. Re-asking the model would change nothing and cost per CVE.

    Returns the updated result, or None if this CVE isn't actually rescorable
    (still no CVSS upstream, or no stored judgment to reuse).
    """
    trimmed = trim(cve)
    cvss = trimmed.get("score")
    if cvss is None:
        return None  # modified for some other reason; still unanalyzed

    prevalence = existing.get("prevalence") or {}
    exploitability = existing.get("exploitability") or {}
    p, e = prevalence.get("value"), exploitability.get("value")
    if p is None or e is None:
        return None  # nothing to reuse — caller falls back to a full re-score

    loop_score = compute_loop_score(cvss, p, e)
    result = dict(existing)
    result.update(
        cvss=cvss,
        severity=trimmed.get("severity"),
        loop_score=loop_score,
        priority=_priority_for(loop_score),
        # NVD populates CPE data during the same analysis pass that assigns the
        # CVSS, so the fresh vendor list is usually better than the one captured
        # when the CVE was still unanalyzed. Keep the old one if it came back empty.
        vendors=trimmed.get("vendors") or existing.get("vendors"),
        rescored_at=_utcnow().isoformat(),
    )
    return result


def _run_rescore(s3, context, lookback_days=None):
    """Sweep: score the CVEs we hold as UNSCORED that NVD has since analyzed.

    Driven by NVD's lastMod window rather than per-CVE lookups. A CVE that gains
    a CVSS base score is MODIFIED at that moment, so one paged query covers every
    transition in the window — no need to re-request the thousands we hold.

    Rewriting analysis/<id>.json is what carries the new score into the rest of
    the pipeline: the ranking digest selects on S3 LastModified, and the mirror
    below flips the table row's score_sk off -1 so the site's search and the
    dashboard's top-N can finally see it.
    """
    if not Config.CVE_TABLE:
        return {"error": "CVE_TABLE not configured; rescore needs the index"}

    days = lookback_days or Config.RESCORE_LOOKBACK_DAYS
    days = max(1, min(int(days), NVD_LASTMOD_MAX_DAYS))

    pending = _unscored_ids(Config.RESCORE_INDEX_DAYS)
    if not pending:
        logger.info("rescore: nothing held as unscored; done")
        return {"lookback_days": days, "unscored_held": 0, "rescored": 0}

    now = _utcnow()
    total, vulns = fetch_cves_by_last_mod(
        Config.NIST_API_BASE_URL, Config.NIST_API_KEY, now - timedelta(days=days), now
    )
    logger.info(
        "rescore: %d CVEs modified in the last %dd; %d held unscored",
        total, days, len(pending),
    )

    deadline = time.monotonic() + max(
        0, context.get_remaining_time_in_millis() / 1000.0 - BACKFILL_RESERVE_SECONDS
    )

    rescored = still_unscored = failed = 0
    for v in vulns:
        cve = v.get("cve") or {}
        cve_id = cve.get("id")
        if cve_id not in pending:
            continue
        if rescored >= Config.RESCORE_MAX_PER_RUN or time.monotonic() >= deadline:
            logger.info("rescore: budget reached; remainder waits for the next run")
            break

        existing = _load_analysis(s3, cve_id)
        if existing is None:
            failed += 1
            continue

        result = _rescore(existing, cve)
        if result is None:
            # No CVSS yet, or no stored judgment to reuse. The second case needs
            # the model, so fall back to a full score rather than skipping it.
            if trim(cve).get("score") is None:
                still_unscored += 1
                continue
            logger.info("rescore: %s has no stored judgment; full re-score", cve_id)
            try:
                _score_one(s3, cve)
                rescored += 1
            except Exception:
                logger.exception("rescore: full re-score failed for %s", cve_id)
                failed += 1
            continue

        _save(s3, result)
        _mirror(result)
        logger.info(
            "rescore: %s UNSCORED -> loop_score=%s priority=%s",
            cve_id, result["loop_score"], result["priority"],
        )
        rescored += 1

    logger.info(
        "rescore done: rescored=%d still_unscored=%d failed=%d", rescored, still_unscored, failed
    )
    return {
        "lookback_days": days,
        "modified_in_window": total,
        "unscored_held": len(pending),
        "rescored": rescored,
        "still_unscored": still_unscored,
        "failed": failed,
    }


def lambda_handler(event, context):
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)

    # Daily sweep: pick up CVEs NVD has scored since we filed them as UNSCORED.
    if event.get("rescore"):
        return _run_rescore(s3, context, event.get("lookback_days"))

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
