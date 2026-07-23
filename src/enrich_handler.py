"""Enricher Lambda: CVE.org (MITRE) vendor/product data, one object per CVE.

NVD's CPE `configurations` are empty until NVD itself analyzes a CVE, which lags
publication by days. CVE.org exposes the CNA's affected[] list at publish time,
so this is the only vendor/product signal available for fresh CVEs — and it's
what the dashboard's per-platform breakdown is built from.

This is a SEPARATE data source from NVD and is treated as one. It has its own
Lambda, its own schedule, and its own keyspace:

    raw/<ts>/cves.json      NVD, written once by the fetcher, never modified
    cna/<cve-id>.json       CVE.org, written here, one object per CVE
    analysis/<cve-id>.json  Bedrock LoopScores, written by the analyzer

It used to run inline inside the fetcher, mutating the raw scans. Two things
were wrong with that: an unbounded third-party network loop sat in the critical
path of a durable write (a slow CVE.org caused a two-day ingest outage in July
2026), and `raw/` — the record of what NVD actually returned — was being
read-modify-written by a second process on a schedule, racing the analyzer.

Per-CVE keys make the unit of work one HTTP call and one PUT, so the run is
interruptible at any point with zero partial state, and a CVE that appears in
several scans is looked up ONCE EVER rather than re-checked per scan.

Triggered on a schedule, independently of the fetcher.
"""

import json
import logging
import time

import boto3

try:
    from config import Config
    from fetcher import fetch_cna_affected
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config
    from src.fetcher import fetch_cna_affected

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.WARNING)

RAW_PREFIX = "raw/"
CNA_PREFIX = "cna/"


def _recent_scan_keys(s3, bucket, limit):
    """Newest-first raw/<ts>/cves.json keys, capped at `limit`.

    Timestamped keys sort lexicographically, so a reverse sort is newest-first.
    Capped so this never walks the bucket's whole history.
    """
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=RAW_PREFIX):
        for obj in page.get("Contents", []):
            if obj["Key"].endswith("/cves.json"):
                keys.append(obj["Key"])
    keys.sort(reverse=True)
    return keys[:limit]


def _cve_ids_from_scans(s3, bucket, keys):
    """Every CVE id across the given scans, newest scan first, deduped."""
    ids = []
    seen = set()
    for key in keys:
        payload = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        for vuln in payload.get("vulnerabilities", []):
            cve_id = vuln.get("cve", {}).get("id")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                ids.append(cve_id)
    return ids


def _settled_cve_ids(s3, bucket):
    """Set of CVE ids that already have a cna/ object.

    One LIST (1000 keys per call) rather than a HeadObject per CVE. With a busy
    day's scans that's the difference between ~5 calls and several thousand —
    and the per-CVE version spent most of the run's budget *discovering* work
    instead of doing it, re-checking the same settled CVEs on every run forever.
    """
    settled = set()
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=CNA_PREFIX):
        for obj in page.get("Contents", []):
            name = obj["Key"][len(CNA_PREFIX) :]
            if name.endswith(".json"):
                settled.add(name[: -len(".json")])
    return settled


def lambda_handler(event, context):
    """Look up CVE.org products for CVEs that don't have a cna/ object yet.

    Bounded twice over: by how many scans we inspect, and by a wall-clock budget
    derived from the Lambda's own remaining time. The budget is the important
    one — a per-request timeout bounds ONE call, and nothing bounded N of them,
    which is exactly how this workload took the fetcher down.
    """
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    bucket = Config.S3_BUCKET

    remaining = context.get_remaining_time_in_millis() / 1000.0
    deadline = time.monotonic() + max(0, remaining - Config.ENRICH_RESERVE_SECONDS)

    scan_keys = _recent_scan_keys(s3, bucket, Config.ENRICH_MAX_SCANS_PER_RUN)
    seen_ids = _cve_ids_from_scans(s3, bucket, scan_keys)
    settled = _settled_cve_ids(s3, bucket)
    pending = [c for c in seen_ids if c not in settled]

    stats = {
        "scans_inspected": len(scan_keys),
        "cves_seen": len(seen_ids),
        "already_done": len(seen_ids) - len(pending),
        "written": 0,
        "failed": 0,
        "skipped_budget": 0,
    }

    for i, cve_id in enumerate(pending):
        if time.monotonic() >= deadline:
            stats["skipped_budget"] = len(pending) - i
            logger.warning(
                "budget exhausted with %s CVE(s) left; next run resumes there",
                stats["skipped_budget"],
            )
            break

        products, ok = fetch_cna_affected(cve_id)
        if not ok:
            # Transient — write nothing, so the next run retries this CVE.
            stats["failed"] += 1
            continue

        s3.put_object(
            Bucket=bucket,
            Key=f"{CNA_PREFIX}{cve_id}.json",
            Body=json.dumps(
                {
                    "cve_id": cve_id,
                    "products": products,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            ContentType="application/json",
        )
        stats["written"] += 1
        time.sleep(Config.ENRICH_DELAY_SECONDS)

    logger.info("enrichment run: %s", json.dumps(stats))
    return stats
