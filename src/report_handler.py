"""Report Lambda: read the latest CVE dump from S3 and email a small report.

Single responsibility — this Lambda only builds and sends the report. It reads
the most recent raw/<timestamp>/cves.json that the fetcher saved, summarizes it,
and publishes that summary to the SNS topic (email).

Triggered daily by EventBridge, shortly after the fetcher.

NOTE: the report body is a deliberate placeholder for now (a count + the CVE
IDs). We'll flesh out the contents next.
"""

import json
from collections import Counter

import boto3

# Same packaging note as the fetcher: modules sit flat at the zip root in Lambda,
# but under src/ locally.
try:
    from config import Config
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config

RAW_PREFIX = "raw/"


def _latest_raw_key(s3, bucket):
    """Return the newest raw/<ts>/cves.json key, or None if none exist.

    Keys are timestamped (raw/YYYYmmddHHMMSS/cves.json), so the lexicographically
    largest key is also the most recent.
    """
    latest = None
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=RAW_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/cves.json") and (latest is None or key > latest):
                latest = key
    return latest


# How many operating systems to list in the OS breakdown before truncating.
TOP_OS_LIMIT = 10


def _cvss(cve):
    """Return (base_score, severity) for a CVE, preferring the newest CVSS
    version present. Returns (None, "UNKNOWN") when no score is available.
    """
    metrics = cve.get("metrics", {})
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version)
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        # V3.x carries baseSeverity inside cvssData; V2 carries it on the entry.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        if score is not None:
            return score, severity or "UNKNOWN"
    return None, "UNKNOWN"


def _operating_systems(cve):
    """Return the set of operating systems a CVE affects.

    OS entries are CPEs whose 'part' field is 'o'
    (cpe:2.3:o:<vendor>:<product>:...). We key on vendor/product.
    """
    oses = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4 and parts[2] == "o":
                    oses.add(f"{parts[3]}/{parts[4]}")
    return oses


def _build_report(payload):
    """Build the report body: new count, top 5 by severity, and OS breakdown."""
    cves = [v["cve"] for v in payload.get("vulnerabilities", []) if "cve" in v]

    # Top 5 by CVSS base score (highest first).
    scored = [
        (score, severity, cve["id"])
        for cve in cves
        for score, severity in [_cvss(cve)]
        if score is not None
    ]
    scored.sort(key=lambda x: x[0], reverse=True)
    top5 = scored[:5]

    # CVE count per operating system (a CVE affecting several OSes counts once
    # for each), most-affected first.
    os_counts = Counter()
    for cve in cves:
        for os_name in _operating_systems(cve):
            os_counts[os_name] += 1

    lines = [
        "CyberLoop CVE Report",
        "=" * 40,
        f"{len(cves)} new CVE(s) in the latest fetch.",
        "",
        "Top 5 by severity (CVSS base score):",
    ]
    if top5:
        lines += [f"  {score:>4}  {severity:<9}  {cid}" for score, severity, cid in top5]
    else:
        lines.append("  (no CVSS scores available)")

    lines += ["", "CVEs by operating system:"]
    if os_counts:
        lines += [f"  {count:>4}  {name}" for name, count in os_counts.most_common(TOP_OS_LIMIT)]
        remaining = len(os_counts) - TOP_OS_LIMIT
        if remaining > 0:
            lines.append(f"  ... and {remaining} more")
    else:
        lines.append("  (no OS-specific CVEs)")

    return "\n".join(lines)


def lambda_handler(event, context):
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    sns = boto3.client("sns", region_name=Config.AWS_REGION)

    key = _latest_raw_key(s3, Config.S3_BUCKET)
    if key is None:
        print(json.dumps({"reported": False, "reason": "no raw data"}))
        return {"reported": False}

    payload = json.loads(
        s3.get_object(Bucket=Config.S3_BUCKET, Key=key)["Body"].read()
    )
    body = _build_report(payload)

    sns.publish(
        TopicArn=Config.SNS_TOPIC_ARN,
        Subject="CyberLoop CVE Report",
        Message=body,
    )

    result = {"reported": True, "raw_key": key}
    print(json.dumps(result))
    return result
