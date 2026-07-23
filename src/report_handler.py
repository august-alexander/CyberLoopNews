"""Report Lambda: summarize the last 24h of CVEs from S3 and email a report.

Single responsibility — this Lambda only builds and sends the report. The CVE
fetcher now runs hourly, so a single scan is just one hour's delta; the daily
report therefore stitches together every raw/<ts>/cves.json from the last 24h
(deduped by CVE id) so nothing published during the day is missed. EDGAR 8-K/6-K
stay daily, so their latest filings.json already covers the day.

Triggered daily by EventBridge.
"""

import json
from collections import Counter
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

# Same packaging note as the fetcher: modules sit flat at the zip root in Lambda,
# but under src/ locally.
try:
    from config import Config
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config

RAW_PREFIX = "raw/"
EDGAR_PREFIX = "edgar/"
EDGAR_6K_PREFIX = "edgar6k/"


def _latest_key(s3, bucket, prefix, suffix):
    """Return the newest key under `prefix` ending in `suffix`, or None.

    Both the CVE fetcher (raw/<ts>/cves.json) and the EDGAR fetcher
    (edgar/<ts>/filings.json) use timestamped keys, so the lexicographically
    largest matching key is also the most recent.
    """
    latest = None
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(suffix) and (latest is None or key > latest):
                latest = key
    return latest


# Timestamp convention for our own S3 keys: raw/<%Y%m%d%H%M%S>/cves.json.
KEY_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"


def _utcnow():
    return datetime.now(timezone.utc)


def _scans_since(s3, bucket, cutoff):
    """Return every raw/<ts>/cves.json key whose timestamp is >= cutoff (UTC)."""
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=RAW_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith("/cves.json"):
                continue
            parts = key.split("/")
            if len(parts) < 3:
                continue
            try:
                ts = datetime.strptime(parts[1], KEY_TIMESTAMP_FORMAT).replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue
            if ts >= cutoff:
                keys.append(key)
    return sorted(keys)


def _combine_scans(s3, bucket, keys):
    """Merge several scans into one payload, deduped by CVE id (latest wins)."""
    merged = {}
    for key in keys:
        payload = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        for vuln in payload.get("vulnerabilities", []):
            cve_id = vuln.get("cve", {}).get("id")
            if cve_id:
                merged[cve_id] = vuln
    return {"vulnerabilities": list(merged.values()), "totalResults": len(merged)}


# How many affected products to list in the breakdown before truncating.
TOP_PRODUCT_LIMIT = 10


def _cvss(cve):
    """Return (base_score, severity) for a CVE, preferring the newest CVSS
    version present. Returns (None, "UNKNOWN") when no score is available.
    """
    metrics = cve.get("metrics", {})
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
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


def _load_cna_products(s3, bucket, cve_ids):
    """Return {cve_id: [{"vendor", "product"}, ...]} from the cna/ keyspace.

    The enricher Lambda writes one cna/<cve-id>.json per CVE from CVE.org, on
    its own schedule. Missing objects are normal and expected — a CVE fetched
    minutes ago may not be enriched yet, or CVE.org may not mirror it at all —
    so this is a left join, never a hard dependency. The report goes out with
    whatever product data exists at the time.
    """
    products = {}
    for cve_id in cve_ids:
        try:
            obj = s3.get_object(Bucket=bucket, Key=f"{Config.CNA_PREFIX}{cve_id}.json")
        except ClientError:
            continue
        products[cve_id] = json.loads(obj["Body"].read()).get("products", [])
    return products


def _affected_products(cve, cna_products):
    """Return the set of 'vendor/product' strings a CVE affects.

    Uses the CNA-supplied affected products from the cna/ keyspace. Unlike NVD's
    `configurations` (CPE) data — which is empty until NVD analyzes a CVE —
    these are populated at publish time, so brand-new CVEs still get a product
    breakdown.
    """
    products = set()
    for entry in cna_products.get(cve.get("id"), []):
        vendor = entry.get("vendor", "").strip()
        product = entry.get("product", "").strip()
        if not product:
            continue
        products.add(f"{vendor}/{product}" if vendor else product)
    return products


def _build_report(payload, cna_products):
    """Build the report body: new count, top 5 by severity, and product breakdown."""
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

    # CVE count per affected product (a CVE affecting several products counts
    # once for each), most-affected first.
    product_counts = Counter()
    for cve in cves:
        for product in _affected_products(cve, cna_products):
            product_counts[product] += 1

    lines = [
        "CyberLoop CVE Report",
        "=" * 40,
        f"{len(cves)} new CVE(s) in the last 24 hours.",
        "",
        "Top 5 by severity (CVSS base score):",
    ]
    if top5:
        lines += [f"  {score:>4}  {severity:<9}  {cid}" for score, severity, cid in top5]
    else:
        lines.append("  (no CVSS scores available)")

    lines += ["", "Top affected products:"]
    if product_counts:
        lines += [
            f"  {count:>4}  {name}"
            for name, count in product_counts.most_common(TOP_PRODUCT_LIMIT)
        ]
        remaining = len(product_counts) - TOP_PRODUCT_LIMIT
        if remaining > 0:
            lines.append(f"  ... and {remaining} more")
    else:
        lines.append("  (no affected-product data)")

    return "\n".join(lines)


def _build_edgar_section(payload, title):
    """Return an SEC filings section (given a heading) as a list of report lines.

    Shared by the 8-K (domestic Item 1.05) and 6-K (foreign private issuer)
    cyber-disclosure feeds — both store the same normalized filing shape. Most
    recent filings first.
    """
    filings = payload.get("filings", [])
    lines = ["", "", title]
    if not filings:
        lines.append("  (none disclosed in the latest window)")
        return lines

    for f in sorted(filings, key=lambda x: x.get("file_date") or "", reverse=True):
        lines.append(f"  {f.get('file_date', '?')}  {f.get('company', '(unknown)')}")
        if f.get("url"):
            lines.append(f"      {f['url']}")
    return lines


def lambda_handler(event, context):
    s3 = boto3.client("s3", region_name=Config.AWS_REGION)
    sns = boto3.client("sns", region_name=Config.AWS_REGION)

    cutoff = _utcnow() - timedelta(hours=Config.REPORT_LOOKBACK_HOURS)
    cve_keys = _scans_since(s3, Config.S3_BUCKET, cutoff)
    if not cve_keys:
        print(json.dumps({"reported": False, "reason": "no scans in 24h window"}))
        return {"reported": False}

    cve_payload = _combine_scans(s3, Config.S3_BUCKET, cve_keys)
    cve_ids = [
        v["cve"]["id"] for v in cve_payload.get("vulnerabilities", []) if "cve" in v
    ]
    cna_products = _load_cna_products(s3, Config.S3_BUCKET, cve_ids)
    body = _build_report(cve_payload, cna_products)

    # Merge in the latest EDGAR dumps if the fetchers have run. Best-effort:
    # the CVE report still goes out even if no EDGAR data exists yet.
    edgar_key = _latest_key(s3, Config.S3_BUCKET, EDGAR_PREFIX, "/filings.json")
    if edgar_key is not None:
        edgar_payload = json.loads(
            s3.get_object(Bucket=Config.S3_BUCKET, Key=edgar_key)["Body"].read()
        )
        body += "\n" + "\n".join(
            _build_edgar_section(
                edgar_payload,
                "SEC 8-K cybersecurity incident disclosures (Item 1.05):",
            )
        )

    edgar_6k_key = _latest_key(s3, Config.S3_BUCKET, EDGAR_6K_PREFIX, "/filings.json")
    if edgar_6k_key is not None:
        edgar_6k_payload = json.loads(
            s3.get_object(Bucket=Config.S3_BUCKET, Key=edgar_6k_key)["Body"].read()
        )
        body += "\n" + "\n".join(
            _build_edgar_section(
                edgar_6k_payload,
                "SEC 6-K cybersecurity incident disclosures (foreign private issuers):",
            )
        )

    sns.publish(
        TopicArn=Config.SNS_TOPIC_ARN,
        Subject="CyberLoop CVE Report",
        Message=body,
    )

    result = {
        "reported": True,
        "scans_in_window": len(cve_keys),
        "cve_count": cve_payload["totalResults"],
        "edgar_key": edgar_key,
        "edgar_6k_key": edgar_6k_key,
    }
    print(json.dumps(result))
    return result
