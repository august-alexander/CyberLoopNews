"""LoopScore analyzer: score one CVE's risk with Bedrock + a fixed formula.

The AI model (Claude on Bedrock) owns the *judgment* — how prevalent/useful the
affected systems are and how exploitable the flaw is. This module owns the
*arithmetic*: it applies the LoopScore formula so the published number is
deterministic and reproducible, independent of the model's mental math.

    LoopScore = 100 * S * (0.4 + 0.4*P + 0.2*E)
        S = CVSS base score / 10   (from the CVE)
        P = prevalence/usefulness of affected systems, 0.0-1.0 (model estimate)
        E = real-world exploitability, 0.0-1.0                 (model estimate)
"""

import json
import logging

import boto3

try:
    from config import Config
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config

logger = logging.getLogger(__name__)

# CVSS metrics come in four versions; prefer the newest present (matches the
# reporter's convention in report_handler.py).
METRIC_PRIORITY = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

# LoopScore weighting: severity-anchored, discounted by prevalence + exploitability.
W_BASE, W_PREVALENCE, W_EXPLOIT = 0.4, 0.4, 0.2

# loop_score -> priority band. One source of truth so score and priority agree.
PRIORITY_BANDS = ((75, "P1"), (50, "P2"), (25, "P3"), (0, "P4"))

# The model returns ONLY its judgment — never the final score. Python computes
# that from the formula so the published number can't drift.
SYSTEM = (
    "You are a cybersecurity risk analyst. You output ONLY a single valid JSON "
    "object and nothing else — no markdown, no code fences, no prose."
)

PROMPT = """Assess this CVE for our LoopScore risk model. You alone estimate the two
subjective inputs; there is NO lookup table. Do NOT compute the final score —
that is done downstream.

Estimate:
  P = prevalence/usefulness of the affected systems, 0.0-1.0
  E = real-world exploitability, 0.0-1.0

RUBRIC:
  P: 1.0 = ubiquitous, business-critical, internet-scale software (Windows,
     Linux kernel, OpenSSL, Apache, widely-used enterprise SaaS); 0.5 =
     moderately common; 0.1 = niche, obscure, or abandoned product.
  E: 1.0 = actively exploited, public PoC, or unauthenticated network RCE that
     is trivially automatable; 0.5 = plausible with some barriers; 0.1 =
     theoretical, needs local access or a complex chain.

Return JSON EXACTLY in this shape:
{
  "prevalence": {"value": number, "rationale": string},
  "exploitability": {"value": number, "rationale": string},
  "summary": string
}
"""


def _cvss(cve):
    """Return (base_score, severity), preferring the newest CVSS version present."""
    metrics = cve.get("metrics", {})
    for version in METRIC_PRIORITY:
        entries = metrics.get(version)
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        # V3.x/V4 carry baseSeverity in cvssData; V2 carries it on the entry.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        if score is not None:
            return score, severity or "UNKNOWN"
    return None, "UNKNOWN"


def _vendors(cve):
    """Deduped 'vendor: product' strings from the CNA-supplied affected[] block.

    NVD's `configurations` (CPE) data is empty until NVD analyzes a CVE, so for
    brand-new CVEs the CNA `affected[]` list is the only product signal.
    """
    pairs, seen = [], set()
    for src in cve.get("affected", []) or []:
        for item in src.get("affectedData", []) or []:
            vendor = (item.get("vendor") or "").strip()
            product = (item.get("product") or "").strip()
            key = (vendor.lower(), product.lower())
            if product and key not in seen:
                seen.add(key)
                pairs.append(f"{vendor}: {product}" if vendor else product)
    return pairs


def trim(cve):
    """Reduce one NVD CVE to the fields the model needs to score it."""
    score, severity = _cvss(cve)
    en = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "score": score,
        "severity": severity,
        "vendors": _vendors(cve),
        "description": en,
    }


def _parse_json(text):
    """Parse the model reply, tolerating ```json fences / stray prose."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned[cleaned.find("{") : cleaned.rfind("}") + 1]
    return json.loads(cleaned)


def _priority_for(score):
    for threshold, label in PRIORITY_BANDS:
        if score >= threshold:
            return label
    return "P4"


def compute_loop_score(cvss, prevalence, exploit):
    """Deterministic LoopScore: 100 * S * (0.4 + 0.4*P + 0.2*E)."""
    s = cvss / 10
    return round(100 * s * (W_BASE + W_PREVALENCE * prevalence + W_EXPLOIT * exploit), 1)


def assess(trimmed, client=None):
    """Ask the model for its P/E judgment on one trimmed CVE (Bedrock Converse)."""
    client = client or boto3.client("bedrock-runtime", region_name=Config.AWS_REGION)
    resp = client.converse(
        modelId=Config.BEDROCK_MODEL_ID,
        system=[{"text": SYSTEM}],
        messages=[
            {
                "role": "user",
                "content": [{"text": f"{PROMPT}\n\nCVE:\n{json.dumps(trimmed, indent=2)}"}],
            }
        ],
        inferenceConfig={"maxTokens": 500, "temperature": 0},  # temp 0 = repeatable
    )
    text = resp["output"]["message"]["content"][0]["text"]
    logger.info("bedrock usage for %s: %s", trimmed.get("id"), resp.get("usage"))
    return _parse_json(text)


def score_cve(cve, client=None):
    """Full pipeline for one raw NVD cve dict: trim -> model judgment -> score."""
    trimmed = trim(cve)
    cve_id = trimmed.get("id")
    logger.info("scoring %s (cvss=%s)", cve_id, trimmed.get("score"))

    judgment = assess(trimmed, client=client)
    p = judgment["prevalence"]["value"]
    e = judgment["exploitability"]["value"]

    cvss = trimmed.get("score")
    if cvss is None:
        # No CVSS base score yet (NVD hasn't analyzed it) — can't anchor severity.
        logger.warning("%s has no CVSS score; leaving unscored", cve_id)
        loop_score, priority = None, "UNSCORED"
    else:
        loop_score = compute_loop_score(cvss, p, e)
        priority = _priority_for(loop_score)

    result = {
        "cve_id": cve_id,
        "cvss": cvss,
        "severity": trimmed.get("severity"),
        "published": trimmed.get("published"),
        "vendors": trimmed.get("vendors"),
        "prevalence": judgment["prevalence"],
        "exploitability": judgment["exploitability"],
        "loop_score": loop_score,
        "priority": priority,
        "summary": judgment.get("summary"),
    }
    logger.info("%s -> loop_score=%s priority=%s", cve_id, loop_score, priority)
    return result
