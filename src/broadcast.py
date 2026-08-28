"""Broadcast writer: turn the day's scored CVEs and breach filings into a script.

This module owns the SHOW — its voice, its segment order, and the rules the
writer works under. It is the counterpart to analyzer.py: that module asks the
model for a narrow judgment and lets Python do the arithmetic, because a score
must be reproducible. Here the model's prose IS the deliverable, so the module
is mostly prompt, and the Python around it just shapes the material and calls
Bedrock.

WHY THE PROMPT IS THIS STRICT: the model has no live web access and a training
cutoff, so for a CVE published this morning it knows the vendor, the product,
and what the attack class means in practice — but nothing about that specific
CVE. That background is exactly the surface-level color a broadcast wants, and
it is also the fastest way to put a confident, false sentence on air. So the
prompt splits the two explicitly: our supplied data is the only source for
claims about a CVE, and the model's own knowledge is licensed only for context
about the product and the attack class. See RULES below.

Editing the show: everything an editor would want to change — segment order,
runtime, tone, sign-off — lives in PROMPT and SHOW_SEGMENTS in this file. A
change here is a commit and a deploy, which is the point: the script that went
out on a given day is recoverable from git.
"""

import logging

import boto3

try:
    from config import Config
except ImportError:  # pragma: no cover - local/dev path
    from src.config import Config

logger = logging.getLogger(__name__)

# Target length. ~150 words per minute is a comfortable read-aloud pace, so a
# 4-5 minute segment is roughly 600-750 words. Stated to the model in both
# minutes and words because it holds a word budget better than a time budget.
TARGET_MINUTES = "4-5"
TARGET_WORDS = "600-750"

# The two daily slots differ in framing, not in content: the 9am show sets up
# the day, the 1pm show is a mid-day update over an overlapping window. Keyed by
# the `slot` the handler passes in.
#
# Each entry also states what the NEXT edition is, because the sign-off asks the
# writer to name it. Without that the model invents one — the first live test
# signed off promising an "evening edition" that does not exist. There are only
# two editions a day; if a slot is ever added to var.broadcast_slots, add it
# here and update these hand-offs to match.
SLOT_FRAMING = {
    "morning": (
        "This is the MORNING edition, which airs at 9am Eastern. Frame it as "
        "setting up the day ahead — what landed overnight and what the audience "
        "should be watching for. The next edition is the MIDDAY show at 1pm "
        "Eastern today; that is the only thing you may point them to."
    ),
    "midday": (
        "This is the MIDDAY edition, which airs at 1pm Eastern. The audience may "
        "have heard the morning show, which covered an overlapping window. Lead "
        "with what is new or what has developed; reference recurring items "
        "briefly rather than re-reading them in full. This is the LAST edition "
        "of the day — the next one is tomorrow morning at 9am Eastern. There is "
        "no evening or late edition; never promise one."
    ),
}

SYSTEM = (
    "You are the head writer for CyberLoop, a short daily cybersecurity news "
    "broadcast for a working security audience — analysts, sysadmins, and IT "
    "leads who will act on what they hear. You write finished scripts meant to "
    "be read aloud on air. You output ONLY the script text: no markdown, no "
    "code fences, no preamble, and no notes to the producer."
)

# The segment structure. Kept as its own constant so the running order can be
# changed without rewriting the surrounding instructions.
SHOW_SEGMENTS = """\
1. COLD OPEN (2-3 sentences)
   The single most important thing in today's data, stated plainly. No throat
   clearing, no "welcome back to another episode." Lead with the story.

2. THE VULNERABILITY DESK
   The highest-LoopScore CVEs from the supplied data, worst first. Cover the
   top 3-5 in real detail; compress the rest into a quick list. For each one
   that gets detail: what the product is and who runs it, what the flaw lets an
   attacker do, and why it scored where it did. Say the CVE ID clearly — the
   audience writes these down.

3. THE BREACH DESK
   The SEC 8-K and 6-K cyber-incident filings from the supplied data. These are
   public companies formally disclosing a material breach, so name the company
   and the filing date. If there are no filings in the window, say so in one
   sentence and move on — a quiet day is information too.

4. WHAT TO DO TODAY
   2-4 concrete actions tied to the items above. "Inventory your internet-facing
   Fortinet appliances" is an action. "Stay vigilant" is not — never write it.

5. SIGN-OFF (1-2 sentences)
   Short. Name the next edition.
"""

# The hard rules. Ordered most-important first; the sourcing rules lead because
# a confident false sentence is the one failure mode that damages the show.
RULES = """\
SOURCING RULES — these are not style preferences:

- The CVE and filing data supplied below is your ONLY source for facts about
  any specific CVE or any specific breach. Every ID, score, severity, vendor,
  product, company, and date must come from that data.

- You have real background knowledge about vendors, products, and classes of
  attack, and you SHOULD use it — that context is what makes this a broadcast
  and not a list. Explaining what Fortinet appliances are typically used for,
  or what an unauthenticated RCE means for an exposed host, is exactly right.

- You must NOT extend that knowledge into claims about the specific items in
  today's data. Do not say a CVE is being actively exploited, has a public
  proof-of-concept, is linked to a named threat actor, or is related to a past
  incident, unless the supplied data says so. You would not know: these items
  are newer than your training data. If it is not in the data, it does not go
  on air.

- Never invent a CVE ID, a company, a score, a date, or a patch version. If the
  data is thin on an item, say less about it. A short segment is fine.

- The LoopScore is our own 0-100 risk number, not an industry standard. If you
  reference it, treat it as the house metric it is. CVSS is the external score.

STYLE RULES:

- Write for the ear. Short sentences. Spoken contractions. No bullet points, no
  headers, no markdown in the output — it is read aloud, not displayed.
- Spell out how IDs are spoken the first time if it helps: "CVE-2026-1234,
  that's CVE dash twenty twenty-six dash twelve thirty-four."
- No hype, no fear-selling, no "cyber pandemic." The audience does this for a
  living and will switch off. Sober and useful beats urgent.
- Do not editorialize about vendors or blame victims of a breach.
"""

PROMPT = """Write today's CyberLoop broadcast script.

{framing}

Target length: {minutes} minutes read aloud, roughly {words} words.

RUNNING ORDER:
{segments}

{rules}
Write the finished script now. Output the script text only.
"""


def trim_cve(result):
    """Reduce one scored analysis result to the fields the writer needs.

    Drops the analyzer's internal scoring inputs (the raw prevalence and
    exploitability values) but KEEPS their rationales — those sentences are the
    model's own reasoning about why the CVE matters, and they are the best raw
    material in the payload for the vulnerability desk.
    """
    prevalence = result.get("prevalence") or {}
    exploitability = result.get("exploitability") or {}
    return {
        "cve_id": result.get("cve_id"),
        "loop_score": result.get("loop_score"),
        "priority": result.get("priority"),
        "cvss": result.get("cvss"),
        "severity": result.get("severity"),
        "published": result.get("published"),
        "affected": (result.get("vendors") or [])[:6],
        "summary": result.get("summary"),
        "why_prevalent": prevalence.get("rationale"),
        "why_exploitable": exploitability.get("rationale"),
    }


def trim_filing(filing):
    """Reduce one EDGAR filing to what the breach desk reads on air."""
    return {
        "company": filing.get("company"),
        "file_date": filing.get("file_date"),
        "url": filing.get("url"),
    }


def _format_material(material):
    """Render the gathered material as the labeled block the prompt refers to.

    Plain labeled text rather than raw JSON: the model reads it as source
    material for prose, and the shape of the payload is not something the show
    should have to explain.
    """
    lines = [
        "=== TODAY'S DATA ===",
        f"Date: {material.get('date')}",
        f"Window: the last {material.get('lookback_hours')} hours",
        "",
        f"SCORED CVES ({len(material.get('cves') or [])}, highest LoopScore first):",
    ]
    cves = material.get("cves") or []
    if not cves:
        lines.append("  (none scored in this window)")
    for cve in cves:
        lines.append("")
        for key, value in cve.items():
            if value in (None, "", []):
                continue
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            lines.append(f"  {key}: {value}")

    for label, key in (
        ("SEC 8-K CYBER INCIDENT FILINGS (domestic)", "filings_8k"),
        ("SEC 6-K CYBER INCIDENT FILINGS (foreign private issuers)", "filings_6k"),
    ):
        filings = material.get(key) or []
        lines.extend(["", f"{label} ({len(filings)}):"])
        if not filings:
            lines.append("  (none disclosed in this window)")
        for f in filings:
            lines.append(
                f"  {f.get('file_date', '?')}  {f.get('company', '(unknown)')}"
                + (f"  {f['url']}" if f.get("url") else "")
            )

    return "\n".join(lines)


def build_prompt(material):
    """Assemble the full user prompt for one broadcast."""
    framing = SLOT_FRAMING.get(material.get("slot"), SLOT_FRAMING["morning"])
    instructions = PROMPT.format(
        framing=framing,
        minutes=TARGET_MINUTES,
        words=TARGET_WORDS,
        segments=SHOW_SEGMENTS,
        rules=RULES,
    )
    return f"{instructions}\n\n{_format_material(material)}"


def _extract_text(resp):
    """Pull the script text out of a Converse reply.

    Deliberately NOT content[0]["text"], which is what analyzer.py does. That
    works there because the analyzer runs on Haiku, but this runs on Sonnet 5,
    which has thinking on by default — on a prompt it finds worth reasoning
    about, block 0 is a reasoning block and block 1 is the text. Confirmed both
    ways against Bedrock: a trivial prompt came back as a single text block, the
    full broadcast prompt came back with a reasoning block first. The layout is
    per-request, so scan for the text block instead of assuming a position.
    """
    blocks = resp.get("output", {}).get("message", {}).get("content", []) or []
    parts = [b["text"] for b in blocks if "text" in b]
    if not parts:
        raise ValueError(
            "Bedrock returned no text block for the broadcast "
            f"(block types: {[list(b) for b in blocks]})"
        )
    return "\n".join(parts).strip()


def write_script(material, client=None):
    """Generate one broadcast script from the gathered material (Bedrock Converse).

    Returns the script text, ready to send. Runs on BROADCAST_MODEL_ID (Sonnet),
    deliberately a stronger model than the analyzer's Haiku: the analyzer makes
    ~1200 small judgment calls a day where cheap and fast is the right trade,
    whereas this is two calls a day and the prose quality IS the product.
    """
    client = client or boto3.client("bedrock-runtime", region_name=Config.AWS_REGION)
    resp = client.converse(
        modelId=Config.BROADCAST_MODEL_ID,
        system=[{"text": SYSTEM}],
        messages=[{"role": "user", "content": [{"text": build_prompt(material)}]}],
        inferenceConfig={
            # Room for the full script plus headroom; a truncated script is a
            # dead air incident, and the cost of the unused ceiling is zero.
            "maxTokens": 4000,
            # NOTE: no `temperature` here, unlike analyzer.assess(). Sonnet 5
            # rejects sampling parameters outright — Bedrock returns
            # ValidationException "`temperature` is deprecated for this model".
            # The analyzer can still pin temperature 0 because it runs on Haiku
            # 4.5, which accepts it. If this model is ever changed back to a
            # model that takes sampling params, variety is the reason you might
            # want one; correctness does not depend on it.
        },
    )
    logger.info(
        "bedrock usage for %s broadcast: %s", material.get("slot"), resp.get("usage")
    )

    # A truncated script is dead air, so surface it loudly rather than emailing
    # a half-written show. maxTokens above is generous; hitting it means the
    # length instructions drifted, not that the ceiling is too low.
    if resp.get("stopReason") == "max_tokens":
        logger.warning(
            "%s broadcast hit maxTokens — the script is probably cut off",
            material.get("slot"),
        )

    return _extract_text(resp)
