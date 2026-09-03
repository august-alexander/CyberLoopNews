"""Search terms for one scored CVE: the words a person would actually type.

WHY THIS EXISTS: the CVE table indexes `vendor_key`, which is the PRIMARY VENDOR
ONLY (analysis_handler._vendor_key). So a CVE filed under "microsoft" whose
affected product is "Azure DevOps" cannot be found by searching "azure", and
"gcp" matches nothing at all — even though both are how people describe the
thing they run. DynamoDB can't index a multi-valued attribute, so the terms get
their own small table (one row per term -> CVE); this module decides what those
terms are.

Pure functions, no AWS and no I/O, so the tokenising is testable on its own and
the same rules apply to what we WRITE (analysis_handler) and what we READ
(search_handler) — a query has to be normalised exactly like the stored terms or
it can never match.
"""

import re

# Split on anything that isn't a letter or digit: "Microsoft: Azure DevOps" and
# "azure-devops" both have to reduce to the same tokens.
_SPLIT = re.compile(r"[^a-z0-9]+")

# Words that would match nearly everything, or nothing anyone would search for.
# Kept deliberately short — over-filtering silently makes a product unfindable,
# which is the exact bug this module exists to fix. Vendor placeholders are the
# same set analysis_handler treats as "no vendor stated".
STOPWORDS = frozenset(
    {
        "the", "and", "for", "with", "from", "all", "any", "not",
        "inc", "corp", "corporation", "llc", "ltd", "gmbh", "co", "company",
        "na", "n", "a", "none", "unknown", "other", "misc",
        "software", "server", "client", "system", "systems", "product",
        "products", "service", "services", "version", "versions",
    }
)

# Cap per CVE. A long affected[] list can name dozens of products; past a dozen
# terms the extras are near-duplicate version strings, and every term is a row
# written on every score and rescore.
MAX_TERMS = 12

# A token must be at least this long. Kills the "v", "x", "1" debris that
# splitting version strings leaves behind.
MIN_TERM_LEN = 2


def tokenize(text):
    """Lowercase `text` and split it into search tokens, in first-seen order.

    Duplicates and stopwords are dropped. Purely mechanical — no stemming, so
    what goes into the table is exactly what a query has to produce.
    """
    tokens, seen = [], set()
    for token in _SPLIT.split((text or "").lower()):
        if len(token) < MIN_TERM_LEN or token in STOPWORDS or token in seen:
            continue
        # Bare numbers are version fragments ("... Server 2022" -> "2022"). Nobody
        # searches for one, and every CVE that names a year would answer it — so
        # they'd only spend the per-CVE term budget. Mixed tokens ("7zip") stay.
        if token.isdigit():
            continue
        seen.add(token)
        tokens.append(token)
    return tokens


def terms_for(result):
    """The search terms for one scored result, capped at MAX_TERMS.

    Two sources, in priority order:

    1. `vendors` — the CNA's "Vendor: Product" strings (analyzer._vendors).
       Tokenising the whole string, not just the vendor half, is what makes
       "Microsoft: Azure DevOps" reachable by "azure". This source alone fixes
       the reported bug for every CVE we already hold, with no model call, so it
       goes first and is never crowded out by the cap.

    2. `keywords` — the analyzer's own list (analyzer.PROMPT). This is where the
       aliases live: "gcp" for Google Cloud, "k8s", "o365". Nothing in the CNA
       data spells those, so a lookup table could never produce them; the model
       is the only source that knows what a product is commonly called.

    Older results predate `keywords` and simply contribute nothing from step 2.
    """
    terms, seen = [], set()
    for text in list(result.get("vendors") or []) + list(result.get("keywords") or []):
        for token in tokenize(text):
            if token in seen:
                continue
            seen.add(token)
            terms.append(token)
            if len(terms) >= MAX_TERMS:
                return terms
    return terms


def query_terms(text, limit=2):
    """Normalise a user's search box input into at most `limit` terms.

    Same tokenizer as the writer, so "Azure DevOps" and "azure-devops" both hit
    the rows written for "Microsoft: Azure DevOps". The limit bounds how many
    Queries one search can cost; the caller intersects whatever it gets back.
    """
    return tokenize(text)[:limit]
