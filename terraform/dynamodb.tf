# Scored-CVE table — the queryable copy of the analysis results.
#
# WHY THIS EXISTS: S3 is the record of truth (analysis/<cve-id>.json), but it
# can't answer a question. "Cisco CVEs above 70, worst first" means listing and
# GETting every object in the bucket — which is exactly what the ranking and
# dashboard Lambdas do today, and why they can only afford a fixed lookback
# window. DynamoDB answers the same question in one Query, so the website can
# let a user ask it directly.
#
# The table is a DERIVED read-model, not a second source of truth: every item is
# rebuildable from the analysis bucket (analyzer `{"backfill": true}`). That's
# why there's no point-in-time recovery here — the recovery story is "replay
# S3", and PITR would be a per-GB charge for data we already hold.
#
# Per environment like everything else (cyberloopnews-dev-cves /
# cyberloopnews-main-cves), so a dev write can never reach the prod table.

resource "aws_dynamodb_table" "cves" {
  name = "${local.name_prefix}-cves"

  # On-demand: no capacity to size or autoscale. The write rate is one put per
  # scored CVE (capped at ANALYSIS_MAX_PER_RUN=50/hour) and reads are whatever
  # the site's visitors ask for — both far too small and too spiky to be worth
  # provisioning for.
  billing_mode = "PAY_PER_REQUEST"

  # One item per CVE, so re-scoring overwrites it — the same idempotency the
  # analyzer's S3 write already has.
  hash_key = "cve_id"

  # Only KEY attributes are declared. Everything else on the item (cvss,
  # severity, vendors, prevalence, exploitability, summary, …) is schemaless and
  # needs no definition here.
  attribute {
    name = "cve_id"
    type = "S"
  }

  attribute {
    name = "published_day"
    type = "S"
  }

  attribute {
    name = "vendor_key"
    type = "S"
  }

  # score_sk is the LoopScore as an index sort key: the real score, or -1 when
  # the CVE is UNSCORED (no CVSS base score yet, so loop_score is null).
  # DynamoDB silently omits an item from an index when its sort key attribute is
  # missing, so a plain `loop_score` key would drop every unscored CVE out of
  # both indexes. -1 keeps them queryable and sorts them below every real score.
  attribute {
    name = "score_sk"
    type = "N"
  }

  # Browse by date, ranked by score: "the last N days, worst first". Partitioned
  # by day so a window is N small queries instead of one hot partition; N is
  # capped in the query Lambda.
  global_secondary_index {
    name            = "by_day"
    hash_key        = "published_day"
    range_key       = "score_sk"
    projection_type = "ALL"
  }

  # Filter by vendor, ranked by score: "all Cisco, worst first". vendor_key is
  # the lowercased PRIMARY vendor — the same single-vendor choice the dashboard's
  # bar chart already makes, so a multi-vendor CVE is filed under one vendor only.
  #
  # NOTE: it is NOT vendors[0] as-is. analyzer._vendors() formats entries as
  # "vendor: product", so vendors[0] is a pair; the vendor is parsed out of it in
  # analysis_handler._vendor_key(). Indexing the raw pair made this GSI
  # unqueryable by vendor name.
  global_secondary_index {
    name            = "by_vendor"
    hash_key        = "vendor_key"
    range_key       = "score_sk"
    projection_type = "ALL"
  }

  # Both indexes project ALL because every query the site makes returns a list
  # of CVEs to display, and the items are small (a few KB of scored JSON). A
  # narrower projection would only trade a trivial storage saving for a fetch
  # back to the base table on nearly every read.

  # NOTE: there is deliberately no `by_priority` index. Priority is a pure
  # function of the score (PRIORITY_BANDS in analyzer.py: 75/50/25 -> P1..P4),
  # so ?priority=P1 is exactly `score_sk >= 75` — a key condition on the two
  # indexes above, not a third copy of the table.

  tags = local.tags
}

# Search-terms table — how the site is searched by PRODUCT, not just by vendor.
#
# WHY A SECOND TABLE: `vendor_key` above is a single value, the CVE's primary
# vendor. That makes a CVE shipped by Microsoft whose affected product is "Azure
# DevOps" unfindable by "azure", and "gcp" unfindable by anything — which is
# exactly how people search. A CVE has MANY searchable words, and DynamoDB
# cannot index a multi-valued attribute: a GSI key is one scalar per item. The
# standard shape for many-values-per-record is a row per (value, record), which
# is what this table is.
#
# Derived and rebuildable from the analysis bucket, same as the table above
# (analyzer `{"backfill": true}` writes both), so again no PITR.
resource "aws_dynamodb_table" "cve_terms" {
  name         = "${local.name_prefix}-cve-terms"
  billing_mode = "PAY_PER_REQUEST"

  # (term, cve_id) — one row per searchable word per CVE. cve_id is the range
  # key rather than the score ON PURPOSE: a rescore changes a CVE's LoopScore,
  # and a score-keyed row would leave the old row behind at the old score, so
  # the same CVE would come back twice. Keyed this way a rescore overwrites, the
  # same idempotency the base table gets from cve_id.
  hash_key  = "term"
  range_key = "cve_id"

  attribute {
    name = "term"
    type = "S"
  }

  attribute {
    name = "cve_id"
    type = "S"
  }

  attribute {
    name = "score_sk"
    type = "N"
  }

  # Worst-first ordering within a term, and `min_score` as a key condition. A
  # LOCAL secondary index, not a global one: it re-sorts rows inside a single
  # term's partition, which is precisely one search. -1 marks UNSCORED here too,
  # so the default floor of 0 leaves them out (see analysis_handler.UNSCORED_SK).
  local_secondary_index {
    name            = "by_score"
    range_key       = "score_sk"
    projection_type = "ALL"
  }

  # ALL, because a term query is the whole answer: the row carries the fields the
  # results panel renders (analysis_handler.TERM_ROW_FIELDS), so a search never
  # fetches back to the CVE table. The rows are a trimmed projection — the
  # model's rationales are not copied a dozen times per CVE.

  tags = local.tags
}
