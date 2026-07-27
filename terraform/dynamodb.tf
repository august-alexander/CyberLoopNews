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
  # the lowercased PRIMARY vendor (vendors[0]) — the same single-vendor choice
  # the dashboard's bar chart already makes, so a multi-vendor CVE is filed
  # under one vendor only.
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
