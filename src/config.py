import os

# python-dotenv is only used for local development. In the Lambda runtime it
# isn't packaged, so treat it as optional and fall back to real env vars.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class Config:
    # NIST NVD API
    NIST_API_KEY = os.getenv("NIST_API_KEY")
    NIST_API_BASE_URL = os.getenv("NIST_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")

    # AWS
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    AWS_PROFILE = os.getenv("AWS_PROFILE", "default")

    # SEC EDGAR — full-text search for 8-K Item 1.05 (material cybersecurity
    # incident) disclosures. SEC REQUIRES a descriptive User-Agent with contact
    # info; requests without one get HTTP 403.
    EDGAR_FTS_URL = os.getenv("EDGAR_FTS_URL", "https://efts.sec.gov/LATEST/search-index")
    EDGAR_USER_AGENT = os.getenv("EDGAR_USER_AGENT", "CyberLoopNews aalexand@rednaxela.technology")
    EDGAR_LOOKBACK_DAYS = int(os.getenv("EDGAR_LOOKBACK_DAYS", "1"))
    EDGAR_PREFIX = os.getenv("EDGAR_PREFIX", "edgar/")
    # 6-K (foreign private issuer) cyber disclosures land under their own prefix
    # so they never collide with the 8-K dumps. Note the trailing slash keeps
    # "edgar/" and "edgar6k/" as distinct S3 prefixes.
    EDGAR_6K_PREFIX = os.getenv("EDGAR_6K_PREFIX", "edgar6k/")

    # Pipeline (Lambda) — Terraform injects these as env vars
    S3_BUCKET = os.getenv("S3_BUCKET", "cyberloopnews-cve-data")
    STATE_KEY = os.getenv("STATE_KEY", "state/last_fetch.json")
    SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
    # On the very first run (no state file yet) look back this many hours.
    LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "24"))

    # Fetcher window sizing. Each invocation advances the ingest by at most
    # MAX_WINDOWS_PER_RUN steps of FETCH_WINDOW_HOURS each, so the cost of one
    # run is fixed no matter how far behind we are. Raising MAX_WINDOWS_PER_RUN
    # drains a backlog faster; keep the product of the two comfortably inside
    # the Lambda timeout.
    FETCH_WINDOW_HOURS = int(os.getenv("FETCH_WINDOW_HOURS", "1"))
    MAX_WINDOWS_PER_RUN = int(os.getenv("MAX_WINDOWS_PER_RUN", "3"))

    # Enricher: CVE.org vendor/product lookups over recent raw scans. Bounded by
    # both a scan count and a wall-clock budget (Lambda time remaining, minus
    # ENRICH_RESERVE_SECONDS held back so partial progress still gets written).
    ENRICH_MAX_SCANS_PER_RUN = int(os.getenv("ENRICH_MAX_SCANS_PER_RUN", "12"))
    ENRICH_RESERVE_SECONDS = int(os.getenv("ENRICH_RESERVE_SECONDS", "30"))
    # Pacing between CVE.org calls — courtesy to a free third-party API.
    ENRICH_DELAY_SECONDS = float(os.getenv("ENRICH_DELAY_SECONDS", "0.34"))
    # Enricher output: cna/<cve-id>.json in the data bucket. Its own keyspace,
    # so raw/ stays exactly as NVD returned it and nothing read-modify-writes.
    CNA_PREFIX = os.getenv("CNA_PREFIX", "cna/")

    # Analyzer (Bedrock) — scores each CVE and writes analysis/<cve-id>.json to
    # the per-environment analysis bucket (OUTPUT_BUCKET) under this prefix, so
    # outputs are always bound to the branch/env like the rest of the pipeline.
    OUTPUT_BUCKET = os.getenv("OUTPUT_BUCKET")
    OUTPUT_PREFIX = os.getenv("OUTPUT_PREFIX", "analysis/")
    BEDROCK_MODEL_ID = os.getenv(
        "BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    )
    # Batch analyzer: cap CVEs scored per invocation so a burst can't run the
    # Lambda past its timeout; leftovers are picked up on the next run.
    ANALYSIS_MAX_PER_RUN = int(os.getenv("ANALYSIS_MAX_PER_RUN", "50"))

    # DynamoDB read-model: the analyzer mirrors each scored CVE into this table
    # so the site can Query it (by day or by vendor, ranked by score) instead of
    # listing the analysis bucket. Unset means "S3 only" — the mirror write is
    # skipped, which keeps local runs and any not-yet-migrated env working.
    CVE_TABLE = os.getenv("CVE_TABLE")

    # Reporter: how many hours of hourly CVE scans the daily report aggregates.
    REPORT_LOOKBACK_HOURS = int(os.getenv("REPORT_LOOKBACK_HOURS", "24"))

    # Ranking alert: thrice-daily (9am/1pm/5pm ET) top-N LoopScore digest emailed
    # via SNS. It ranks ONLY the CVEs scored since the previous alert, so every
    # send is fresh with no repeats. The "since last alert" boundary is persisted
    # as a marker object (RANKING_STATE_KEY) in the analysis bucket; on the very
    # first run (no marker yet) it looks back RANKING_FIRST_RUN_LOOKBACK_HOURS so
    # the inaugural alert isn't empty.
    RANKING_TOP_N = int(os.getenv("RANKING_TOP_N", "10"))
    RANKING_STATE_KEY = os.getenv("RANKING_STATE_KEY", "ranking-state/last_alert.json")
    RANKING_FIRST_RUN_LOOKBACK_HOURS = int(
        os.getenv("RANKING_FIRST_RUN_LOOKBACK_HOURS", "24")
    )

    # Dashboard data publisher: writes the static site's summary JSON (the top-N
    # LoopScore CVEs the bar chart reads) to the SITE bucket, same-origin with
    # index.html. Reuses RANKING_TOP_N, but ranks a fixed lookback window (not the
    # alert's "since last alert" delta) so the chart always shows a full top-N.
    SITE_BUCKET = os.getenv("SITE_BUCKET")
    DASHBOARD_KEY = os.getenv("DASHBOARD_KEY", "data/top10.json")
    DASHBOARD_LOOKBACK_HOURS = int(os.getenv("DASHBOARD_LOOKBACK_HOURS", "24"))

    # Broadcast script: twice-daily (9am/1pm ET) news script written by Bedrock
    # from the scored CVEs plus the EDGAR breach filings, emailed via SNS. Uses a
    # FIXED lookback rather than the ranking alert's "since last alert" marker —
    # the two slots are only four hours apart, so a delta window would leave the
    # midday show with almost nothing.
    #
    # Its own model, NOT the analyzer's BEDROCK_MODEL_ID: the analyzer runs
    # Haiku because it makes ~1200 short scoring calls a day, while the
    # broadcast is two calls a day whose whole output is prose. Note that Sonnet
    # 5 rejects sampling parameters (`temperature` returns a Bedrock
    # ValidationException) — see the inferenceConfig note in broadcast.py.
    BROADCAST_MODEL_ID = os.getenv(
        "BROADCAST_MODEL_ID", "us.anthropic.claude-sonnet-5"
    )
    BROADCAST_LOOKBACK_HOURS = int(os.getenv("BROADCAST_LOOKBACK_HOURS", "24"))
    BROADCAST_TOP_N = int(os.getenv("BROADCAST_TOP_N", "8"))

    # Red alert: fired by the analyzer's S3 write for each scored CVE. A LoopScore
    # at or above this threshold is rare/critical enough to email immediately,
    # one CVE at a time (see red_alert_handler.py). No schedule or state — the
    # per-CVE S3 event is the trigger and the dedup.
    RED_ALERT_THRESHOLD = int(os.getenv("RED_ALERT_THRESHOLD", "85"))

    # Application
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    @classmethod
    def validate(cls):
        """Validate that all required environment variables are set."""
        if not cls.NIST_API_KEY:
            raise ValueError("NIST_API_KEY is required but not set")
        return True
