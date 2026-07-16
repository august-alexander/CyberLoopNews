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

    # Application
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    @classmethod
    def validate(cls):
        """Validate that all required environment variables are set."""
        if not cls.NIST_API_KEY:
            raise ValueError("NIST_API_KEY is required but not set")
        return True
