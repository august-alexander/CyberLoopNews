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

    # Pipeline (Lambda) — Terraform injects these as env vars
    S3_BUCKET = os.getenv("S3_BUCKET", "cyberloopnews-cve-data")
    STATE_KEY = os.getenv("STATE_KEY", "state/last_fetch.json")
    SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
    # On the very first run (no state file yet) look back this many hours.
    LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "24"))

    # Application
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    @classmethod
    def validate(cls):
        """Validate that all required environment variables are set."""
        if not cls.NIST_API_KEY:
            raise ValueError("NIST_API_KEY is required but not set")
        return True
