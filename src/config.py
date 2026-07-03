import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # NIST NVD API
    NIST_API_KEY = os.getenv("NIST_API_KEY")
    NIST_API_BASE_URL = os.getenv("NIST_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")

    # AWS
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    AWS_PROFILE = os.getenv("AWS_PROFILE", "default")

    # Application
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    @classmethod
    def validate(cls):
        """Validate that all required environment variables are set."""
        if not cls.NIST_API_KEY:
            raise ValueError("NIST_API_KEY is required but not set")
        return True
