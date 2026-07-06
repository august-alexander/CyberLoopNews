#!/usr/bin/env python3
"""Test NIST NVD API fetch and S3 storage."""

import json
import requests
import boto3
from datetime import datetime
from src.config import Config

Config.validate()

# Fetch from NIST
print("1. Fetching CVEs from NIST NVD...")
headers = {"apiKey": Config.NIST_API_KEY}
params = {"resultsPerPage": 10}

response = requests.get(Config.NIST_API_BASE_URL, headers=headers, params=params)
data = response.json()

print(f"   ✓ Total CVEs in NVD: {data['totalResults']:,}")
print(f"   ✓ Retrieved: {len(data['vulnerabilities'])} CVEs")

# Upload to S3
print("\n2. Uploading to S3...")
s3 = boto3.client('s3', region_name=Config.AWS_REGION)
bucket = "cyberloopnews-cve-data"
utc_timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
s3_key = f"raw/{utc_timestamp}/cves.json"

s3.put_object(
    Bucket=bucket,
    Key=s3_key,
    Body=json.dumps(data, indent=2),
    ContentType="application/json"
)
print(f"   ✓ Uploaded to: s3://{bucket}/{s3_key}")

# Read back from S3
print("\n3. Reading back from S3...")
response = s3.get_object(Bucket=bucket, Key=s3_key)
retrieved_data = json.loads(response['Body'].read())

print(f"   ✓ Retrieved: {len(retrieved_data['vulnerabilities'])} CVEs")

# Verify
print("\n4. Sample CVEs:")
for vuln in retrieved_data['vulnerabilities'][:3]:
    cve_id = vuln['cve']['id']
    desc = vuln['cve']['descriptions'][0]['value'][:60]
    print(f"   • {cve_id}: {desc}...")

print("\n✓ Test complete! Data lake flow working.")
