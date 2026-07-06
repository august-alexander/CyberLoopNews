data "aws_caller_identity" "current" {}

# Reference the EXISTING data-lake bucket. We deliberately do not manage it in
# Terraform so `terraform destroy` never touches the CVE data.
data "aws_s3_bucket" "cve_data" {
  bucket = var.s3_bucket_name
}

# Zip the src/ folder into the Lambda deployment package. Re-runs of
# `terraform apply` re-hash this, so code changes redeploy automatically.
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/lambda.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

locals {
  # Every resource name derives from this, so dev/main resources never collide.
  name_prefix = "${var.project}-${var.environment}"
  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    Component   = "cve-pipeline"
  }
}

# Safety interlock: the environment we're deploying (from the -var-file) must
# equal the Terraform workspace. This is what stops a `dev` apply from ever
# mutating the `main` workspace's state, and blocks the "default" workspace.
resource "terraform_data" "environment_guard" {
  input = var.environment

  lifecycle {
    precondition {
      condition     = var.environment == terraform.workspace
      error_message = "environment (${var.environment}) must match the selected workspace (${terraform.workspace}). Run: terraform workspace select ${var.environment}"
    }
  }
}

terraform {
  backend "s3" {
    bucket       = "cyberloopnews-state-221876793592-us-east-1-an"
    key          = "terraform.tfstate" # Path inside the bucket
    region       = "us-east-1"         # Your AWS region
    encrypt      = true                # Encrypts state at rest
    use_lockfile = true                # Enables native S3 state locking
  }
}

