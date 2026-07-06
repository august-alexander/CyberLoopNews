terraform {
  required_version = ">= 1.10.0" # use_lockfile (native S3 state locking) needs 1.10+

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}
