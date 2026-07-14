# Analysis output bucket — stores per-CVE LoopScore results (analysis/<id>.json).
#
# Named per environment via var.output_bucket_name (dev -> ...-analysis-dev,
# main -> ...-analysis-main), so — together with the environment_guard in
# main.tf that forces workspace == environment — a dev apply can only ever touch
# the dev bucket. Kept separate from the raw CVE data bucket so the future
# dashboard can be granted read on JUST the scored outputs.
#
# No force_destroy: if the bucket has objects, `terraform destroy` will refuse to
# delete it rather than silently wipe scored data.
resource "aws_s3_bucket" "analysis" {
  bucket = var.output_bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "analysis" {
  bucket                  = aws_s3_bucket.analysis.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
