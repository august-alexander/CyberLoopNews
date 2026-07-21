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

# Red-alert trigger: every time the analyzer writes a scored result
# (analysis/<id>.json), fire the red-alert Lambda on that object. The prefix +
# suffix filter keeps it to scored results only (never the ranking-state marker
# or any other key). This is the whole trigger — no schedule, one event per CVE.
resource "aws_lambda_permission" "allow_s3_red_alert" {
  statement_id  = "AllowS3InvokeRedAlert"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.red_alert.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.analysis.arn
}

resource "aws_s3_bucket_notification" "analysis" {
  bucket = aws_s3_bucket.analysis.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.red_alert.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "analysis/"
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.allow_s3_red_alert]
}
