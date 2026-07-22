# Static single-page dashboard hosting.
#
# The site's files live in a PRIVATE S3 bucket and are served ONLY through
# CloudFront (never directly public) — same locked-down posture as the analysis
# bucket. Per environment (cyberloopnews-dev-site / cyberloopnews-main-site) so
# the branches get independent sites and a dev deploy can't touch the prod page.
#
# This is deliberately the whole frontend stack: a bucket, one HTML file, and a
# CDN in front of it. No API, no server, no build step — the browser fetches a
# static page (and, later, a single aggregated dashboard.json).

resource "aws_s3_bucket" "site" {
  bucket = "${local.name_prefix}-site"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload the page. etag = filemd5 makes `terraform apply` re-upload whenever
# web/index.html changes, so "edit the file + apply" is the entire deploy step.
# (CloudFront still caches the old copy at the edge until its TTL expires — see
# the invalidation note in outputs.tf / the deploy handover.)
resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.site.id
  key          = "index.html"
  source       = "${path.module}/../web/index.html"
  etag         = filemd5("${path.module}/../web/index.html")
  content_type = "text/html"
}

# Origin Access Control: lets THIS distribution (and nothing else) read the
# private bucket over SigV4. The modern replacement for the legacy OAI.
resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${local.name_prefix}-site-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true # serve IPv6 clients; required for the AAAA alias records.
  default_root_object = "index.html"
  comment             = "${local.name_prefix} dashboard"
  price_class         = "PriceClass_100" # North America + Europe edges only — cheapest tier.
  tags                = local.tags

  # Custom domain(s) — empty unless var.dashboard_domain is set (see dns.tf).
  aliases = local.domain_aliases

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "site-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  default_cache_behavior {
    target_origin_id       = "site-s3"
    viewer_protocol_policy = "redirect-to-https" # never serve the page over plain HTTP
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    # AWS-managed "CachingOptimized" policy: caches by path, ignores cookies/query.
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # With a custom domain: use the validated ACM cert (SNI). Without one: fall
  # back to the free CloudFront cert on the *.cloudfront.net domain. The nulls
  # omit the args that don't apply to each case.
  viewer_certificate {
    cloudfront_default_certificate = local.use_custom_domain ? null : true
    acm_certificate_arn            = local.use_custom_domain ? aws_acm_certificate_validation.site[0].certificate_arn : null
    ssl_support_method             = local.use_custom_domain ? "sni-only" : null
    minimum_protocol_version       = local.use_custom_domain ? "TLSv1.2_2021" : null
  }
}

# Bucket policy: allow ONLY this distribution to read objects, enforced by
# matching its ARN. Nothing else — no user, no other service — can read the bucket.
data "aws_iam_policy_document" "site" {
  statement {
    sid       = "AllowCloudFrontRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = data.aws_iam_policy_document.site.json
}
