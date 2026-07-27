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
  bucket        = aws_s3_bucket.site.id
  key           = "index.html"
  source        = "${path.module}/../web/index.html"
  etag          = filemd5("${path.module}/../web/index.html")
  content_type  = "text/html"
  cache_control = "max-age=30" # edge caches 30s, then revalidates — deploys go live within 30s, no invalidation needed
}

# Origin Access Control: lets THIS distribution (and nothing else) read the
# private bucket over SigV4. The modern replacement for the legacy OAI.
resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${local.name_prefix}-site-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# A SECOND origin access control, this one for the search Lambda's Function URL.
# origin_type "lambda" makes CloudFront SigV4-sign each request to the URL, which
# is what lets the Function URL use AWS_IAM auth (see lambda.tf) instead of being
# public — only this distribution can invoke it.
resource "aws_cloudfront_origin_access_control" "search" {
  name                              = "${local.name_prefix}-search-oac"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Cache policy for /api/*. Unlike the site's managed CachingOptimized policy
# (which ignores query strings), the query string IS the request here — vendor,
# days, min_score, limit — so it must be part of the cache key and forwarded to
# the origin. Short TTL: a fresh scored CVE should surface quickly, and identical
# repeat queries still get a cheap edge hit within the window.
resource "aws_cloudfront_cache_policy" "search_api" {
  name        = "${local.name_prefix}-search-api"
  min_ttl     = 0
  default_ttl = 30
  max_ttl     = 60

  parameters_in_cache_key_and_forwarded_to_origin {
    query_strings_config {
      query_string_behavior = "all"
    }
    headers_config {
      header_behavior = "none"
    }
    cookies_config {
      cookie_behavior = "none"
    }
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true
  }
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

  # Second origin: the search Lambda's Function URL. domain_name wants a bare
  # host, but function_url is a full "https://<id>.lambda-url.<region>.on.aws/"
  # — strip the scheme and every slash to leave just the host. custom_origin_config
  # (not S3) because a Function URL is an HTTPS endpoint; the OAC signs the request.
  origin {
    domain_name              = replace(replace(aws_lambda_function_url.search.function_url, "https://", ""), "/", "")
    origin_id                = "search-lambda"
    origin_access_control_id = aws_cloudfront_origin_access_control.search.id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only" # Function URLs are HTTPS-only
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "site-s3"
    viewer_protocol_policy = "redirect-to-https" # never serve the page over plain HTTP
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    # AWS-managed "CachingOptimized" policy: caches by path, ignores cookies/query.
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  }

  # /api/* → the search Lambda. Ordered behaviors are matched before the default,
  # so only /api/* leaves the static origin. The query string is forwarded and
  # cached on (search_api policy); the managed "AllViewerExceptHostHeader" origin
  # request policy passes the viewer's query/headers through while letting
  # CloudFront set the Host the Function URL's SigV4 signature needs.
  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = "search-lambda"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = aws_cloudfront_cache_policy.search_api.id
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac" # managed AllViewerExceptHostHeader
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
