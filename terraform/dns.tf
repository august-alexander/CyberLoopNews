# Custom domain for the dashboard (cyberloops.net + www), fully automated.
#
# DNS lives in Route 53, so Terraform owns the entire chain — no registrar UI:
#   1. Request an ACM cert for the apex + www.
#   2. Write the DNS records that PROVE we own the domain (ACM checks these).
#   3. Wait for validation, then hand the cert to CloudFront (see frontend.tf).
#   4. Point the apex + www at the CloudFront distribution via alias records.
#
# The whole thing is gated on var.dashboard_domain being set, so an environment
# with no domain (e.g. main today) just skips all of this and keeps the plain
# *.cloudfront.net URL. CloudFront certs MUST be in us-east-1, which the stack
# already is, so no separate provider is needed.

locals {
  use_custom_domain = var.dashboard_domain != ""

  # The zone to write records into. For an apex domain it IS the domain; for a
  # subdomain (dev.cyberloops.net) the records still live in the parent zone.
  zone_name = var.dns_zone_name != "" ? var.dns_zone_name : var.dashboard_domain

  # Serve the apex and www off the same distribution so www.* never 404s. A
  # subdomain sets dashboard_include_www = false and gets just the one name.
  domain_aliases = local.use_custom_domain ? concat(
    [var.dashboard_domain],
    var.dashboard_include_www ? ["www.${var.dashboard_domain}"] : [],
  ) : []

  # every alias × A/AAAA -> one alias record each (AAAA needs is_ipv6_enabled on
  # the distribution, set in frontend.tf). Keyed by "host-type" for for_each, so
  # dropping www drops its two records and nothing else.
  alias_records = local.use_custom_domain ? {
    for pair in setproduct(local.domain_aliases, ["A", "AAAA"]) :
    "${pair[0]}-${pair[1]}" => { name = pair[0], type = pair[1] }
  } : {}
}

# The existing hosted zone Route 53 created for the domain. Referenced, not
# managed, so Terraform never risks deleting your zone.
data "aws_route53_zone" "site" {
  count        = local.use_custom_domain ? 1 : 0
  name         = "${local.zone_name}."
  private_zone = false
}

resource "aws_acm_certificate" "site" {
  count                     = local.use_custom_domain ? 1 : 0
  domain_name               = var.dashboard_domain
  subject_alternative_names = var.dashboard_include_www ? ["www.${var.dashboard_domain}"] : []
  validation_method         = "DNS"
  tags                      = local.tags

  # A cert can't be modified in place; make the new one before destroying the
  # old so a domain change never leaves CloudFront with no valid cert.
  lifecycle {
    create_before_destroy = true
  }
}

# The DNS records ACM tells us to publish to prove domain ownership. One per
# distinct validation name (apex + www may share one).
resource "aws_route53_record" "cert_validation" {
  for_each = local.use_custom_domain ? {
    for dvo in aws_acm_certificate.site[0].domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id         = data.aws_route53_zone.site[0].zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

# Blocks until ACM sees the validation records and issues the cert. CloudFront
# consumes this resource's cert ARN, so the domain is never attached un-validated.
resource "aws_acm_certificate_validation" "site" {
  count                   = local.use_custom_domain ? 1 : 0
  certificate_arn         = aws_acm_certificate.site[0].arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}

# Point the apex + www at CloudFront. Route 53 alias records work at the apex
# (a plain CNAME can't), and cost nothing per query.
resource "aws_route53_record" "site_alias" {
  for_each = local.alias_records

  zone_id = data.aws_route53_zone.site[0].zone_id
  name    = each.value.name
  type    = each.value.type

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}
