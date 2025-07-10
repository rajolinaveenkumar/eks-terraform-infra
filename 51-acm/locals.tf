locals {
    cert_name = "${var.project_name}-${var.environment}-cert"
    zone_id = data.aws_route53_zone.zone_info.id
}