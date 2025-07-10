resource "aws_ssm_parameter" "ssl_cert_arn" {
    name = "/${var.project_name}/${var.environment}/ssl_cert_arn"
    type = "String"
    value = aws_acm_certificate.cert.arn
}