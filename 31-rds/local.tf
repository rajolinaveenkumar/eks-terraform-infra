locals {
    
   rds_name = "${var.project_name}-${var.environment}-rds"
    db_subnet_group = data.aws_ssm_parameter.db_subnet_group.value
    mysql_sg_id = data.aws_ssm_parameter.mysql_sg_id.value
    zone_id = data.aws_route53_zone.get_domain.id
  zone_name = data.aws_route53_zone.get_domain.name
}