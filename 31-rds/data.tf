
# database Subnet 
data "aws_ssm_parameter" "database_subnet_id" {
    name = "/${var.project_name}/${var.environment}/database_subnet_ids"
}

data "aws_ssm_parameter" "mysql_sg_id" {
    name = "/${var.project_name}/${var.environment}/mysql_sg_id"
}

# database Subnet group 
 data "aws_ssm_parameter" "db_subnet_group" {
    name = "/${var.project_name}/${var.environment}/database_subnet_group_id"
 }

 data "aws_route53_zone" "get_domain" {
  name         = "naveenrajoli.site"
  
}
