resource "aws_ssm_parameter" "vpc_id" {
  name  = "/${var.project_name}/${var.environment}/vpc_id"
  type  = "String"
  value = module.expense_vpc.vpc_info.id
}

resource "aws_ssm_parameter" "public_subnet" {
  name  = "/${var.project_name}/${var.environment}/public_subnet_ids"
  type  = "StringList"
  value = join(",", module.expense_vpc.public_subnet[*].id)
}

resource "aws_ssm_parameter" "private_subnet" {
  name  = "/${var.project_name}/${var.environment}/private_subnet_ids"
  type  = "StringList"
  value = join(",", module.expense_vpc.private_subnet[*].id)
}

resource "aws_ssm_parameter" "database_subnet" {
  name  = "/${var.project_name}/${var.environment}/database_subnet_ids"
  type  = "StringList"
  value = join(",", module.expense_vpc.database_subnet[*].id)
}

resource "aws_ssm_parameter" "database_subnet_group" {
  name  = "/${var.project_name}/${var.environment}/database_subnet_group_id"
  type  = "String"
  value = aws_db_subnet_group.db_subnet_group.name
}

