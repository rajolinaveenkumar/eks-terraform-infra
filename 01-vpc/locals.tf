locals {
    db_subnet_group_name = "${var.project_name}-${var.environment}-db-subnet-group"
    database_subnet_ids = module.expense_vpc.database_subnet[*].id
}