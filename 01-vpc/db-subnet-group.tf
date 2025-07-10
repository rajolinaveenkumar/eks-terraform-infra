resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${local.db_subnet_group_name}"
  subnet_ids = local.database_subnet_ids

  tags = merge(
        
        var.common_tags,
        {
            Name            =  "${local.db_subnet_group_name}"
            Owner    =  "Naveen Rajoli"
            Terraform       = true
        }
    )
}

