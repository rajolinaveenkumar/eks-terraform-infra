module "expense_vpc" {

    # source = "../../terraform-vpc-module-dev"
    source = "git::https://github.com/rajolinaveenkumar/terraform-vpc-module-dev.git?ref=main"
    project_name = var.project_name
    environment = var.environment
    cidr_range = var.cidr_range
    common_tags = var.common_tags
    vpc_tags = var.vpc_tags
    igw_tags = var.igw_tags
    public_subnet_cidr = var.public_subnet_cidr
    public_subnet_tags = var.public_subnet_tags
    private_subnet_cidr = var.private_subnet_cidr
    private_subnet_tags = var.private_subnet_tags
    database_subnet_cidr = var.database_subnet_cidr
    database_subnet_tags = var.database_subnet_tags
    vpc_peering_tags = var.vpc_peering_tags
    # is_peering_required       = true # This is for peering b/w 2 vpc's
}

