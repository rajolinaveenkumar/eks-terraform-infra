# Bastion Security Group
module "bastion_sg" {
    # source = "../../terraform-sg-module-dev"
    source = "git::https://github.com/rajolinaveenkumar/terraform-sg-module-dev.git?ref=main"
    sg_name = "bastion"
    description = "Bastion Security group to make inbound and outbound"
    vpc_id = data.aws_ssm_parameter.vpc_id.value
    project_name = var.project_name
    environment = var.environment
    common_tags = var.common_tags
    bastion_sg_tags = var.bastion_sg_tags
}

# mysql Security Group
module "mysql_sg" {
    # source = "../../terraform-sg-module-dev"
    source = "git::https://github.com/rajolinaveenkumar/terraform-sg-module-dev.git?ref=main"
    sg_name = "mysql-sg"
    description = "mysql Security group for expense project"
    vpc_id = data.aws_ssm_parameter.vpc_id.value
    project_name = var.project_name
    environment = var.environment
    common_tags = var.common_tags
    mysql_sg_tags = var.mysql_sg_tags
}

# eks control plan Security Group
module "eks_master_sg" {
    # source = "../../terraform-sg-module-dev"
    source = "git::https://github.com/rajolinaveenkumar/terraform-sg-module-dev.git?ref=main"
    sg_name = "eks-master-sg"
    description = "eks control plan Security group for expense project"
    vpc_id = data.aws_ssm_parameter.vpc_id.value
    project_name = var.project_name
    environment = var.environment
    common_tags = var.common_tags
    
}

# eks nodes Security Group
module "eks_nodes_sg" {
    # source = "../../terraform-sg-module-dev"
    source = "git::https://github.com/rajolinaveenkumar/terraform-sg-module-dev.git?ref=main"
    sg_name = "eks-nodes-sg"
    description = "eks nodes Security group for expense project"
    vpc_id = data.aws_ssm_parameter.vpc_id.value
    project_name = var.project_name
    environment = var.environment
    common_tags = var.common_tags
    
}

# ingress ALB Security Group
module "ingress_alb_sg" {
    # source = "../../terraform-sg-module-dev"
    source = "git::https://github.com/rajolinaveenkumar/terraform-sg-module-dev.git?ref=main"
    sg_name = "ingress-alb-sg"
    description = "Ingress Load Balancer group for expense project"
    vpc_id = data.aws_ssm_parameter.vpc_id.value
    project_name = var.project_name
    environment = var.environment
    common_tags = var.common_tags
    app_alb_sg_tags = var.app_alb_sg_tags
}



# Bastion host accepting tarrfic from internet on port number 22
resource "aws_security_group_rule" "local_bastion" {
    type = "ingress"
    from_port = 22
    to_port = 22
    protocol       = "tcp"
    security_group_id = module.bastion_sg.sg_info.id
    cidr_blocks         = ["0.0.0.0/0"]
  
}


# mysql SG accepting traffic from bastion security group on port number 3306
resource "aws_security_group_rule" "bastion_mysql" {
    type = "ingress"
    from_port = 3306
    to_port = 3306
    protocol       = "tcp"
    
    source_security_group_id = module.bastion_sg.sg_info.id
    security_group_id = module.mysql_sg.sg_info.id
  
}

# mysql SG accepting traffic from eks node security group on port number 3306
resource "aws_security_group_rule" "nodes_mysql" {
    type = "ingress"
    from_port = 3306
    to_port = 3306
    protocol       = "tcp"
    source_security_group_id = module.eks_nodes_sg.sg_info.id
    security_group_id = module.mysql_sg.sg_info.id
  
}

# eks control plane SG accepting tarffic from eks nodes group 
resource "aws_security_group_rule" "eks_node_eks_control_plane" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = module.eks_nodes_sg.sg_info.id
  security_group_id        = module.eks_master_sg.sg_info.id
}

# eks nodes SG accepting traffic from eks control plain
resource "aws_security_group_rule" "eks_control_plane_eks_node" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = module.eks_master_sg.sg_info.id
  security_group_id        = module.eks_nodes_sg.sg_info.id
}

# ingress alb SG accepting traffic from internet
resource "aws_security_group_rule" "internet_ingress_alb" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id        = module.ingress_alb_sg.sg_info.id
}

# eks control plane SG accepting tarffic from  bastion server on port number 443
resource "aws_security_group_rule" "bastion_eks" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = module.bastion_sg.sg_info.id
  security_group_id        = module.eks_master_sg.sg_info.id
}


# eks nodes SG accepting traffic from ingress alb sg on 30000 t0 32767
resource "aws_security_group_rule" "ingress_nodes" {
  type                     = "ingress"
  from_port                = 30000
  to_port                  = 32767
  protocol                 = "tcp"
  source_security_group_id = module.ingress_alb_sg.sg_info.id
  security_group_id        = module.eks_nodes_sg.sg_info.id
}

# eks nodes SG accepting tarffic from  bastion server on port number 22
resource "aws_security_group_rule" "bastion_nodes" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = module.bastion_sg.sg_info.id
  security_group_id        = module.eks_nodes_sg.sg_info.id
}

# ingress alb SG accepting traffic from bastion on port number 443
resource "aws_security_group_rule" "ingress_bastion_https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = module.bastion_sg.sg_info.id
  security_group_id        = module.ingress_alb_sg.sg_info.id
}

# ingress alb SG accepting traffic from bastion on port number 80
resource "aws_security_group_rule" "ingress_bastion_http" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = module.bastion_sg.sg_info.id
  security_group_id        = module.ingress_alb_sg.sg_info.id
}

#  eks nodes SG accepting tarffic from  our vpc
resource "aws_security_group_rule" "vpc_node" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks = ["10.0.0.0/16"] # This huge mistake, if value is tcp, DNS will work in EKS. UDP traffic is required.So make it all traffic.
  security_group_id = module.eks_nodes_sg.sg_info.id
}

#  eks nodes SG accepting tarffic from  alb ingress
resource "aws_security_group_rule" "ingress_eks_nodes" {
  type              = "ingress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  source_security_group_id = module.ingress_alb_sg.sg_info.id
  security_group_id = module.eks_nodes_sg.sg_info.id
}