resource "aws_ssm_parameter" "bastion_sg_id" {
    name = "/${var.project_name}/${var.environment}/bastion_sg_id"
    type = "String"
    value = module.bastion_sg.sg_info.id
}

resource "aws_ssm_parameter" "mysql_sg_id" {
    name = "/${var.project_name}/${var.environment}/mysql_sg_id"
    type = "String"
    value = module.mysql_sg.sg_info.id
}

resource "aws_ssm_parameter" "eks_master_sg_id" {
    name = "/${var.project_name}/${var.environment}/eks_master_sg_id"
    type = "String"
    value = module.eks_master_sg.sg_info.id
}

resource "aws_ssm_parameter" "eks_nodes_sg_id" {
    name = "/${var.project_name}/${var.environment}/eks_nodes_sg_id"
    type = "String"
    value = module.eks_nodes_sg.sg_info.id
}

resource "aws_ssm_parameter" "ingress_alb_sg_id" {
    name = "/${var.project_name}/${var.environment}/ingress_alb_sg_id"
    type = "String"
    value = module.ingress_alb_sg.sg_info.id
}