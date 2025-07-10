locals {
    ingress_lb_name = "${var.project_name}-${var.environment}-ingress-alb"
   ingress_alb_sg_id = data.aws_ssm_parameter.ingress_alb_sg_id.value
    public_subnet_ids = split(",", data.aws_ssm_parameter.public_subnet_ids.value)
    zone_id = data.aws_route53_zone.zone_info.id
    zone_name = data.aws_route53_zone.zone_info.name
    vpc_id = data.aws_ssm_parameter.vpc_id.value
    
}