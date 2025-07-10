resource "aws_lb" "ingress_alb" {
  name = local.ingress_lb_name
  internal = false
  load_balancer_type = "application"
  security_groups = [local.ingress_alb_sg_id]
  subnets = local.public_subnet_ids

 enable_deletion_protection = false # Prevents accidental deletion


  tags = merge(
    var.common_tags,
    {
      Name      = local.ingress_lb_name
      Owner     = "Naveen Rajoli"
      Terraform = true
    }
  )
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.ingress_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_ssm_parameter.ssl_cert_arn.value

  
  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/html"
      message_body = "<h1>Expense App Site Under Maintenance. Please check back later.</h1>"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener_rule" "backend" {
  listener_arn = aws_lb_listener.front_end.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target_group.arn
  }
  condition {
    host_header {
      values = ["expense-${var.environment}.${local.zone_name}"]
    }
  }
}

# Target Group
resource "aws_lb_target_group" "target_group" {
  name     = "${var.project_name}-${var.environment}-frontend-TG"
  target_type = "instance"
  port     = 80
  protocol = "HTTP"
  vpc_id   = local.vpc_id
  deregistration_delay = 60

  health_check {
    path                = "/health"
    protocol            = "HTTP"
    port                = "8080"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
    matcher = "200-299"
  }
}

resource "aws_route53_record" "ingress_alb" {
  zone_id = local.zone_id
  name    = "*.${local.zone_name}"
  type    = "A"
  allow_overwrite = true

  # These are ALB DNS names and zone id information
  alias {
    name                   = aws_lb.ingress_alb.dns_name
    zone_id                = aws_lb.ingress_alb.zone_id
    evaluate_target_health = false
  }
}