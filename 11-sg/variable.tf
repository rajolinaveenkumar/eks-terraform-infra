

variable "project_name" {
    default = "expense"
}

variable "environment" {
    default = "dev"
}

variable "common_tags" {
    default = {
        Project         = "Expense"
        Environment     = "Dev"
        CreatedBy = "naveenrajoli@rajoli.com"
        Team            = "DevSecOps" 
        Application     = "Expense Tracker API" 
    }
}


variable "bastion_sg_tags" {
    default = {
        Purpose = "bastion security group for bastion servers"
    }
}

variable "mysql_sg_tags" {
    default = {
        Purpose = "mysql security group for mysql servers"
    }
}


variable "app_alb_sg_tags" {
    default = {
        Purpose = "Ingress load balancer group for web servers"
    }
}

