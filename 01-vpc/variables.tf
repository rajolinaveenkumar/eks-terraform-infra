
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

variable "vpc_tags" {
    default = {
        Purpose = "VPC-creation-for-expense-project"
    }
}

variable "cidr_range" {
    default = "10.0.0.0/16"
}

variable "igw_tags" {
    default = {
        Purpose = "Attaching to VPC for public access"
    }
}

variable "public_subnet_cidr" {
    default = ["10.0.1.0/24", "10.0.2.0/24"]

}

variable "public_subnet_tags" {
    default = {
        Purpose = "Creating Public Subnet for web servers"
    }
}

variable "private_subnet_cidr" {
    default = ["10.0.11.0/24", "10.0.12.0/24"]

}

variable "private_subnet_tags" {
    default = {
        Purpose = "Creating private Subnet for backend servers"
    }
}

variable "database_subnet_cidr" {
   default = ["10.0.21.0/24", "10.0.22.0/24"]

}

variable "database_subnet_tags" {
    default = {
        Purpose = "Creating database Subnet for database servers"
    }
}

variable "vpc_peering_tags" {
    default = {
        Name = "VPC Peering between expense vpc and default vpc" 
    }
}
