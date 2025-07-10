variable "project_name" {
  default = "expense"
}

variable "environment" {
  default = "dev"
}

variable "common_tags" {
  default = {
    Project     = "Expense"
    Environment = "Dev"
    CreatedBy   = "naveenrajoli@rajoli.com"
    Team        = "DevSecOps"
    Application = "Expense Tracker API"
  }
}
