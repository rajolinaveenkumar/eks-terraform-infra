terraform {
    required_providers {
        aws = {
            source  = "hashicorp/aws"
            version = "5.98.0"
         }
    }

    backend "s3" {
        bucket = "rnk-s3-bucket"
        key = "security-groups-for-expense-project"
        region = "us-east-1"
        dynamodb_table = "rnk-s3-locking"
    }

   
}

provider "aws" {
  # Configuration options
  region = "us-east-1"
}