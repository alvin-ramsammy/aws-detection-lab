terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Permanent account baseline: applied once and left in place. It is kept
  # separate from envs/lab so `terraform destroy` on the lab never removes
  # account-wide protections like the S3 public access block.
}

provider "aws" {
  region = var.region

  # Refuses to touch any account except the lab account — a guardrail against
  # applying with the wrong CLI profile.
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      Project   = "aws-detection-lab"
      ManagedBy = "terraform"
    }
  }
}

# Billing metrics only exist in us-east-1, so the billing alarm and its SNS
# topic always live there regardless of the lab region.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      Project   = "aws-detection-lab"
      ManagedBy = "terraform"
    }
  }
}
