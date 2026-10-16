terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Local state on purpose: this lab is destroyed between sessions, and state
  # is gitignored. Move to an S3 backend if more than one machine runs applies.
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
