terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.x is required for the per-resource `region` argument, which is what lets a
      # single provider configuration place vaults in any number of Regions.
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}
