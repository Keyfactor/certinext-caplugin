terraform {
  required_version = ">= 1.6"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  # Remote state in Azure Blob Storage — run bootstrap first, then:
  #   terraform init -backend-config=backend.hcl
  # To use local state instead (no bootstrap required):
  #   remove this backend block and run: terraform init
  backend "azurerm" {}
}

provider "github" {
  owner = "Keyfactor"
  token = var.github_token
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}
