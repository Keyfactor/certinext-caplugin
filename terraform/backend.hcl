# Populated by terraform/bootstrap — run bootstrap first, then:
#   terraform init -backend-config=backend.hcl
#
# To use local state instead, remove the backend block from providers.tf
# and run: terraform init

resource_group_name  = "rg-tf-state"
storage_account_name = "stkeyfactortfstate"
container_name       = "tfstate"
key                  = "certinext-caplugin/terraform.tfstate"
