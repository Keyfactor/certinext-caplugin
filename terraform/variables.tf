variable "github_token" {
  description = "GitHub Personal Access Token with repo, admin:org, and workflow scopes."
  type        = string
  sensitive   = true
}

variable "azure_subscription_id" {
  description = "Azure subscription ID for the Terraform remote state backend."
  type        = string
  default     = "b3114ff1-bb92-45b6-9bd6-e4a1eed8c91e"
}
