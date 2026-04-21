locals {
  repo_name = "certinext-caplugin"
}

# ── Repository ────────────────────────────────────────────────────────────────

resource "github_repository" "repo" {
  name        = local.repo_name
  description = "Keyfactor AnyCA REST Gateway plugin for CERTInext (eMudhra) certificate lifecycle management."
  visibility  = "internal"

  has_issues      = true
  has_projects    = false
  has_wiki        = false
  has_discussions = false

  # Merge strategy: squash only — enforces conventional commits on merge
  allow_merge_commit     = false
  allow_squash_merge     = true
  allow_rebase_merge     = false
  squash_merge_commit_title   = "PR_TITLE"
  squash_merge_commit_message = "COMMIT_MESSAGES"

  delete_branch_on_merge = true
  allow_auto_merge       = true

  vulnerability_alerts = true

  topics = [
    "keyfactor",
    "certinext",
    "ca-plugin",
    "anycagateway",
    "dotnet",
    "pki",
  ]
}

# ── Team access ───────────────────────────────────────────────────────────────

resource "github_team_repository" "integration_engineers" {
  team_id    = "integration-engineers"
  repository = github_repository.repo.name
  permission = "maintain"
}
