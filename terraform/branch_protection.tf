resource "github_repository_ruleset" "main" {
  name        = "main"
  repository  = github_repository.repo.name
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  # Repository admins can bypass — needed for emergency fixes and initial bootstrapping
  bypass_actors {
    actor_id    = 5  # Repository role: admin
    actor_type  = "RepositoryRole"
    bypass_mode = "always"
  }

  rules {
    # Prevent direct pushes — all changes via PR
    deletion                = true
    non_fast_forward        = true
    required_linear_history = true

    pull_request {
      required_approving_review_count   = 1
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = false
      require_last_push_approval        = false
      required_review_thread_resolution = false
    }

    # Uncomment once dotnet-ci has run at least once so the check name is registered:
    # required_status_checks {
    #   required_check {
    #     context        = "Build and Test"
    #     integration_id = 15368  # GitHub Actions app ID
    #   }
    #   strict_required_status_checks_policy = true
    # }
  }
}
