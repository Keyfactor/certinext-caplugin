output "repository_url" {
  description = "HTTPS URL of the created repository."
  value       = github_repository.repo.html_url
}

output "repository_ssh_clone_url" {
  description = "SSH clone URL."
  value       = github_repository.repo.ssh_clone_url
}
