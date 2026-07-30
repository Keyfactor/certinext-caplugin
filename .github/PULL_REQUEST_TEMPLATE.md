## What

<!-- One or two sentences: what does this PR do? -->

## Why

<!-- What problem does it solve, or what improvement does it make? -->

## Testing

<!-- How was this validated? Check all that apply. -->

- [ ] `just test` passes (unit tests)
- [ ] `just integration-test` passes (requires `~/.env_certinext`)
- [ ] `just coverage` shows no coverage regression
- [ ] Terraform changes validated with `terraform plan`
- [ ] Tested only docs/config — no runtime changes

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, etc.) — this becomes the squash commit message on `main`
- [ ] No secrets, credential files, or `~/.env_certinext` content committed
- [ ] `docsource/` updated if behavior or configuration changed
