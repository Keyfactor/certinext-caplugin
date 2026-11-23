<!--
Delete any section you have nothing to put in.
Keep it short and plain: say what changed and why, not how you debugged it.
Live-run logs, order IDs and open questions go in the issue, not here.
-->

## Summary

<!-- One or two sentences: what does this PR do, and why? -->

## Breaking Changes

<!-- Anything users must change when they upgrade: settings, defaults, behavior. -->

## Features

<!-- New things the plugin can do. One bullet each. -->

## Fixes

<!-- Bugs fixed. One bullet each: what was wrong, what happens now. -->

## Chores

<!-- Refactors, docs, build, CI, test-only changes. -->

## Testing

<!-- How was this checked? Check what applies and name any new tests. -->

- [ ] `make test` passes (unit tests)
- [ ] `make integration-test` passes (requires `~/.env_certinext`)
- [ ] `make coverage` shows no coverage regression
- [ ] Tested only docs/config — no runtime changes

## Other

<!-- Anything else a reviewer should know. -->

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, etc.) — this becomes the squash commit message on `main`
- [ ] No secrets, credential files, or `~/.env_certinext` content committed
- [ ] `docsource/` updated if behavior or configuration changed
