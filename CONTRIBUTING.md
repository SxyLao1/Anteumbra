# Contributing

Anteumbra uses `dev` as the default branch for the latest development work.
`main` contains promotion-approved, stable changes and is not a direct
development branch.

## Development Flow

1. Start a `feature/...`, `fix/...`, or `chore/...` branch from `dev`.
2. Open a pull request with `dev` as its base branch.
3. Use `Closes #N` or `Fixes #N` in the PR body when the work resolves an
   issue. Use `N/A` when no issue applies.
4. Merge only after the required CI checks and review are complete. Verify that
   every referenced issue is closed after merge.
5. Keep GitHub's repository setting **Automatically delete head branches**
   enabled so merged source branches are deleted by the repository.

## Promotion To Main

When `dev` has passed stable validation, open a promotion pull request from
`dev` to `main`. Do not develop directly on `main` and do not bypass this
promotion pull request. The promotion PR must pass every required check before
merge; tag and publish only from the resulting `main` commit.

## Pull Request Content

Use the repository pull request template. State the change, validation, and
issue closure status. A PR without an associated issue must say `N/A`; do not
invent an issue reference.
