# Contributing

Thank you for contributing to D2DAP.

## Repository Workflow

1. Create a new branch from main for each change.
2. Keep commits focused and use descriptive messages.
3. Open a pull request with a clear summary and testing notes.

## Branch Naming

- feature/<short-description>
- chore/<short-description>
- docs/<short-description>
- fix/<short-description>

## Commit Message Conventions

Use the following style:

- feat: add a new feature
- fix: resolve a bug
- docs: update documentation
- chore: update project tooling or maintenance
- test: add or update tests

## Pull Request Guidelines

- Describe the purpose of the change.
- Include testing steps.
- Keep the change scope limited to the task.

## Code Style

- Follow Black formatting.
- Keep imports sorted with isort.
- Use Ruff to find lint issues.
- Add type hints for public Python functions.

## Testing Expectations

- Add or update tests for behavior changes.
- Run pytest before submitting a pull request.
