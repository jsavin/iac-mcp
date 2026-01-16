# GitHub Actions Setup for Claude Code

This project uses Claude Code for automated code reviews and on-demand assistance.

## Prerequisites

You need to configure the `CLAUDE_CODE_OAUTH_TOKEN` secret in your GitHub repository settings.

## Getting Your OAuth Token

1. Visit [Claude Code OAuth Setup](https://code.anthropic.com/oauth)
2. Follow the instructions to generate an OAuth token for GitHub Actions
3. Copy the token (you'll only see it once)

## Adding the Secret to GitHub

1. Go to your repository on GitHub: `https://github.com/jsavin/iac-mcp`
2. Navigate to **Settings** > **Secrets and variables** > **Actions**
3. Click **New repository secret**
4. Name: `CLAUDE_CODE_OAUTH_TOKEN`
5. Value: Paste the OAuth token you copied
6. Click **Add secret**

## Workflows Enabled

### 1. Automatic Code Review (`claude-code-review.yml`)

- **Triggers**: When a PR is opened or updated
- **What it does**: Claude automatically reviews the PR and posts feedback as a comment
- **Focus areas**:
  - Code quality and best practices
  - Security concerns (especially for SDEF parsing and JXA execution)
  - Test coverage
  - TypeScript type safety
  - JITD architecture alignment

### 2. On-Demand Assistance (`claude.yml`)

- **Triggers**: When you mention `@claude` in:
  - Issue comments
  - PR review comments
  - Issue descriptions
  - PR reviews
- **What it does**: Claude responds to your specific request
- **Examples**:
  - `@claude can you update the PR description?`
  - `@claude please explain this error`
  - `@claude what tests should I add for this?`

## Verifying Setup

After adding the secret, the workflows will automatically run on:
- New pull requests (automatic review)
- Any `@claude` mention in issues or PRs (on-demand help)

You can check workflow runs in the **Actions** tab of your repository.

## Security Notes

- The OAuth token has limited permissions (read-only access to code, ability to comment)
- Claude cannot push code changes directly
- All Claude actions are visible in the Actions tab
- You can revoke the token at any time from the Claude Code dashboard

## Documentation

- [Claude Code GitHub Action](https://github.com/anthropics/claude-code-action)
- [Claude Code CLI Documentation](https://code.claude.com/docs)
