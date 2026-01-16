# GitHub Actions Setup for Claude Code

This project uses Claude Code for automated code reviews and on-demand assistance.

## Setup Steps

There are **two required steps** to enable Claude Code on this repository:

### Step 1: Install the Claude Code GitHub App

1. Go to https://github.com/apps/claude
2. Click "Install" or "Configure"
3. Select repository access:
   - Choose "Only select repositories"
   - Select `jsavin/iac-mcp`
4. Click "Install" or "Save"

**This step grants Claude the permissions to access the repo and post comments.**

### Step 2: Configure the OAuth Token

1. Visit [Claude Code OAuth Setup](https://code.anthropic.com/oauth)
2. Follow the instructions to generate an OAuth token for GitHub Actions
3. Copy the token (you'll only see it once)
4. Go to your repository on GitHub: `https://github.com/jsavin/iac-mcp`
5. Navigate to **Settings** > **Secrets and variables** > **Actions**
6. Click **New repository secret**
7. Name: `CLAUDE_CODE_OAUTH_TOKEN`
8. Value: Paste the OAuth token you copied
9. Click **Add secret**

**This token authenticates Claude's actions in the workflows.**

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
