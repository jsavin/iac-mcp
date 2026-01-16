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

### Step 2: Configure the Anthropic API Key

1. Get your Anthropic API key from https://console.anthropic.com/settings/keys
2. Copy the API key (starts with `sk-ant-`)
3. Go to your repository on GitHub: `https://github.com/jsavin/iac-mcp`
4. Navigate to **Settings** > **Secrets and variables** > **Actions**
5. Click **New repository secret**
6. Name: `ANTHROPIC_API_KEY`
7. Value: Paste your Anthropic API key
8. Click **Add secret**

**This API key authenticates Claude's actions in the workflows.**

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

- The API key is stored securely as a GitHub secret (encrypted at rest)
- Claude has read-only access to code and can only comment on PRs/issues
- Claude cannot push code changes directly (unless you modify the allowed tools)
- All Claude actions are visible in the Actions tab
- You can revoke the API key at any time from the Anthropic Console

## Documentation

- [Claude Code GitHub Action](https://github.com/anthropics/claude-code-action)
- [Claude Code CLI Documentation](https://code.claude.com/docs)
