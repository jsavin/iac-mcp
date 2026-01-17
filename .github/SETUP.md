# Development Setup Guide

This document covers both development environment setup and GitHub Actions configuration for the iac-mcp project.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Testing Setup](#testing-setup)
- [Claude Desktop Integration](#claude-desktop-integration)
- [GitHub Actions Setup](#github-actions-setup)

## Development Environment Setup

### Prerequisites

1. **macOS**: Monterey (12.0) or later
2. **Node.js**: Version 20.11 or later
3. **Git**: Latest version
4. **Claude Desktop**: For testing MCP integration (optional but recommended)

### Initial Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/jsavin/iac-mcp.git
   cd iac-mcp
   ```

2. **Install Node.js 20+** (if not already installed):

   **Option 1: Using Homebrew**
   ```bash
   brew install node@20
   ```

   **Option 2: Using nvm**
   ```bash
   nvm install 20
   nvm use 20
   ```

   **Option 3: Using Volta**
   ```bash
   # Volta will automatically use the version specified in .node-version
   cd iac-mcp
   ```

3. **Install dependencies**:
   ```bash
   npm ci
   ```

   Note: Use `npm ci` for clean installs to ensure exact dependency versions from `package-lock.json`.

4. **Build the project**:
   ```bash
   npm run build
   ```

5. **Verify setup**:
   ```bash
   npm run verify
   ```

   This will check your Node.js version and ensure the build succeeds.

### Development Workflow

1. **Watch mode** (auto-rebuild on changes):
   ```bash
   npm run dev
   ```

2. **Run tests**:
   ```bash
   npm test              # Run all tests
   npm run test:watch    # Watch mode
   npm run test:unit     # Unit tests only
   npm run test:integration  # Integration tests only
   ```

3. **Lint code**:
   ```bash
   npm run lint          # Check for issues
   npm run lint:fix      # Auto-fix issues
   ```

4. **Clean build**:
   ```bash
   npm run clean         # Remove dist/
   npm run build         # Rebuild
   ```

### Project Structure

```
iac-mcp/
├── src/                    # Source code
│   ├── index.ts           # MCP server entry point
│   ├── jitd/              # JITD engine
│   ├── adapters/          # Platform adapters
│   ├── mcp/               # MCP protocol implementation
│   ├── permissions/       # Permission system
│   └── types/             # TypeScript types
├── tests/                 # Tests
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
├── dist/                  # Compiled output (generated)
├── docs/                  # Documentation
├── planning/              # Vision, roadmap, decisions
└── tools/                 # Development scripts
```

### Code Quality Standards

This project enforces strict code quality standards:

1. **100% Test Coverage**: All code must be fully tested
2. **Zero Code Duplication**: Automated detection via jscpd
3. **TypeScript Strict Mode**: No `any` types, full type safety
4. **ESLint**: No warnings or errors allowed

Before committing:
```bash
npm test                   # Must pass with 100% coverage
npm run lint               # Must pass with no errors
npx jscpd src/            # Must show zero duplications
```

See [CODE-QUALITY.md](../CODE-QUALITY.md) for complete standards.

## Testing Setup

### Unit and Integration Tests

All tests use Vitest and are located in `tests/`:

```bash
# Run all tests with coverage
npm run test:coverage

# Run specific test file
npx vitest run tests/unit/jitd/discovery/sdef-parser.test.ts

# Debug tests
npx vitest --inspect-brk
```

### MCP Inspector Testing

The MCP Inspector is essential for testing the server before integrating with Claude Desktop:

```bash
# Start MCP Inspector
npx @modelcontextprotocol/inspector node dist/index.js
```

This opens a browser interface where you can:
- List available tools
- Call tools with test inputs
- Inspect request/response payloads
- Debug server behavior

See [docs/MANUAL-TESTING.md](../docs/MANUAL-TESTING.md) for comprehensive test procedures.

## Claude Desktop Integration

### Configuration

1. **Locate the config file**:
   ```bash
   ~/Library/Application Support/Claude/claude_desktop_config.json
   ```

2. **Get your absolute path**:
   ```bash
   cd /path/to/iac-mcp
   pwd
   # Copy the output
   ```

3. **Add server configuration**:
   ```json
   {
     "mcpServers": {
       "iac-mcp": {
         "command": "node",
         "args": ["/absolute/path/to/iac-mcp/dist/index.js"],
         "env": {
           "NODE_ENV": "production"
         }
       }
     }
   }
   ```

4. **Restart Claude Desktop**: Completely quit (Cmd+Q) and relaunch.

### Verification

In Claude Desktop, start a new conversation and try:
```
Can you show me what tools are available from iac-mcp?
```

or

```
Use the example_tool to echo "Hello from Claude Desktop"
```

### Monitoring Logs

Server logs are written to stderr. To view them:

```bash
# Option 1: Run server manually and watch logs
node dist/index.js
# Then interact with Claude Desktop
# Logs appear in this terminal

# Option 2: Check Claude Desktop's developer console
# (If available in your version)
```

### Troubleshooting

**Server not appearing:**
1. Verify absolute path is correct in config
2. Ensure project is built: `npm run build`
3. Check JSON syntax in config file
4. Restart Claude Desktop completely

**Tools not working:**
1. Test with MCP Inspector first
2. Check server logs for errors
3. Verify Node.js version: `node --version`

See [README.md](../README.md#troubleshooting-claude-desktop-integration) for more troubleshooting tips.

## GitHub Actions Setup

This project uses Claude Code for automated code reviews and on-demand assistance.

### Setup Steps

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

1. Go to your repository on GitHub: `https://github.com/jsavin/iac-mcp`
2. Navigate to **Settings** > **Secrets and variables** > **Actions**
3. Click **New repository secret**
4. Name: `CLAUDE_CODE_OAUTH_TOKEN`
5. Value: Paste the same OAuth token you use for other repositories (same token as Frontier)
6. Click **Add secret**

**This OAuth token authenticates Claude's actions in the workflows.**

**Note:** If you need to generate a new OAuth token, you can get one from the Claude Code setup process. The same token can be used across multiple repositories.

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

- The OAuth token is stored securely as a GitHub secret (encrypted at rest)
- Claude has read-only access to code and can only comment on PRs/issues
- Claude cannot push code changes directly (unless you modify the allowed tools)
- All Claude actions are visible in the Actions tab
- You can revoke the OAuth token at any time from the Claude Code dashboard

## Documentation

- [Claude Code GitHub Action](https://github.com/anthropics/claude-code-action)
- [Claude Code CLI Documentation](https://code.claude.com/docs)
