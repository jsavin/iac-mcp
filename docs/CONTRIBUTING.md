# Contributing to IAC-MCP

Thank you for your interest in contributing! This guide will help you get started.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Code Quality Standards](#code-quality-standards)
5. [Testing Requirements](#testing-requirements)
6. [Commit Guidelines](#commit-guidelines)
7. [Pull Request Process](#pull-request-process)
8. [Project Structure](#project-structure)
9. [Common Tasks](#common-tasks)

## Code of Conduct

**Be respectful, constructive, and collaborative.**

This project adheres to professional standards:
- Treat all contributors with respect
- Provide constructive feedback
- Focus on the technical merits
- Help others learn and grow

Unacceptable behavior will not be tolerated.

## Getting Started

### Prerequisites

- **Node.js 20+** (required)
- **macOS** (for full testing, other platforms for development)
- **Git** (for version control)
- **TypeScript** knowledge (intermediate level)

### Initial Setup

1. **Fork and clone:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/iac-mcp.git
   cd iac-mcp
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Build project:**
   ```bash
   npm run build
   ```

4. **Run tests:**
   ```bash
   npm test
   ```

5. **Verify setup:**
   ```bash
   npm run verify
   ```

### Development Environment

**Recommended:**
- **Editor:** VS Code with TypeScript extension
- **Terminal:** iTerm2 or native Terminal.app
- **Tools:** MCP Inspector for testing

**VS Code Extensions:**
- ESLint
- Prettier
- TypeScript and JavaScript Language Features

## Development Workflow

### 1. Create Feature Branch

```bash
# Main repo directory
cd /path/to/iac-mcp

# Create worktree for feature
git worktree add ../iac-mcp-my-feature -b feature/my-feature

# Work in worktree
cd ../iac-mcp-my-feature
```

**Why worktrees?**
- Complete isolation
- No git interference
- IDE-friendly
- Easy cleanup

### 2. Make Changes

```bash
# Edit files
vim src/jitd/discovery/app-discovery.ts

# Build and test continuously
npm run dev  # Watch mode

# In another terminal
npm run test:watch  # Test watch mode
```

### 3. Run Tests

```bash
# All tests
npm test

# Unit tests only
npm run test:unit

# Integration tests only
npm run test:integration

# With coverage
npm run test:coverage
```

**Tests MUST pass before committing.**

### 4. Lint and Format

```bash
# Check for issues
npm run lint

# Auto-fix issues
npm run lint:fix
```

### 5. Commit Changes

```bash
# Stage changes
git add src/jitd/discovery/app-discovery.ts

# Commit with descriptive message
git commit -m "$(cat <<'EOF'
Improve app discovery performance

- Use parallel filesystem scanning
- Cache results to reduce I/O
- Add progress logging

Reduces discovery time from 8s to 3s for 20 apps.

Co-Authored-By: Your Name <your.email@example.com>
EOF
)"
```

See [Commit Guidelines](#commit-guidelines) for details.

### 6. Push and Create PR

```bash
# Push feature branch
git push origin feature/my-feature

# Create PR (use gh CLI or GitHub web)
gh pr create --title "Improve app discovery performance" --body "$(cat <<'EOF'
## Summary
- Parallel filesystem scanning
- Result caching
- Progress logging

## Performance Impact
- Before: 8s for 20 apps
- After: 3s for 20 apps (62.5% improvement)

## Test Plan
- [x] All unit tests pass
- [x] All integration tests pass
- [x] Manual testing with 20+ apps
- [x] No performance regression

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Code Quality Standards

**NON-NEGOTIABLE REQUIREMENTS:**

### 1. 100% Test Coverage

- **NOT 90%. NOT 95%. 100%.**
- Every function must have tests
- Every branch must be tested
- Every error path must be tested

**Why:** Enable development without manual code inspection.

### 2. Zero Code Duplication

- No duplicated logic anywhere
- Extract shared code to utilities
- Parameterize variations
- Delete duplicates completely

**Detection:**
```bash
# Automated check
npx jscpd src/

# Must show: 0 duplications found
```

### 3. DRY Principle

- Don't Repeat Yourself
- Single source of truth
- Reusable components
- Clear abstractions

**Example:**
```typescript
// ❌ BAD: Duplicated logic
function parseFinderSdef() {
  const parser = new XMLParser();
  const xml = readFile('Finder.sdef');
  return parser.parse(xml);
}

function parseSafariSdef() {
  const parser = new XMLParser();
  const xml = readFile('Safari.sdef');
  return parser.parse(xml);
}

// ✅ GOOD: Shared implementation
function parseSdef(appName: string) {
  const parser = new XMLParser();
  const xml = readFile(`${appName}.sdef`);
  return parser.parse(xml);
}
```

### 4. TypeScript Strict Mode

- All code in strict mode
- No `any` types (use `unknown` if needed)
- Explicit return types on public functions
- Proper null handling

### 5. Error Handling

- Use ErrorHandler for all errors
- Categorize errors correctly
- Provide context
- User-friendly messages

**Example:**
```typescript
try {
  const result = await riskyOperation();
  return result;
} catch (error) {
  this.errorHandler.handleError(
    error as Error,
    ErrorCategory.EXECUTION,
    {
      operation: 'riskyOperation',
      context: 'additional-info'
    }
  );
  throw error; // Re-throw if caller should handle
}
```

## Testing Requirements

### Test Structure

```typescript
import { describe, it, expect } from 'vitest';

describe('ComponentName', () => {
  describe('methodName', () => {
    it('should handle happy path', () => {
      // Arrange
      const input = createInput();

      // Act
      const result = component.method(input);

      // Assert
      expect(result).toBe(expected);
    });

    it('should handle error case', () => {
      expect(() => component.method(invalidInput)).toThrow();
    });

    it('should handle edge case', () => {
      const result = component.method(edgeInput);
      expect(result).toMatchObject(expectedPartial);
    });
  });
});
```

### Coverage Requirements

**Required for ALL files:**
- **Statements:** 100%
- **Branches:** 100%
- **Functions:** 100%
- **Lines:** 100%

**Check coverage:**
```bash
npm run test:coverage

# Output must show 100% for all metrics
```

### Test Naming

**Pattern:** `should [expected behavior] [when condition]`

**Examples:**
- ✅ `should discover all apps when SDEF files exist`
- ✅ `should throw error when SDEF is malformed`
- ✅ `should cache results when validation passes`
- ❌ `test discovery` (too vague)
- ❌ `it works` (not descriptive)

### Test Types

1. **Unit Tests:** Test individual functions/classes
   - Fast (<1ms per test)
   - No external dependencies
   - Mocked dependencies

2. **Integration Tests:** Test component interactions
   - Moderate speed (<100ms per test)
   - Real file system (temp directories)
   - Real external processes (where needed)

3. **End-to-End Tests:** Test full workflows
   - Slower (<5s per test)
   - Real applications
   - Full stack

## Commit Guidelines

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `refactor`: Code restructuring (no behavior change)
- `test`: Adding or updating tests
- `perf`: Performance improvement
- `chore`: Maintenance tasks

### Subject

- Use imperative mood ("Add feature" not "Added feature")
- Start with capital letter
- No period at end
- Max 72 characters

### Body

- Explain WHAT and WHY, not HOW
- Wrap at 72 characters
- Separate from subject with blank line

### Footer

```
Co-Authored-By: Name <email@example.com>
```

### Examples

**Good:**
```
feat: Add parallel app discovery

Improve discovery performance by scanning directories in parallel.
Uses Promise.all to scan /Applications and /System/Library
simultaneously.

Reduces discovery time from 8s to 3s for 20 apps.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

**Bad:**
```
updated stuff
```

## Pull Request Process

### Before Creating PR

1. ✅ All tests pass
2. ✅ Coverage is 100%
3. ✅ No linter errors
4. ✅ No code duplication
5. ✅ Documentation updated
6. ✅ CHANGELOG.md updated

### PR Title

Follow commit message format:
```
feat: Add parallel app discovery
fix: Handle malformed SDEF files
docs: Update troubleshooting guide
```

### PR Description

**Template:**
```markdown
## Summary
- Bullet points of changes
- Key improvements
- Related issues

## Motivation
Why this change is needed

## Changes Made
- Detailed list of changes
- File modifications
- New dependencies (if any)

## Test Plan
- [x] Unit tests added/updated
- [x] Integration tests pass
- [x] Manual testing completed
- [x] Performance benchmarked

## Performance Impact
- Before: X ms
- After: Y ms
- Impact: Z% improvement

## Breaking Changes
None / List of breaking changes

## Screenshots (if UI changes)
[screenshots]

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

### PR Review Process

1. **Automated checks:**
   - Tests pass
   - Coverage 100%
   - Linting passes
   - Build succeeds

2. **Code review:**
   - Maintainer reviews code
   - Requests changes if needed
   - Approves when ready

3. **Merge:**
   - Squash and merge (default)
   - Delete branch after merge

### PR Guidelines

**DO:**
- ✅ Keep PRs focused (one feature/fix)
- ✅ Write clear descriptions
- ✅ Add tests for new code
- ✅ Update documentation
- ✅ Respond to feedback promptly

**DON'T:**
- ❌ Mix unrelated changes
- ❌ Submit without tests
- ❌ Break existing functionality
- ❌ Ignore review feedback

## Project Structure

```
iac-mcp/
├── src/
│   ├── index.ts              # MCP server entry point
│   ├── cli.ts                # CLI interface
│   ├── error-handler.ts      # Centralized error handling
│   ├── jitd/                 # JITD engine
│   │   ├── discovery/        # App discovery and SDEF parsing
│   │   ├── tool-generation/  # Tool generation from SDEF
│   │   ├── execution/        # Tool execution
│   │   └── cache/            # Caching layer
│   ├── adapters/             # Platform adapters
│   │   └── macos/            # macOS-specific adapter
│   └── types/                # TypeScript type definitions
├── tests/
│   ├── unit/                 # Unit tests
│   └── integration/          # Integration tests
├── docs/                     # Documentation
├── planning/                 # Project planning docs
└── dist/                     # Compiled output (git-ignored)
```

### File Naming

- **TypeScript:** `kebab-case.ts`
- **Tests:** `component-name.test.ts`
- **Types:** `types.ts` or inline

### Import Order

1. Node.js built-ins
2. External dependencies
3. Internal dependencies (absolute paths)
4. Relative imports

```typescript
import { readFile } from 'fs/promises';
import { XMLParser } from 'fast-xml-parser';
import { ErrorHandler } from '../error-handler.js';
import { SdefParser } from './sdef-parser.js';
```

## Common Tasks

### Adding a New Platform Adapter

1. Create adapter directory: `src/adapters/<platform>/`
2. Implement adapter interface
3. Add discovery logic
4. Write tests (100% coverage)
5. Update documentation
6. Add integration tests

### Adding a New SDEF Type

1. Update `src/jitd/tool-generation/type-mapper.ts`
2. Add mapping logic
3. Update `parameter-marshaler.ts` if needed
4. Add tests for new type
5. Document in API.md

### Adding a New Tool Generator

1. Extend `ToolGenerator` class
2. Implement generation logic
3. Add tests (100% coverage)
4. Update documentation

### Improving Performance

1. Benchmark current performance
2. Identify bottleneck (profiling)
3. Implement optimization
4. Benchmark new performance
5. Document improvement
6. Add regression tests

### Fixing a Bug

1. Reproduce the bug
2. Write failing test
3. Fix the bug
4. Verify test passes
5. Add regression test
6. Document in CHANGELOG.md

## Documentation

### Required Documentation

- **Code comments:** For complex logic
- **JSDoc:** For public APIs
- **README:** For new features
- **CHANGELOG:** For all changes
- **Architecture docs:** For system changes

### Documentation Style

**Code Comments:**
```typescript
/**
 * Parse SDEF file and extract application capabilities
 *
 * @param sdefPath - Absolute path to SDEF file
 * @param bundleId - Application bundle identifier
 * @returns Parsed application capabilities
 * @throws {Error} If SDEF file is malformed or unreadable
 */
async parseSdef(sdefPath: string, bundleId: string): Promise<AppCapabilities>
```

**Markdown:**
- Clear headings
- Code examples
- Blank line before tables (Obsidian requirement)
- Link to related docs

## Getting Help

### Questions?

- Check existing documentation
- Search GitHub issues
- Ask in GitHub Discussions
- Tag maintainers in PR

### Stuck?

- Review similar code in the project
- Check test examples
- Ask for help (don't stay blocked)

### Found a Bug?

1. Search existing issues
2. Create new issue with reproduction
3. Include logs and environment details
4. PR with fix (if you can)

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Thanked in commit messages (Co-Authored-By)

Thank you for contributing! 🎉

## Quick Reference

```bash
# Setup
npm install
npm run build
npm test

# Development
npm run dev          # Watch mode
npm run test:watch   # Test watch mode

# Quality
npm run lint         # Check code
npm run test:coverage # Check coverage
npx jscpd src/      # Check duplication

# Git
git worktree add ../iac-mcp-feature -b feature/name
cd ../iac-mcp-feature

# PR
git push origin feature/name
gh pr create

# Cleanup
git worktree remove ../iac-mcp-feature
```
