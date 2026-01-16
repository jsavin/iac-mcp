# Code Quality Standards

## Overview

This document defines mandatory code quality standards for the iac-mcp project. These standards ensure maintainability, reliability, and enable development without requiring manual code inspection.

**Philosophy:** Code quality is not negotiable. We build for the long term.

---

## Test Coverage Requirements

### Mandatory: 100% Coverage

**All production code MUST have 100% test coverage** through some reasonable combination of:
- Unit tests
- Integration tests
- End-to-end tests

**Rationale:** 100% coverage enables:
- Fearless refactoring
- Confident deployments
- Documentation through tests
- Development without manual code inspection
- Automated verification of all code paths

### Coverage Measurement

**Tools:**
```bash
# Run tests with coverage
npm run test:coverage

# View coverage report
npm run coverage:report

# Enforce 100% threshold (fails if < 100%)
npm run test:ci
```

**Configuration (vitest.config.ts):**
```typescript
export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      all: true,
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'src/**/*.spec.ts',
        'src/tools/**',  // Demo/utility scripts
        'src/types/**',  // Type definitions only
      ],
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100,
      },
    },
  },
});
```

### What Counts as Coverage

**Unit tests:**
- Test individual functions/classes in isolation
- Mock dependencies
- Cover all branches and edge cases

**Integration tests:**
- Test modules working together
- Real dependencies (no mocks)
- Cover critical paths and error scenarios

**Acceptable combinations:**
- 70% unit + 30% integration = 100% total ✅
- 100% unit only = 100% total ✅
- 50% unit + 50% integration = 100% total ✅

**What matters:** Every line, branch, and function is executed by at least one test.

### Exclusions from Coverage

**Type definitions only (no logic):**
- Pure TypeScript interfaces
- Type aliases
- Enums without methods

**Demo/tool scripts:**
- Files in `src/tools/` (not part of production code)
- Example scripts

**Generated code:**
- Auto-generated type definitions
- Build artifacts

### Enforcement

**Pre-commit hook:**
```bash
# .git/hooks/pre-commit
npm run test:coverage
if [ $? -ne 0 ]; then
  echo "❌ Tests failed or coverage < 100%"
  exit 1
fi
```

**CI/CD pipeline:**
```yaml
# .github/workflows/ci.yml
- name: Run tests with coverage
  run: npm run test:ci

- name: Enforce 100% coverage
  run: |
    if ! grep -q "All files.*100.*100.*100.*100" coverage/coverage-summary.json; then
      echo "❌ Coverage below 100%"
      exit 1
    fi
```

**Pull request requirement:**
- CI must pass (includes coverage check)
- PRs with < 100% coverage are automatically blocked

---

## DRY Principle: Don't Repeat Yourself

### Zero Tolerance for Duplication

**Rule:** No duplicated code. Period.

**Duplicated code is defined as:**
- Same logic in 2+ places (even with different variable names)
- Similar patterns that could be abstracted
- Copy-pasted code blocks
- Parallel implementations of same concept

**Examples of violations:**

❌ **Bad: Duplicated validation logic**
```typescript
// In file1.ts
function validateAppPath(path: string) {
  if (!path || typeof path !== 'string' || path.trim() === '') {
    throw new Error('Invalid path');
  }
}

// In file2.ts
function validateSdefPath(path: string) {
  if (!path || typeof path !== 'string' || path.trim() === '') {
    throw new Error('Invalid path');
  }
}
```

✅ **Good: Shared validation utility**
```typescript
// src/utils/validation.ts
export function validatePath(path: string, context?: string): void {
  if (!path || typeof path !== 'string' || path.trim() === '') {
    const msg = context ? `Invalid ${context} path` : 'Invalid path';
    throw new Error(msg);
  }
}

// In file1.ts
validatePath(appPath, 'app');

// In file2.ts
validatePath(sdefPath, 'SDEF');
```

### When to Refactor to Shared Code

**Immediate refactoring required when:**

1. **Identical logic in 2+ files** (even if small)
   - Extract to shared utility
   - Location: `src/utils/` or module-specific `common.ts`

2. **Similar patterns with slight variations**
   - Extract to parameterized function
   - Use generics if type-dependent

3. **Copy-paste anywhere**
   - If you copied it, refactor it immediately
   - No exceptions

4. **Parallel implementations**
   - Multiple ways to do the same thing
   - Standardize on one approach
   - Extract to shared code

### Where to Place Shared Code

**Project-wide utilities:**
```
src/utils/
├── validation.ts      # Input validation utilities
├── path-utils.ts      # Path manipulation helpers
├── type-guards.ts     # TypeScript type guards
└── index.ts           # Re-exports
```

**Module-specific shared code:**
```
src/jitd/discovery/
├── common.ts          # Shared within discovery module
├── find-sdef.ts       # Uses common.ts
└── parse-sdef.ts      # Uses common.ts
```

**Domain-specific shared code:**
```
src/jitd/
├── common/            # Shared across all JITD modules
│   ├── cache.ts       # Generic caching utilities
│   ├── errors.ts      # Custom error classes
│   └── index.ts
├── discovery/
├── tool-generator/
└── executor/
```

### Refactoring Guidelines

**How to extract shared code:**

1. **Identify duplication** (manual review or automated tools)
2. **Analyze variations** (what's the same, what differs?)
3. **Design abstraction** (parameterize differences)
4. **Extract to shared module** (choose appropriate location)
5. **Replace all usages** (update all call sites)
6. **Test thoroughly** (ensure behavior unchanged)
7. **Delete old code** (remove duplicates completely)

**Example refactoring process:**

```typescript
// Step 1: Identify duplication
// File A has:
const cached = cache.get(key);
if (cached) {
  return cached;
}
const result = await compute();
cache.set(key, result);
return result;

// File B has:
const cached = cache.get(id);
if (cached) {
  return cached;
}
const data = await fetch();
cache.set(id, data);
return data;

// Step 2: Design abstraction
async function withCache<T>(
  cache: Map<string, T>,
  key: string,
  compute: () => Promise<T>
): Promise<T> {
  const cached = cache.get(key);
  if (cached) return cached;

  const result = await compute();
  cache.set(key, result);
  return result;
}

// Step 3: Replace usages
// File A:
return withCache(cache, key, () => compute());

// File B:
return withCache(cache, id, () => fetch());
```

### Automated Duplication Detection

**Tools to use:**

**jscpd (Copy-Paste Detector):**
```bash
# Install
npm install -D jscpd

# Run detection
npx jscpd src/

# Configuration (.jscpd.json)
{
  "threshold": 0,  // Zero tolerance
  "reporters": ["html", "console"],
  "ignore": ["**/*.test.ts", "**/types/**"],
  "format": ["typescript"],
  "minLines": 5,   // Detect duplicates >= 5 lines
  "minTokens": 50
}
```

**ESLint plugin:**
```bash
npm install -D eslint-plugin-sonarjs

# .eslintrc.json
{
  "plugins": ["sonarjs"],
  "rules": {
    "sonarjs/no-duplicate-string": ["error", 3],
    "sonarjs/no-identical-functions": "error"
  }
}
```

**Pre-commit hook:**
```bash
# .git/hooks/pre-commit
npx jscpd src/ --threshold 0
if [ $? -ne 0 ]; then
  echo "❌ Code duplication detected"
  exit 1
fi
```

### Exceptions to DRY

**Rare cases where duplication is acceptable:**

1. **Test setup code**
   - Similar test fixtures in different test files
   - Rationale: Test isolation more important than DRY
   - Guideline: Okay if < 10 lines and aids readability

2. **Type definitions**
   - Similar TypeScript types for different domains
   - Rationale: Type safety over code reuse
   - Guideline: Only if types have different semantic meaning

3. **Configuration objects**
   - Similar config shapes in different modules
   - Rationale: Module independence
   - Guideline: Document why duplication is intentional

**How to document exceptions:**
```typescript
// INTENTIONAL DUPLICATION: Test isolation
// Similar fixture exists in other-test.ts
// Each test file should be independently readable
const testFixture = { ... };
```

---

## Code Organization Principles

### Single Responsibility Principle

**Each file/class/function should do ONE thing.**

**File organization:**
```
❌ Bad: utils.ts (200 lines of mixed utilities)
✅ Good:
  utils/
  ├── validation.ts
  ├── path-utils.ts
  ├── cache.ts
  └── index.ts
```

**Class organization:**
```
❌ Bad: One class does parsing, validation, and caching
✅ Good: Separate classes for Parser, Validator, Cache
```

### Module Boundaries

**Clear separation of concerns:**

```
src/jitd/
├── discovery/       # Finding and parsing SDEF files
├── tool-generator/  # Converting SDEF → MCP tools
├── executor/        # Executing JXA commands
└── common/          # Shared utilities
```

**Rules:**
- Modules should not reach into each other's internals
- Use public exports (index.ts) as module boundaries
- Shared code goes in `common/` or `utils/`

### Dependency Direction

**Dependencies flow one direction:**

```
executor → tool-generator → discovery → common
          ↓                  ↓            ↓
          types ← ← ← ← ← ← ← ← ← ← ← ←
```

**Rules:**
- Higher-level modules depend on lower-level modules
- `common/` and `types/` have NO dependencies on feature modules
- Circular dependencies are forbidden

---

## Testing Standards

### Test File Organization

**Co-located test files:**
```
src/jitd/discovery/
├── parse-sdef.ts
├── parse-sdef.test.ts   # Unit tests
└── find-sdef.ts

tests/
├── unit/                 # Additional unit tests
├── integration/          # Integration tests
└── e2e/                  # End-to-end tests
```

### Test Naming Conventions

**Describe blocks:**
```typescript
describe('ToolGenerator', () => {
  describe('generateTool', () => {
    it('should generate valid MCP tool from SDEF command', () => {
      // ...
    });

    it('should handle commands with no parameters', () => {
      // ...
    });

    it('should throw error for invalid command', () => {
      // ...
    });
  });
});
```

**Test names should:**
- Start with "should"
- Be specific about behavior
- Include context (success/error conditions)

### Test Coverage Strategy

**Every function needs:**
- ✅ Happy path test (successful execution)
- ✅ Error path tests (all error conditions)
- ✅ Edge case tests (boundary conditions)
- ✅ Integration test (in context)

**Example:**
```typescript
// Function to test
function divide(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero');
  return a / b;
}

// Tests (100% coverage)
describe('divide', () => {
  it('should divide two positive numbers', () => {
    expect(divide(10, 2)).toBe(5);
  });

  it('should divide negative numbers', () => {
    expect(divide(-10, 2)).toBe(-5);
  });

  it('should handle zero dividend', () => {
    expect(divide(0, 5)).toBe(0);
  });

  it('should throw error for zero divisor', () => {
    expect(() => divide(10, 0)).toThrow('Division by zero');
  });

  it('should handle floating point division', () => {
    expect(divide(5, 2)).toBe(2.5);
  });
});
```

---

## Code Review Checklist

**Every PR must verify:**

- [ ] 100% test coverage (CI enforced)
- [ ] No code duplication (jscpd passes)
- [ ] All tests passing
- [ ] No ESLint errors
- [ ] TypeScript strict mode passes
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if user-facing change)

**Automated checks:**
```bash
# Run all quality checks
npm run check

# Includes:
# - npm run test:coverage (100% required)
# - npm run lint (ESLint + duplication check)
# - npm run type-check (TypeScript strict)
# - npm run format:check (Prettier)
```

---

## Enforcement

### Pre-commit Hooks

**Installed via Husky:**
```bash
npm install -D husky lint-staged

# .husky/pre-commit
npm run lint-staged
npm run test:coverage
npx jscpd src/ --threshold 0
```

### CI/CD Pipeline

**GitHub Actions (.github/workflows/ci.yml):**
```yaml
name: CI

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm run test:coverage

      - name: Enforce 100% coverage
        run: npm run coverage:check

      - name: Check for code duplication
        run: npx jscpd src/ --threshold 0

      - name: Lint
        run: npm run lint

      - name: Type check
        run: npm run type-check

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
```

### Pull Request Requirements

**Branch protection rules:**
- ✅ CI must pass (all checks green)
- ✅ Code review required
- ✅ Up-to-date with main branch
- ✅ Linear history (squash merge)

**Auto-reject if:**
- Coverage < 100%
- Code duplication detected
- ESLint errors
- TypeScript errors
- Failing tests

---

## Summary

### The Golden Rules

1. **100% test coverage** - No exceptions
2. **Zero duplication** - Refactor immediately
3. **Single responsibility** - Each file/function does one thing
4. **Clear module boundaries** - Use public exports
5. **Dependencies flow down** - No circular dependencies
6. **Tests are documentation** - Write tests you'd want to read

### Quick Reference

**Before committing:**
```bash
npm run check          # Run all quality checks
npm run test:coverage  # Ensure 100% coverage
npx jscpd src/        # Check for duplication
```

**When writing code:**
- ❓ "Have I seen this logic before?" → Extract to shared code
- ❓ "Is this function > 50 lines?" → Split into smaller functions
- ❓ "Does this file > 200 lines?" → Split into multiple modules
- ❓ "Can I test this easily?" → If not, refactor for testability

**When reviewing code:**
- ❓ "Is coverage 100%?" → Check coverage report
- ❓ "Any duplicated code?" → Run jscpd
- ❓ "Tests cover all branches?" → Read test file
- ❓ "Clear module boundaries?" → Check imports

---

**These standards are non-negotiable. Quality is not optional.**
