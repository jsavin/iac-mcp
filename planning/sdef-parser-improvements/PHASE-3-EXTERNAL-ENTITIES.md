# Phase 3: External Entity Resolution

> **Model**: Sonnet (security-sensitive)
> **Effort**: 3-5 days
> **Goal**: Support Apple apps with XI:INCLUDE

## Problem

15% of SDEF parsing failures are due to external XML entities:

```xml
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary xmlns:xi="http://www.w3.org/2003/XInclude">
  <xi:include href="file:///System/Library/ScriptingDefinitions/CocoaStandard.sdef" />
```

**Affected Apps**: Pages, Numbers, Keynote, System Events

**Current Behavior**: External entities ignored for security (correct behavior)

## Solution

Implement safe entity resolution with strict path whitelisting.

## Security Considerations

**This phase is security-critical.** External entity resolution can be exploited for:
- Path traversal attacks
- Arbitrary file reads
- XML External Entity (XXE) attacks

**Mitigation**: Whitelist-only approach with strict path validation.

## Tasks

### 1. Design safe entity resolution (1 day)

**Whitelist trusted paths only:**
```typescript
const TRUSTED_PATHS = [
  '/System/Library/DTDs/',
  '/System/Library/ScriptingDefinitions/',
  '/Applications/*.app/Contents/Resources/',
];

function isPathTrusted(path: string): boolean {
  // Normalize path (resolve symlinks, remove ..)
  const normalized = path.normalize(path);

  // Check against whitelist
  return TRUSTED_PATHS.some(pattern =>
    matchesPattern(normalized, pattern)
  );
}
```

### 2. Implement entity resolver (1.5 days)

```typescript
// src/jitd/discovery/entity-resolver.ts

export interface EntityResolverOptions {
  /** Additional trusted paths beyond defaults */
  additionalTrustedPaths?: string[];
  /** Cache resolved entities */
  enableCache?: boolean;
  /** Max recursion depth for nested includes */
  maxDepth?: number;
}

export class EntityResolver {
  private cache: Map<string, string> = new Map();
  private trustedPaths: string[];
  private maxDepth: number;

  constructor(options?: EntityResolverOptions) {
    this.trustedPaths = [
      ...DEFAULT_TRUSTED_PATHS,
      ...(options?.additionalTrustedPaths || [])
    ];
    this.maxDepth = options?.maxDepth ?? 3;
  }

  /**
   * Resolve XInclude references in SDEF content
   */
  async resolveIncludes(
    content: string,
    basePath: string,
    depth: number = 0
  ): Promise<string> {
    if (depth > this.maxDepth) {
      throw new Error(`Max include depth (${this.maxDepth}) exceeded`);
    }

    // Find all xi:include elements
    const includePattern = /<xi:include\s+href="([^"]+)"\s*\/>/g;
    let match;
    let result = content;

    while ((match = includePattern.exec(content)) !== null) {
      const [fullMatch, href] = match;
      const resolvedPath = this.resolvePath(href, basePath);

      // Security check
      if (!this.isPathTrusted(resolvedPath)) {
        console.warn(`Skipping untrusted include: ${href}`);
        continue;
      }

      // Check cache
      let includedContent = this.cache.get(resolvedPath);
      if (!includedContent) {
        includedContent = await this.readFile(resolvedPath);
        this.cache.set(resolvedPath, includedContent);
      }

      // Recursively resolve nested includes
      includedContent = await this.resolveIncludes(
        includedContent,
        path.dirname(resolvedPath),
        depth + 1
      );

      result = result.replace(fullMatch, includedContent);
    }

    return result;
  }

  private isPathTrusted(filePath: string): boolean {
    // Normalize to prevent traversal
    const normalized = path.resolve(filePath);

    // Must not contain .. after normalization
    if (normalized.includes('..')) {
      return false;
    }

    // Check against whitelist
    return this.trustedPaths.some(trusted =>
      normalized.startsWith(trusted)
    );
  }

  private resolvePath(href: string, basePath: string): string {
    // Handle file:// URLs
    if (href.startsWith('file://')) {
      return href.replace('file://', '').replace('localhost', '');
    }

    // Relative paths
    return path.resolve(basePath, href);
  }
}
```

### 3. Security testing (1 day)

**Test cases for security:**

```typescript
describe('EntityResolver Security', () => {
  describe('path traversal attacks', () => {
    it('should reject paths with ../', async () => {
      const resolver = new EntityResolver();
      await expect(
        resolver.resolveIncludes(
          '<xi:include href="../../../etc/passwd" />',
          '/System/Library/ScriptingDefinitions/'
        )
      ).not.toContain('/etc/passwd');
    });

    it('should reject encoded traversal', async () => {
      const resolver = new EntityResolver();
      // %2e%2e = ..
      await expect(
        resolver.resolveIncludes(
          '<xi:include href="%2e%2e/%2e%2e/etc/passwd" />',
          '/System/Library/ScriptingDefinitions/'
        )
      ).not.toContain('/etc/passwd');
    });
  });

  describe('symlink attacks', () => {
    it('should resolve symlinks before validation');
    it('should reject symlinks pointing outside whitelist');
  });

  describe('malformed entities', () => {
    it('should handle missing href attribute');
    it('should handle empty href');
    it('should handle invalid file:// URLs');
  });

  describe('recursion limits', () => {
    it('should enforce max depth');
    it('should detect circular includes');
  });
});
```

### 4. Integration testing (0.5 day)

- Test with Pages, Numbers, Keynote
- Verify tools generated correctly
- Test with real CocoaStandard.sdef includes

## Success Criteria

- [ ] Pages/Numbers/Keynote parsed
- [ ] No security regressions
- [ ] 80%+ SDEF success rate
- [ ] Entity caching works
- [ ] All security tests pass

## Files to Modify

| File | Changes |
|------|---------|
| `src/jitd/discovery/parse-sdef.ts` | Integrate entity resolution |
| `src/jitd/discovery/entity-resolver.ts` | New file |
| `tests/unit/entity-resolver.test.ts` | Security tests |
| `tests/integration/sdef-parsing.test.ts` | Real file tests |

## Trusted Paths (Default)

```typescript
const DEFAULT_TRUSTED_PATHS = [
  '/System/Library/DTDs/',
  '/System/Library/ScriptingDefinitions/',
  '/System/Library/CoreServices/',
  '/Applications/',
  '/System/Applications/',
];
```

## Common Includes

| Include | Location | Used By |
|---------|----------|---------|
| CocoaStandard.sdef | `/System/Library/ScriptingDefinitions/` | Pages, Numbers, Keynote, many others |
| sdef.dtd | `/System/Library/DTDs/` | All SDEF files |

## Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Path traversal exploit | Low | **Critical** | Strict whitelist, no user paths |
| Symlink attacks | Low | High | Resolve symlinks before validation |
| XXE vulnerability | Low | **Critical** | Only handle XInclude, not DTD entities |
| Performance (many includes) | Medium | Low | Cache resolved entities |

## Security Review Checklist

Before merging, verify:

- [ ] All paths normalized before validation
- [ ] Symlinks resolved and re-validated
- [ ] No user-controllable paths in whitelist
- [ ] Max recursion depth enforced
- [ ] Circular include detection
- [ ] URL decoding handled before validation
- [ ] Security test coverage complete
