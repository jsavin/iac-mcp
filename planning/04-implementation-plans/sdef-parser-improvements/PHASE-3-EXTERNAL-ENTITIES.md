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

---

## Security Review Notes

**Reviewed by**: security-reviewer agent
**Date**: 2026-01-16
**Severity Level**: CRITICAL - External entity resolution is high-risk

### Executive Summary

**Overall Assessment**: The proposed approach is **fundamentally sound** but has **6 HIGH severity gaps** and **9 additional security concerns** that must be addressed before implementation.

**Risk Level**: HIGH → Can be reduced to MEDIUM-LOW with recommended mitigations

**Recommended Action**: Do NOT implement as-written. Address all HIGH severity findings first.

---

### Critical Findings

#### 1. CRITICAL: Incomplete Path Traversal Protection

**Severity**: HIGH
**Location**: Lines 131-144 (`isPathTrusted` function)

**Issue**: The path validation has multiple bypass vectors:

1. **Double normalization attack**: `path.resolve()` may not handle all edge cases
2. **Unicode normalization**: Paths with Unicode characters (e.g., `\u002e\u002e`) not handled
3. **Case sensitivity**: macOS is case-insensitive but case-preserving
4. **Trailing slashes**: `/System/Library/../../../etc/passwd/` might bypass checks

**Current Code**:
```typescript
const normalized = path.resolve(filePath);
if (normalized.includes('..')) {
  return false;
}
```

**Problem**: After `path.resolve()`, the path should NEVER contain `..` - this check is redundant and suggests misunderstanding of `path.resolve()` behavior.

**Recommendation**:
```typescript
private isPathTrusted(filePath: string): boolean {
  // 1. Resolve to absolute path (handles .., symlinks, etc.)
  const normalized = fs.realpathSync.native(filePath);

  // 2. Normalize Unicode (prevent bypass via Unicode encoding)
  const unicodeNormalized = normalized.normalize('NFC');

  // 3. Convert to lowercase for case-insensitive comparison (macOS)
  const canonical = unicodeNormalized.toLowerCase();

  // 4. Check against whitelist
  return this.trustedPaths.some(trusted => {
    const trustedCanonical = trusted.toLowerCase();
    return canonical.startsWith(trustedCanonical);
  });
}
```

**Additional Security**:
- Use `fs.realpathSync.native()` instead of `path.resolve()` to resolve symlinks
- Check file existence BEFORE validation (fail if file doesn't exist)
- Validate AFTER resolving, not before

---

#### 2. CRITICAL: Time-of-Check Time-of-Use (TOCTOU) Race Condition

**Severity**: HIGH
**Location**: Lines 106-116 (validation → read sequence)

**Issue**: The code validates path, then reads file. An attacker could:
1. Create valid symlink in trusted directory
2. Pass validation
3. Swap symlink to point to `/etc/passwd` before read
4. File content exfiltrated

**Current Code**:
```typescript
if (!this.isPathTrusted(resolvedPath)) {
  console.warn(`Skipping untrusted include: ${href}`);
  continue;
}

// RACE CONDITION HERE - file could be swapped

let includedContent = this.cache.get(resolvedPath);
if (!includedContent) {
  includedContent = await this.readFile(resolvedPath); // Read happens later
```

**Recommendation**:
```typescript
// Open file descriptor first
const fd = fs.openSync(resolvedPath, 'r');
try {
  // Get real path from file descriptor (immune to TOCTOU)
  const realPath = fs.readlinkSync(`/dev/fd/${fd}`);

  // Validate the ACTUAL file being read
  if (!this.isPathTrusted(realPath)) {
    throw new SecurityError(`Untrusted include after symlink resolution: ${realPath}`);
  }

  // Read from file descriptor (same file we validated)
  const includedContent = fs.readFileSync(fd, 'utf-8');

} finally {
  fs.closeSync(fd);
}
```

**Alternative**: Use `fs.realpathSync()` before validation and read from the resolved path.

---

#### 3. CRITICAL: Missing DTD Entity Attack Protection

**Severity**: CRITICAL
**Location**: Lines 19, 253 (mentions DTD but no protection implemented)

**Issue**: The code mentions "only handle XInclude, not DTD entities" but provides NO IMPLEMENTATION of this protection.

**Attack Vector**:
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<dictionary>
  <suite name="&xxe;" />
</dictionary>
```

**Current Code**: No protection visible in entity resolver

**Recommendation**:
```typescript
// In EntityResolver constructor or resolveIncludes
private readonly XML_PARSER_OPTIONS = {
  // CRITICAL: Disable external entities
  noent: false,  // Do NOT expand entities
  nonet: true,   // Do NOT fetch network resources

  // XML2JS equivalent:
  explicitChildren: false,
  preserveChildrenOrder: false,
  // Do NOT use any entity expansion features
};

// Add explicit check before parsing
private validateNoExternalEntities(content: string): void {
  // Reject any DOCTYPE with ENTITY declarations
  const entityPattern = /<!ENTITY\s+/i;
  if (entityPattern.test(content)) {
    throw new SecurityError('External entity declarations not allowed');
  }

  // Allow only XInclude-specific processing
  const doctypePattern = /<!DOCTYPE[^>]*\[/i;
  if (doctypePattern.test(content)) {
    // DOCTYPE with internal subset - potential XXE
    throw new SecurityError('DOCTYPE with internal subset not allowed');
  }
}
```

**Integration**:
```typescript
async resolveIncludes(content: string, basePath: string, depth: number = 0): Promise<string> {
  // FIRST: Validate no XXE attempts
  this.validateNoExternalEntities(content);

  // THEN: Process XIncludes only
  // ... rest of code
}
```

---

#### 4. HIGH: Insufficient URL Parsing Validation

**Severity**: HIGH
**Location**: Lines 146-154 (`resolvePath` function)

**Issue**: URL parsing is overly simplistic and has bypass vectors:

**Attack Vectors**:
1. `file:///localhost/../../../etc/passwd` - localhost not removed correctly
2. `file://example.com/etc/passwd` - network file access
3. `file:////etc/passwd` - quad-slash bypass
4. `FILE://` (uppercase) - case sensitivity
5. `file:\\\etc\passwd` - backslash confusion (Windows-style)

**Current Code**:
```typescript
if (href.startsWith('file://')) {
  return href.replace('file://', '').replace('localhost', '');
}
```

**Problems**:
- Simple string replacement is insufficient
- No validation of resulting path
- Doesn't handle network hosts
- Case-sensitive check

**Recommendation**:
```typescript
private resolvePath(href: string, basePath: string): string {
  // Normalize case for URL scheme check
  const hrefLower = href.toLowerCase();

  // Handle file:// URLs
  if (hrefLower.startsWith('file://')) {
    // Use URL parser for proper parsing
    let url: URL;
    try {
      url = new URL(href);
    } catch (error) {
      throw new SecurityError(`Invalid file URL: ${href}`);
    }

    // CRITICAL: Reject non-localhost hosts
    if (url.hostname && url.hostname !== 'localhost') {
      throw new SecurityError(`Network file access not allowed: ${href}`);
    }

    // Extract pathname (handles encoding, normalization)
    const pathname = decodeURIComponent(url.pathname);

    // Validate it's absolute path
    if (!path.isAbsolute(pathname)) {
      throw new SecurityError(`Relative path in file URL: ${href}`);
    }

    return pathname;
  }

  // Handle relative paths
  if (path.isAbsolute(href)) {
    return href;
  }

  return path.resolve(basePath, href);
}
```

---

#### 5. HIGH: Whitelist Pattern Matching Not Implemented

**Severity**: HIGH
**Location**: Lines 40-54 (design section shows wildcard patterns, but implementation doesn't support them)

**Issue**: Design shows `'/Applications/*.app/Contents/Resources/'` but implementation (lines 141-143) only does `startsWith()` check.

**Problem**: If whitelist contains `/Applications/*.app/Contents/Resources/`:
- `startsWith()` will return FALSE (string doesn't literally start with `*`)
- All app bundle SDEF files will be rejected
- Feature will not work

**Current Code**:
```typescript
return this.trustedPaths.some(trusted =>
  normalized.startsWith(trusted)  // Doesn't handle wildcards
);
```

**Recommendation**:
```typescript
private isPathTrusted(filePath: string): boolean {
  const normalized = fs.realpathSync.native(filePath);
  const canonical = normalized.normalize('NFC').toLowerCase();

  return this.trustedPaths.some(pattern => {
    if (pattern.includes('*')) {
      // Convert glob pattern to regex
      const regex = this.globToRegex(pattern.toLowerCase());
      return regex.test(canonical);
    } else {
      // Exact prefix match
      return canonical.startsWith(pattern.toLowerCase());
    }
  });
}

private globToRegex(pattern: string): RegExp {
  // Escape regex special chars except *
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  // Replace * with .*? (non-greedy match)
  const regex = escaped.replace(/\*/g, '.*?');
  return new RegExp(`^${regex}`);
}
```

**Validation**: Add test to ensure `/Applications/Safari.app/Contents/Resources/Safari.sdef` matches pattern.

---

#### 6. HIGH: Missing Circular Include Detection

**Severity**: HIGH
**Location**: Lines 199-201 (mentioned in test but not implemented)

**Issue**: Depth limit prevents infinite recursion but doesn't detect circular includes:

**Attack Scenario**:
- `A.sdef` includes `B.sdef`
- `B.sdef` includes `C.sdef`
- `C.sdef` includes `A.sdef`
- Depth = 3, so it stops, but wastes resources

**More Critical**: Depth limit alone is insufficient if max depth is increased.

**Recommendation**:
```typescript
export class EntityResolver {
  private cache: Map<string, string> = new Map();
  private includeStack: Set<string> = new Set(); // Track current resolution chain

  async resolveIncludes(
    content: string,
    basePath: string,
    depth: number = 0,
    currentFile?: string
  ): Promise<string> {
    if (depth > this.maxDepth) {
      throw new Error(`Max include depth (${this.maxDepth}) exceeded`);
    }

    // Track this file in resolution chain
    if (currentFile) {
      if (this.includeStack.has(currentFile)) {
        throw new SecurityError(
          `Circular include detected: ${Array.from(this.includeStack).join(' -> ')} -> ${currentFile}`
        );
      }
      this.includeStack.add(currentFile);
    }

    try {
      // ... process includes ...

      // When processing nested include:
      includedContent = await this.resolveIncludes(
        includedContent,
        path.dirname(resolvedPath),
        depth + 1,
        resolvedPath  // Pass file path for cycle detection
      );

    } finally {
      // Remove from stack when done
      if (currentFile) {
        this.includeStack.delete(currentFile);
      }
    }
  }
}
```

---

### Medium Severity Findings

#### 7. MEDIUM: Insufficient Input Validation on href Attribute

**Severity**: MEDIUM
**Location**: Lines 97-102 (regex pattern)

**Issue**: The regex `/<xi:include\s+href="([^"]+)"\s*\/>/g` doesn't validate:
1. Empty href (`href=""`)
2. Whitespace-only href (`href="   "`)
3. Non-file protocols (`href="http://evil.com/malicious.sdef"`)
4. Malformed XML (`href="file:///etc/passwd' onerror='alert(1)'`)

**Recommendation**:
```typescript
while ((match = includePattern.exec(content)) !== null) {
  const [fullMatch, href] = match;

  // Validate href is not empty
  if (!href || href.trim().length === 0) {
    console.warn('Skipping empty href in xi:include');
    continue;
  }

  // Validate protocol (only file:// or relative paths)
  const hrefLower = href.toLowerCase();
  if (hrefLower.includes('://') && !hrefLower.startsWith('file://')) {
    throw new SecurityError(`Non-file protocol not allowed: ${href}`);
  }

  // ... continue processing
}
```

---

#### 8. MEDIUM: Cache Poisoning Vulnerability

**Severity**: MEDIUM
**Location**: Lines 112-116 (cache without validation)

**Issue**: If an attacker can write to a trusted directory temporarily:
1. Place malicious `CocoaStandard.sdef` in `/System/Library/ScriptingDefinitions/`
2. Trigger parsing (cache is populated with malicious content)
3. Remove malicious file
4. All future parses use cached malicious content

**Current Code**:
```typescript
let includedContent = this.cache.get(resolvedPath);
if (!includedContent) {
  includedContent = await this.readFile(resolvedPath);
  this.cache.set(resolvedPath, includedContent);
}
```

**Recommendation**:
```typescript
// Add cache validation with file metadata
private async getCachedOrRead(resolvedPath: string): Promise<string> {
  const cached = this.cache.get(resolvedPath);

  if (cached) {
    // Validate cache is still fresh
    const stats = await fs.promises.stat(resolvedPath);
    const cacheKey = `${resolvedPath}:${stats.mtimeMs}:${stats.size}`;

    if (this.cacheMetadata.get(resolvedPath) === cacheKey) {
      return cached.content;
    }

    // Cache stale, re-read
    this.cache.delete(resolvedPath);
  }

  const content = await this.readFile(resolvedPath);
  const stats = await fs.promises.stat(resolvedPath);
  const cacheKey = `${resolvedPath}:${stats.mtimeMs}:${stats.size}`;

  this.cache.set(resolvedPath, content);
  this.cacheMetadata.set(resolvedPath, cacheKey);

  return content;
}
```

---

#### 9. MEDIUM: Information Disclosure via Console Warnings

**Severity**: MEDIUM
**Location**: Lines 107-108

**Issue**: Warning logs may leak sensitive path information to attacker:

**Current Code**:
```typescript
console.warn(`Skipping untrusted include: ${href}`);
```

**Problem**: If attacker controls SDEF file, they can probe for file existence:
- Include `file:///secret/path` → warning reveals if path was attempted
- Enumerate internal directory structure
- Information leakage for future attacks

**Recommendation**:
```typescript
// Use structured logging (not console)
this.logger.warn('Untrusted include skipped', {
  // Only log in debug mode
  href: this.options.debug ? href : '[redacted]',
  // Don't log resolved path at all
});

// Or throw error instead of silent skip
if (!this.isPathTrusted(resolvedPath)) {
  throw new SecurityError('Include path not in whitelist');
}
```

---

#### 10. MEDIUM: Missing File Size Limits

**Severity**: MEDIUM
**Location**: Not implemented

**Issue**: No limits on included file sizes. Attacker could:
1. Create 10GB `CocoaStandard.sdef` symlink pointing to `/dev/random`
2. Trigger parsing
3. Exhaust memory, DOS attack

**Recommendation**:
```typescript
private async readFile(filePath: string): Promise<string> {
  const stats = await fs.promises.stat(filePath);

  // Enforce reasonable file size limit (1MB)
  const MAX_FILE_SIZE = 1024 * 1024;
  if (stats.size > MAX_FILE_SIZE) {
    throw new SecurityError(
      `File too large: ${stats.size} bytes (max ${MAX_FILE_SIZE})`
    );
  }

  // Also limit total parsed content across all includes
  this.totalBytesRead += stats.size;
  if (this.totalBytesRead > MAX_FILE_SIZE * 10) {
    throw new SecurityError('Total included content exceeds limit');
  }

  return await fs.promises.readFile(filePath, 'utf-8');
}
```

---

#### 11. MEDIUM: Regex Denial of Service (ReDoS)

**Severity**: MEDIUM
**Location**: Line 97 (`includePattern` regex)

**Issue**: Current regex is simple, but if expanded could be vulnerable to ReDoS:

**Current**: `/<xi:include\s+href="([^"]+)"\s*\/>/g`

**Potential ReDoS if modified**: `/<xi:include\s+.*?href="([^"]+)".*?\/>/g`

**Recommendation**:
- Keep regex simple
- Add timeout to regex matching
- Limit input size before regex

```typescript
// Limit content size before regex processing
const MAX_CONTENT_SIZE = 5 * 1024 * 1024; // 5MB
if (content.length > MAX_CONTENT_SIZE) {
  throw new SecurityError('SDEF file too large');
}

// Use non-backtracking regex if possible
// Or wrap in timeout
```

---

### Additional Security Concerns

#### 12. LOW: Missing Content Validation After Resolution

**Severity**: LOW

**Issue**: No validation that included content is valid XML/SDEF

**Recommendation**: Validate structure of included content before insertion.

---

#### 13. LOW: Default Trusted Paths Too Permissive

**Severity**: LOW
**Location**: Lines 231-237

**Issue**: Whitelisting entire `/Applications/` directory includes:
- User-installed applications (potentially malicious)
- Applications not from App Store
- Third-party tools

**Recommendation**:
```typescript
const DEFAULT_TRUSTED_PATHS = [
  '/System/Library/DTDs/',
  '/System/Library/ScriptingDefinitions/',
  '/System/Library/CoreServices/',
  '/System/Applications/',  // System apps only
  // DO NOT include /Applications/ by default
];

// Require explicit opt-in for /Applications/
const options = {
  allowUserApplications: false,  // Must be explicitly enabled
  additionalTrustedPaths: ['/Applications/Safari.app/'] // Specific apps only
};
```

---

#### 14. LOW: No Audit Logging

**Severity**: LOW

**Issue**: No logging of security events:
- Which files were included
- Which paths were rejected
- Who triggered resolution

**Recommendation**:
```typescript
// Security audit log
this.auditLogger.info('Entity resolution started', {
  basePath,
  requestedBy: context.user,
  timestamp: Date.now()
});

this.auditLogger.warn('Path rejected', {
  path: resolvedPath,
  reason: 'not in whitelist',
  requestedHref: href
});
```

---

#### 15. LOW: Missing Rate Limiting

**Severity**: LOW

**Issue**: No rate limiting on entity resolution. Attacker could:
- Trigger thousands of parse operations
- Exhaust CPU/memory
- DOS attack

**Recommendation**: Add rate limiting per user/session.

---

### Security Testing Gaps

The proposed test suite (lines 163-202) is **incomplete**. Add these tests:

#### Additional Required Tests

```typescript
describe('EntityResolver Security - Extended', () => {
  describe('TOCTOU attacks', () => {
    it('should prevent symlink swap during validation-read gap');
    it('should validate actual file descriptor, not path');
  });

  describe('XXE attacks', () => {
    it('should reject DOCTYPE with ENTITY declarations');
    it('should reject parameter entities');
    it('should reject external DTD subsets');
    it('should only process XInclude, not XML entities');
  });

  describe('URL parsing', () => {
    it('should reject network file URLs (file://example.com)');
    it('should handle uppercase FILE://');
    it('should reject quad-slash file:////');
    it('should handle URL encoding in paths');
    it('should reject non-file protocols (http://, ftp://)');
  });

  describe('whitelist validation', () => {
    it('should match wildcard patterns correctly');
    it('should reject case variations on case-sensitive systems');
    it('should handle trailing slashes in whitelist');
    it('should not allow /Applications/ by default');
  });

  describe('resource exhaustion', () => {
    it('should enforce max file size limit');
    it('should enforce total bytes read limit');
    it('should timeout on regex processing');
    it('should rate limit parse operations');
  });

  describe('cache security', () => {
    it('should invalidate cache when file changes');
    it('should prevent cache poisoning');
    it('should not cache errors');
  });

  describe('circular includes', () => {
    it('should detect A->B->A cycles');
    it('should detect longer cycles (A->B->C->A)');
    it('should clear cycle detection state after resolution');
  });

  describe('information disclosure', () => {
    it('should not leak paths in error messages');
    it('should not leak paths in logs (except debug mode)');
    it('should sanitize warnings');
  });

  describe('malformed input', () => {
    it('should handle invalid UTF-8 in href');
    it('should handle null bytes in paths');
    it('should handle extremely long paths (> PATH_MAX)');
    it('should handle invalid XML in included files');
  });
});
```

---

### Recommended Additional Controls

#### 16. Content Security Policy for Includes

```typescript
interface IncludePolicy {
  // Only allow includes from same directory or parent
  allowParentDirectory: boolean;
  // Maximum number of includes per file
  maxIncludesPerFile: number;
  // Allowed file extensions
  allowedExtensions: string[];
}

const DEFAULT_POLICY: IncludePolicy = {
  allowParentDirectory: false,
  maxIncludesPerFile: 10,
  allowedExtensions: ['.sdef', '.xml']
};
```

---

#### 17. Sandboxing

**Recommendation**: Run entity resolution in a sandboxed context:
- Separate process with limited permissions
- Read-only file system access
- No network access
- Resource limits (CPU, memory)

---

#### 18. Cryptographic Verification

**For System Files**: Verify signature/hash of system SDEF files:

```typescript
const KNOWN_SYSTEM_FILES = {
  '/System/Library/ScriptingDefinitions/CocoaStandard.sdef': {
    sha256: 'expected-hash-here',
    size: 12345
  }
};

// Verify before including
if (KNOWN_SYSTEM_FILES[resolvedPath]) {
  const hash = await this.computeSHA256(resolvedPath);
  if (hash !== KNOWN_SYSTEM_FILES[resolvedPath].sha256) {
    throw new SecurityError('System file hash mismatch - possible tampering');
  }
}
```

---

### Implementation Priority

**Must Fix Before Implementation** (blocking):
1. Finding #1: Path traversal protection (CRITICAL)
2. Finding #2: TOCTOU race condition (CRITICAL)
3. Finding #3: DTD entity attack protection (CRITICAL)
4. Finding #4: URL parsing validation (HIGH)
5. Finding #5: Wildcard pattern matching (HIGH)
6. Finding #6: Circular include detection (HIGH)

**Should Fix During Implementation** (important):
7. Finding #7: Input validation
8. Finding #8: Cache poisoning
9. Finding #9: Information disclosure
10. Finding #10: File size limits

**Can Fix Post-Implementation** (nice to have):
11-15: Additional security controls
16-18: Defense in depth measures

---

### Alternative Approaches to Consider

#### Option A: No External Entity Resolution (Safest)

**Instead of implementing risky entity resolution:**
1. Pre-bundle CocoaStandard.sdef content
2. Inline common includes at build time
3. Avoid runtime resolution entirely

**Pros**: Zero attack surface
**Cons**: Doesn't handle app updates, less flexible

#### Option B: Strict Static Whitelist (Recommended)

**Instead of pattern matching:**
```typescript
const ALLOWED_INCLUDES = new Set([
  '/System/Library/ScriptingDefinitions/CocoaStandard.sdef',
  '/System/Library/DTDs/sdef.dtd',
  // Explicit list only, no wildcards
]);

if (!ALLOWED_INCLUDES.has(resolvedPath)) {
  throw new SecurityError('Include not in whitelist');
}
```

**Pros**: Much simpler, harder to bypass
**Cons**: Requires maintenance as macOS updates

#### Option C: Capability-Based Security

**Use macOS sandbox/entitlements:**
- App has read-only access to specific directories
- OS enforces access control
- No application-level path validation needed

**Pros**: Defense in depth, OS-level protection
**Cons**: Requires app sandboxing, entitlements configuration

---

### Recommended Security Development Lifecycle

1. **Threat Modeling Session**: Before implementation
   - Identify all attack vectors
   - Map trust boundaries
   - Document security assumptions

2. **Security-First Implementation**:
   - Implement security controls FIRST
   - Then add functionality
   - Not the reverse

3. **Security Review Gates**:
   - Code review by security expert (required)
   - Penetration testing with malicious SDEF files
   - Fuzzing with malformed inputs

4. **Continuous Security**:
   - Monitor for XXE vulnerabilities in dependencies
   - Regular security updates
   - Incident response plan

---

### Final Recommendation

**DO NOT IMPLEMENT AS CURRENTLY SPECIFIED.**

**Required Changes**:
1. Fix all 6 HIGH severity findings
2. Implement comprehensive security tests (additional 30+ tests needed)
3. Add defense-in-depth controls (sandboxing, file size limits)
4. Consider safer alternatives (static whitelist, pre-bundling)
5. Conduct threat modeling session
6. Security review by qualified expert before merge

**Estimated Additional Effort**: +2-3 days for security hardening

**Alternative**: If timeline is critical, implement Option A (no external resolution) for MVP, add proper external resolution in later phase with adequate security review.

---

### Questions for Decision

1. **Risk Tolerance**: Is the complexity of secure external entity resolution justified, or should we use a simpler approach?
2. **Threat Model**: What is the assumed threat model? (Malicious apps? Compromised system files? Network attackers?)
3. **Compliance**: Are there any compliance requirements (SOC2, ISO27001) that affect implementation?
4. **Maintenance**: Who will maintain the security posture long-term?

---

**Security Review Complete**

This review identifies 18 security concerns (6 CRITICAL/HIGH, 9 MEDIUM/LOW, 3 architectural). Addressing these findings will significantly improve the security posture of external entity resolution.

**Recommendation**: Treat this as a security-critical feature requiring expert review and comprehensive testing before deployment.
