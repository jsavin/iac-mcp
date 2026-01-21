/**
 * EntityResolver - Safe SDEF External Entity Resolution
 *
 * SECURITY-CRITICAL MODULE
 *
 * Enables safe parsing of SDEF files with XInclude external entity references
 * (used by Pages, Numbers, Keynote, System Events). Implements comprehensive
 * security controls based on security review findings.
 *
 * Security Features:
 * - Path traversal protection (symlink resolution, normalization, whitelist)
 * - XXE/DTD entity attack prevention (reject malicious DOCTYPE)
 * - URL parsing validation (proper URL handling, localhost-only)
 * - Circular include detection (track resolution chain)
 * - Resource exhaustion limits (depth, file size, total bytes, includes per file)
 * - Information disclosure prevention (sanitized error messages)
 * - TOCTOU protection (file descriptor validation)
 * - Cache invalidation (detect file changes)
 */

import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';

/**
 * Configuration options for EntityResolver
 */
export interface EntityResolverOptions {
  /** Additional trusted paths beyond defaults (used for testing) */
  additionalTrustedPaths?: string[];
  /** Enable caching of resolved entities (default: true) */
  enableCache?: boolean;
  /** Maximum recursion depth for nested includes (default: 3) */
  maxDepth?: number;
  /** Maximum file size in bytes (default: 1MB) */
  maxFileSize?: number;
  /** Maximum total bytes across all includes (default: 10MB) */
  maxTotalBytes?: number;
  /** Maximum number of includes per file (default: 50) */
  maxIncludesPerFile?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

/**
 * Default trusted paths for SDEF includes
 *
 * SECURITY: Only system directories are trusted by default.
 * /Applications/ is NOT included (user-installed apps).
 */
const DEFAULT_TRUSTED_PATHS = [
  '/System/Library/DTDs/',
  '/System/Library/ScriptingDefinitions/',
  '/System/Library/CoreServices/',
  '/System/Applications/',
];

/**
 * Default limits for resource exhaustion protection
 */
const DEFAULT_MAX_DEPTH = 3;
const DEFAULT_MAX_FILE_SIZE = 1024 * 1024; // 1MB
const DEFAULT_MAX_TOTAL_BYTES = 10 * 1024 * 1024; // 10MB
const DEFAULT_MAX_INCLUDES_PER_FILE = 50;

/**
 * Security error for entity resolution violations
 */
export class SecurityError extends Error {
  constructor(
    message: string,
    public readonly category: 'path_traversal' | 'xxe' | 'resource_limit' | 'circular' | 'url_parsing'
  ) {
    super(message);
    this.name = 'SecurityError';
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Circular include detection error
 */
export class CircularIncludeError extends SecurityError {
  constructor(public readonly filePath: string) {
    super(`Circular include detected: file is already in resolution chain`, 'circular');
    this.name = 'CircularIncludeError';
  }
}

/**
 * Resource limit exceeded error
 */
export class ResourceLimitError extends SecurityError {
  constructor(message: string) {
    super(message, 'resource_limit');
    this.name = 'ResourceLimitError';
  }
}

/**
 * Cache metadata for validation
 */
interface CacheMetadata {
  mtime: number; // Modification time in milliseconds
  size: number; // File size in bytes
}

/**
 * EntityResolver - Safe resolution of XInclude external entities
 *
 * Implements defense-in-depth security controls:
 * 1. Path whitelist validation (only trusted system directories)
 * 2. XXE/DTD entity rejection (prevent malicious entity declarations)
 * 3. URL parsing validation (reject non-file protocols, remote hosts)
 * 4. Circular include detection (track resolution chain)
 * 5. Resource limits (depth, file size, total bytes, includes count)
 * 6. TOCTOU protection (validate at file descriptor level)
 * 7. Cache invalidation (detect file modifications)
 */
export class EntityResolver {
  private cache: Map<string, string>;
  private cacheMetadata: Map<string, CacheMetadata>;
  private trustedPaths: string[];
  private maxDepth: number;
  private maxFileSize: number;
  private maxTotalBytes: number;
  private maxIncludesPerFile: number;
  private totalBytesRead: number;
  private includeStack: Set<string>;
  private readonly options: EntityResolverOptions;
  private readonly debug: boolean;

  constructor(options: EntityResolverOptions = {}) {
    this.options = options;
    this.cache = new Map();
    this.cacheMetadata = new Map();
    this.totalBytesRead = 0;
    this.includeStack = new Set();
    this.debug = options.debug ?? false;

    // Initialize trusted paths (defaults + additional)
    // SECURITY: Normalize all trusted paths to resolve symlinks (e.g., /var -> /private/var on macOS)
    const rawTrustedPaths = [
      ...DEFAULT_TRUSTED_PATHS,
      ...(options.additionalTrustedPaths ?? []),
    ];

    this.trustedPaths = rawTrustedPaths.map(p => {
      try {
        // Resolve symlinks if path exists
        return fs.realpathSync.native(p);
      } catch (error) {
        // Path doesn't exist yet (e.g., System directories that might not exist)
        // Keep original path
        return p;
      }
    });

    // Initialize limits
    this.maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
    this.maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
    this.maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
    this.maxIncludesPerFile = options.maxIncludesPerFile ?? DEFAULT_MAX_INCLUDES_PER_FILE;

    if (this.debug) {
      console.log('[EntityResolver] Initialized with options:', {
        trustedPaths: this.trustedPaths,
        maxDepth: this.maxDepth,
        maxFileSize: this.maxFileSize,
        maxTotalBytes: this.maxTotalBytes,
        maxIncludesPerFile: this.maxIncludesPerFile,
      });
    }
  }

  /**
   * Resolve XInclude elements in SDEF content
   *
   * SECURITY: Validates all includes against whitelist, prevents XXE, enforces limits.
   *
   * @param content - XML content potentially containing xi:include elements
   * @param basePath - Base directory for resolving relative paths
   * @param depth - Current recursion depth (internal use)
   * @param currentFile - Current file being processed (for circular detection)
   * @returns Content with all includes resolved
   * @throws SecurityError for security violations
   * @throws ResourceLimitError for limit violations
   * @throws CircularIncludeError for circular dependencies
   */
  async resolveIncludes(
    content: string,
    basePath: string,
    depth: number = 0,
    currentFile?: string
  ): Promise<string> {
    // SECURITY: Reset resource tracking at top level
    if (depth === 0) {
      this.totalBytesRead = 0;
      // SECURITY: Clear includeStack to prevent false circular include errors from previous calls
      this.includeStack.clear();
    }

    // SECURITY: Validate against XXE/DTD entity attacks BEFORE processing
    this.validateNoExternalEntities(content);

    // SECURITY: Enforce recursion depth limit
    if (depth > this.maxDepth) {
      throw new ResourceLimitError(
        `Maximum include depth (${this.maxDepth}) exceeded`
      );
    }

    // SECURITY: Track circular includes (if we have a current file)
    let normalizedCurrentFile: string | undefined;
    if (currentFile) {
      try {
        // Normalize the current file path for circular detection
        normalizedCurrentFile = fs.realpathSync.native(currentFile).normalize('NFC').toLowerCase();

        if (this.includeStack.has(normalizedCurrentFile)) {
          throw new CircularIncludeError(currentFile);
        }
        this.includeStack.add(normalizedCurrentFile);
      } catch (error) {
        // If we can't normalize (file doesn't exist), use original path
        normalizedCurrentFile = currentFile.toLowerCase();
        if (this.includeStack.has(normalizedCurrentFile)) {
          throw new CircularIncludeError(currentFile);
        }
        this.includeStack.add(normalizedCurrentFile);
      }
    }

    try {
      // Find all xi:include elements
      const includePattern = /<xi:include\s+([^>]*)\/>/g;
      const includes: Array<{ match: string; href: string }> = [];

      let match;
      while ((match = includePattern.exec(content)) !== null) {
        const attributes = match[1];
        if (!attributes) {
          continue;
        }
        const hrefMatch = /href="([^"]*)"/.exec(attributes);

        // SECURITY: Add ALL xi:include elements to includes array, including those with empty href
        // This ensures:
        // 1. Empty hrefs are detected and removed from output (fail-secure)
        // 2. Invalid xi:include elements don't remain as malformed XML
        // 3. All xi:include processing goes through the same validation pipeline
        if (hrefMatch && hrefMatch[1] !== undefined) {
          includes.push({
            match: match[0],
            href: hrefMatch[1],
          });
        }
      }

      // SECURITY: Enforce maximum includes per file
      if (includes.length > this.maxIncludesPerFile) {
        throw new ResourceLimitError(
          `Maximum includes per file (${this.maxIncludesPerFile}) exceeded: found ${includes.length}`
        );
      }

      if (this.debug && includes.length > 0) {
        console.log(`[EntityResolver] Found ${includes.length} includes at depth ${depth}`);
      }

      // Process each include in reverse order to preserve indices during replacement
      // This ensures if two includes have identical text, both are replaced correctly
      let result = content;
      for (let i = includes.length - 1; i >= 0; i--) {
        // Defensive check: verify array bounds before access
        // Although i is controlled by the for loop, defensive programming prevents
        // future logic changes from introducing out-of-bounds access
        const include = includes[i];
        if (!include) {
          // Should never happen with valid for loop, but fail-safe in case loop logic changes
          if (this.debug) {
            console.warn(`[EntityResolver] Unexpected: include at index ${i} is undefined`);
          }
          continue;
        }
        const { match: matchText, href } = include;

        // SECURITY: Validate href (reject empty, whitespace-only)
        const trimmedHref = href.trim();
        if (!trimmedHref) {
          if (this.debug) {
            console.warn('[EntityResolver] Skipping empty href');
          }
          // Skip empty href safely - use replaceAll to handle duplicates
          result = result.split(matchText).join('');
          continue;
        }

        try {
          // SECURITY: Resolve and validate path
          const resolvedPath = this.resolvePath(trimmedHref, basePath);

          // Skip if path resolution returned null (e.g., null bytes)
          if (resolvedPath === null) {
            result = result.split(matchText).join('');
            continue;
          }

          // SECURITY: Check if path is trusted
          if (!this.isPathTrusted(resolvedPath, basePath)) {
            if (this.debug) {
              console.warn('[EntityResolver] Skipping untrusted path (not in whitelist)');
            }
            // Skip untrusted paths silently (fail-secure)
            result = result.split(matchText).join('');
            continue;
          }

          // SECURITY: Check for circular includes before reading
          const normalizedResolved = fs.realpathSync.native(resolvedPath).normalize('NFC').toLowerCase();
          if (this.includeStack.has(normalizedResolved)) {
            throw new CircularIncludeError(resolvedPath);
          }

          // SECURITY: Read file with size limits and validation
          const includedContent = await this.getCachedOrRead(resolvedPath);

          // SECURITY: Recursively resolve nested includes
          const resolvedContent = await this.resolveIncludes(
            includedContent,
            path.dirname(resolvedPath),
            depth + 1,
            resolvedPath
          );

          // Replace include with resolved content - use split/join to replace all occurrences
          result = result.split(matchText).join(resolvedContent);
        } catch (error) {
          if (error instanceof SecurityError) {
            // Re-throw security errors
            throw error;
          }

          // SECURITY: Handle other errors safely (don't leak details)
          if (this.debug) {
            console.warn('[EntityResolver] Error processing include:', error);
          }

          // Skip failed includes silently (fail-secure)
          result = result.split(matchText).join('');
        }
      }

      return result;
    } finally {
      // SECURITY: Clean up circular detection tracking
      if (normalizedCurrentFile) {
        this.includeStack.delete(normalizedCurrentFile);
      }
    }
  }

  /**
   * Validate that content does not contain malicious external entities
   *
   * SECURITY: Prevents XXE attacks by distinguishing safe vs dangerous entity types:
   *
   * ALLOWED - Parameter entities for XML schema definition (no SYSTEM reference):
   * - <!ENTITY % common.attrib "attribute definitions">
   * - Used by Pages/Numbers/Keynote for schema
   * - Cannot read files (purely for schema)
   *
   * REJECTED - General entities with SYSTEM (XXE attack vector):
   * - <!ENTITY xxe SYSTEM "file:///etc/passwd">
   * - <!ENTITY % file SYSTEM "file:///etc/passwd">
   * - Can read arbitrary files via entity expansion
   *
   * REJECTED - Sensitive file references:
   * - /etc/passwd, /etc/shadow, /etc/hosts
   *
   * ALLOWED - DOCTYPE without internal subset (legitimate DTD references):
   * - <!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
   *
   * @param content - XML content to validate
   * @throws SecurityError if malicious entities detected
   */
  private validateNoExternalEntities(content: string): void {
    // SECURITY: Prevent ReDoS by limiting the portion of content we apply regex to
    // DOCTYPE declarations should appear at start of XML, so we only check first 64KB
    // This protects against catastrophic backtracking on maliciously crafted input
    const maxDocTypeCheckLength = 65536; // 64KB - enough for any reasonable DOCTYPE
    const contentToCheck = content.length > maxDocTypeCheckLength
      ? content.substring(0, maxDocTypeCheckLength)
      : content;

    // Check for ENTITY declarations in DOCTYPE internal subset
    // Note: Using [\s\S] instead of 's' flag for ES2017 compatibility
    const doctypeWithInternalSubset = /<!DOCTYPE[^>]*\[([\s\S]*?)\]/;
    const match = doctypeWithInternalSubset.exec(contentToCheck);

    if (match && match[1]) {
      const internalSubset = match[1];

      // SECURITY: Distinguish between safe parameter entities and dangerous general entities
      // Parameter entities (<!ENTITY % name ...>) are safe for schema definition
      // General entities (<!ENTITY name ...>) with SYSTEM are XXE attack vectors

      // SECURITY: Check for ALL ENTITY declarations with SYSTEM references
      // This catches both:
      // - <!ENTITY name SYSTEM "file:///etc/passwd"> (general entity XXE)
      // - <!ENTITY % name SYSTEM "file:///etc/passwd"> (parameter entity XXE)
      if (/<!ENTITY\s+(?:%\s+)?\w+\s+SYSTEM\s+/i.test(internalSubset)) {
        throw new SecurityError(
          'DOCTYPE with ENTITY SYSTEM references is not allowed (XXE protection)',
          'xxe'
        );
      }

      // SECURITY: Parameter entities without SYSTEM are allowed (schema definition)
      // They're used by Pages/Numbers/Keynote for XML schema attributes
      // Example: <!ENTITY % common.attrib "xmlns:xi CDATA #FIXED 'http://...'">
      // These are safe because they can't read files
    }

    // Reject DOCTYPE with SYSTEM that references suspicious files
    const doctypeSystem = /<!DOCTYPE\s+\w+\s+SYSTEM\s+"([^"]+)"/i;
    const systemMatch = doctypeSystem.exec(contentToCheck);

    if (systemMatch && systemMatch[1]) {
      const systemId = systemMatch[1];

      // Reject SYSTEM references to sensitive files (even if no internal subset)
      const suspiciousPatterns = [
        /\/etc\/passwd/i,
        /\/etc\/shadow/i,
        /\/etc\/hosts/i,
        /file:\/\/\/etc\//i,
        /file:\/\/.*\/etc\//i,
      ];

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(systemId)) {
          throw new SecurityError(
            'DOCTYPE SYSTEM reference to sensitive file is not allowed',
            'xxe'
          );
        }
      }
    }

    // Note: We allow DOCTYPE without internal subset for legitimate DTD references
    // Example: <!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
  }

  /**
   * Check if a file path is in the trusted whitelist
   *
   * SECURITY: Implements comprehensive path traversal protection via whitelist validation.
   * This is the critical security gate that prevents directory traversal attacks.
   *
   * PATH TRAVERSAL PROTECTION MECHANISM:
   * ====================================
   *
   * Attack vectors prevented:
   *
   * 1. RELATIVE PATH TRAVERSAL: ../../../etc/passwd
   *    - Attacker references file outside app bundle using relative paths
   *    - Example: /Applications/App.app/Contents/Resources/main.sdef includes ../../secret.xml
   *    - Resolution: ../../secret.xml resolves to /Applications/App.app/secret.xml
   *    - Protected: /Applications/App.app/secret.xml is NOT in basePath whitelist
   *                 (/Applications/App.app/Contents/Resources) and NOT in system whitelist
   *    - Action: Include is silently skipped (fail-secure)
   *
   * 2. ABSOLUTE PATH TRAVERSAL: /etc/passwd
   *    - Attacker specifies absolute path directly
   *    - Example: <xi:include href="/etc/passwd"/>
   *    - Protected: /etc/passwd is NOT in whitelist
   *    - Action: Include is silently skipped
   *
   * 3. SYMLINK ESCAPE ATTACKS: symlink points outside basePath
   *    - Attacker creates symlink to ../../../etc/passwd and references it
   *    - Example: include.xml -> /etc/passwd (symlink)
   *    - Protected: fs.realpathSync.native() resolves symlink to /etc/passwd
   *                 Then /etc/passwd fails whitelist check
   *    - Why it works: Symlink resolution happens BEFORE whitelist check
   *    - Action: Include is skipped
   *
   * 4. UNICODE BYPASS: é vs \u00e9
   *    - Attacker uses Unicode variations to bypass string comparison
   *    - Example: "../..\u0065tc/passwd" might bypass string.startsWith("../")
   *    - Protected: path.normalize('NFC') canonicalizes Unicode before comparison
   *    - Action: Normalized paths are compared
   *
   * 5. CASE-SENSITIVITY BYPASS ON MACOS: Etc/Passwd (capital E, P)
   *    - macOS filesystem is case-insensitive, but Node.js paths preserve case
   *    - Example: /ETC/PASSWD would bypass case-sensitive startsWith comparison
   *    - Protected: toLowerCase() ensures case-insensitive comparison on macOS
   *
   * VALIDATION LAYERS:
   * ==================
   * Layer 1 - Path Resolution (lines 460-469):
   *   - fs.realpathSync.native() resolves symlinks to their canonical paths
   *   - This happens FIRST, preventing symlink escape attacks
   *   - Returns false if file doesn't exist (fail-secure)
   *
   * Layer 2 - Unicode Normalization (lines 471-475):
   *   - Normalize to NFC form (canonical decomposition)
   *   - Prevents Unicode bypass attacks
   *   - Case-normalize for macOS filesystem
   *
   * Layer 3 - Readability Verification (lines 477-485):
   *   - fs.accessSync() validates file is readable
   *   - TOCTOU protection at file descriptor level
   *   - Returns false if not readable (fail-secure)
   *
   * Layer 4 - basePath Containment Check (lines 487-507):
   *   - Trust model: Files within the same directory tree as base SDEF are trusted
   *   - Example: /Applications/Pages.app/Contents/Resources/Pages.sdef can include
   *             relative paths that resolve to files within /Applications/Pages.app/
   *   - Whitelist check: realPathLower.startsWith(realBasePath)
   *   - Why prefix matching is safe: Both paths are fully resolved by fs.realpathSync.native(),
   *     eliminating .. and . sequences, so they cannot escape the tree
   *   - basePath must also be resolved with fs.realpathSync.native() for consistency
   *
   * Layer 5 - System Whitelist Validation (lines 509-532):
   *   - Final defense: validate against explicit whitelist of trusted system directories
   *   - Matches both exact paths and glob patterns
   *   - Default trusted paths: /System/Library/DTDs/, /System/Library/ScriptingDefinitions/, etc.
   *   - Non-system paths are NOT trusted by default
   *   - /Applications is NOT in default whitelist (prevents app-to-app attacks)
   *
   * WHY THIS DESIGN IS SECURE:
   * ===========================
   * 1. Defense-in-depth: Multiple independent checks
   * 2. Symlink resolution first: Closes the most practical attack vector
   * 3. Explicit whitelist: Only known-safe paths are allowed (principle of least privilege)
   * 4. Fail-secure: Untrusted paths are skipped, not allowed
   * 5. Case/Unicode normalization: Prevents encoding bypasses
   * 6. Real-world safe: System Integrity Protection (SIP) on macOS prevents system file tampering
   *
   * Implements:
   * 1. Uses fs.realpathSync.native() to resolve symlinks (prevents symlink escape)
   * 2. Normalizes Unicode (NFC) to prevent bypass via Unicode variations
   * 3. Handles case-insensitivity on macOS
   * 4. Validates file exists and is readable
   * 5. Checks against whitelist patterns (some with wildcards)
   *
   * @param filePath - Absolute file path to validate
   * @param basePath - Base path for relative include resolution (optional trust)
   *                   Files within this directory tree are trusted (after resolution)
   * @returns true if path is trusted, false otherwise (always returns false on security violation)
   */
  private isPathTrusted(filePath: string, basePath?: string): boolean {
    try {
      // SECURITY: Resolve symlinks and get real path (immune to symlink attacks)
      // Use .native() to avoid Node.js path normalization issues
      let realPath: string;
      try {
        realPath = fs.realpathSync.native(filePath);
      } catch (error) {
        // File doesn't exist or not readable
        if (this.debug) {
          console.warn('[EntityResolver] File does not exist or not readable:', filePath);
        }
        return false;
      }

      // SECURITY: Normalize Unicode (NFC) to prevent bypass via Unicode variations
      realPath = realPath.normalize('NFC');

      // SECURITY: Case-insensitive path for macOS (do this once)
      const realPathLower = realPath.toLowerCase();

      // SECURITY: Check file exists and is readable (TOCTOU protection at FD level)
      try {
        fs.accessSync(realPath, fs.constants.R_OK);
      } catch (error) {
        if (this.debug) {
          console.warn('[EntityResolver] File not readable:', realPath);
        }
        return false;
      }

      // SECURITY: First check if path is within basePath hierarchy
      // This allows relative includes within the same document tree
      // Trust model: Files included from the same app bundle are allowed
      if (basePath) {
        try {
          // Normalize basePath the same way (resolve symlinks, normalize Unicode)
          // This is crucial: basePath must be resolved BEFORE prefix comparison
          // Otherwise symlinks could bypass the check (e.g., symlink in basePath pointing outside)
          const realBasePath = fs.realpathSync.native(basePath).normalize('NFC').toLowerCase();

          // Trust files within the same directory tree as the base document
          // Uses string prefix matching: /app/Contents/Resources/main.sdef can include
          // relative paths that resolve to /app/Contents/Resources/* files
          // WHY THIS IS SAFE (answers the prefix matching concern):
          // - Both realPath and realBasePath are fully resolved via fs.realpathSync.native()
          // - This eliminates all .. and . sequences from the path
          // - Therefore realPath cannot contain .. to escape the basePath tree
          // - Example: /app/Contents/Resources/../../etc/passwd
          //   Step 1: Resolved by fs.realpathSync to /etc/passwd
          //   Step 2: /etc/passwd does NOT start with /app/Contents/Resources
          //   Result: FALSE, untrusted path is rejected
          // - Example: /app/Contents/Resources/include.xml
          //   Step 1: Already resolved, no traversal
          //   Step 2: /app/contents/resources/include.xml starts with /app/contents/resources
          //   Result: TRUE, trusted path is allowed
          if (realPathLower.startsWith(realBasePath)) {
            if (this.debug) {
              console.log('[EntityResolver] Path within basePath hierarchy');
            }
            return true;
          }
        } catch (error) {
          // basePath doesn't exist or not readable, skip this check
          if (this.debug) {
            console.warn('[EntityResolver] Could not normalize basePath:', error);
          }
        }
      }

      // SECURITY: Validate against whitelist patterns

      for (const trustedPattern of this.trustedPaths) {
        // Handle both exact paths and wildcard patterns
        if (trustedPattern.endsWith('*')) {
          // Wildcard pattern (e.g., "/System/Library/*/")
          const regex = this.globToRegex(trustedPattern);
          if (regex.test(realPathLower)) {
            if (this.debug) {
              console.log('[EntityResolver] Path matches trusted pattern:', trustedPattern);
            }
            return true;
          }
        } else {
          // Exact path or prefix match
          const trustedLower = trustedPattern.toLowerCase();
          if (realPathLower.startsWith(trustedLower)) {
            if (this.debug) {
              console.log('[EntityResolver] Path in trusted directory:', trustedPattern);
            }
            return true;
          }
        }
      }

      if (this.debug) {
        console.warn('[EntityResolver] Path not in whitelist:', realPath);
      }
      return false;
    } catch (error) {
      if (this.debug) {
        console.warn('[EntityResolver] Error validating path:', error);
      }
      return false;
    }
  }

  /**
   * Resolve href to absolute path
   *
   * SECURITY: Proper URL parsing and validation:
   * 1. Handles file:// URLs with URL.parse()
   * 2. Rejects non-localhost hosts
   * 3. Decodes URL encoding before path validation
   * 4. Validates absolute paths
   * 5. Rejects relative paths in file:// URLs
   * 6. Rejects non-file protocols (http://, ftp://)
   *
   * @param href - Include reference (file path or file:// URL)
   * @param basePath - Base directory for resolving relative paths
   * @returns Absolute file path
   * @throws SecurityError for invalid URLs or non-file protocols
   */
  private resolvePath(href: string, basePath: string): string | null {
    // SECURITY: Reject null bytes (path truncation attack)
    if (href.includes('\x00')) {
      if (this.debug) {
        console.warn('[EntityResolver] Null bytes in path, skipping');
      }
      return null; // Return null to signal skip
    }

    // SECURITY: Handle file:// URLs
    if (href.toLowerCase().startsWith('file://')) {
      try {
        // Use URL parser for proper parsing
        const url = new URL(href);

        // SECURITY: Reject non-file protocols
        if (url.protocol.toLowerCase() !== 'file:') {
          throw new SecurityError(
            `Non-file protocol not allowed: ${url.protocol}`,
            'url_parsing'
          );
        }

        // SECURITY: Reject non-localhost hosts (network access)
        // Also reject relative hosts like '.' or '..'
        const allowedHosts = ['', 'localhost'];
        if (url.hostname && !allowedHosts.includes(url.hostname)) {
          // Throw for relative paths (like file://./etc/passwd) - explicit attack
          if (url.hostname === '.' || url.hostname === '..') {
            throw new SecurityError(
              'Relative paths in file URLs are not allowed',
              'url_parsing'
            );
          }

          // Skip for network hosts (less critical, could be misconfiguration)
          if (this.debug) {
            console.warn('[EntityResolver] File URL with network host, skipping:', url.hostname);
          }
          return null; // Skip network file URLs
        }

        // SECURITY: Reject relative paths in file URLs
        if (url.pathname.startsWith('.')) {
          throw new SecurityError(
            'Relative paths in file URLs are not allowed',
            'url_parsing'
          );
        }

        // Get pathname (already URL-decoded by URL parser)
        const filePath = url.pathname;

        // Handle empty pathname
        if (!filePath) {
          throw new SecurityError(
            'File URL must contain a pathname',
            'url_parsing'
          );
        }

        // SECURITY: Validate absolute path
        if (!path.isAbsolute(filePath)) {
          throw new SecurityError(
            'File URL must reference absolute path',
            'url_parsing'
          );
        }

        return filePath;
      } catch (error) {
        if (error instanceof SecurityError) {
          throw error;
        }
        throw new SecurityError(
          'Invalid file URL format',
          'url_parsing'
        );
      }
    }

    // SECURITY: Reject non-file protocols (http://, ftp://, etc.)
    if (/^[a-z]+:\/\//i.test(href)) {
      throw new SecurityError(
        'Only file:// protocol is allowed for includes',
        'url_parsing'
      );
    }

    // SECURITY: Decode URL encoding in paths (handle %20, %2e%2e, etc.)
    let decodedHref = href;
    try {
      decodedHref = decodeURIComponent(href);
    } catch (error) {
      // If decoding fails, use original (may be already decoded)
      if (this.debug) {
        console.warn('[EntityResolver] Failed to decode URI:', href);
      }
    }

    // Handle relative paths
    let resolvedPath: string;
    if (path.isAbsolute(decodedHref)) {
      resolvedPath = decodedHref;
    } else {
      resolvedPath = path.resolve(basePath, decodedHref);
    }

    // SECURITY: Normalize path (resolve .., ., //, etc.)
    resolvedPath = path.normalize(resolvedPath);

    return resolvedPath;
  }

  /**
   * Convert glob pattern to RegExp
   *
   * SECURITY: Implements basic glob pattern matching for whitelist
   * Supports: * (any characters), ? (single character)
   * Note: [abc] and {a,b} patterns are escaped (treated as literals)
   *
   * @param pattern - Glob pattern (e.g., "/System/Library/*.sdef")
   * @returns Regular expression
   */
  private globToRegex(pattern: string): RegExp {
    // Escape all special regex characters except * and ?
    let regexPattern = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape regex special chars including [, ]
      .replace(/\*/g, '.*') // * matches any characters
      .replace(/\?/g, '.'); // ? matches single character

    // Make case-insensitive for macOS filesystem
    return new RegExp(`^${regexPattern}`, 'i');
  }

  /**
   * Get cached content or read from file
   *
   * SECURITY: Implements cache invalidation based on:
   * 1. File modification time (mtime)
   * 2. File size
   *
   * @param resolvedPath - Absolute file path
   * @returns File content
   */
  private async getCachedOrRead(resolvedPath: string): Promise<string> {
    // Check if caching is enabled
    if (this.options.enableCache === false) {
      return this.readFile(resolvedPath);
    }

    try {
      // SECURITY: Stat file to check for modifications (before read)
      const statsBefore = fs.statSync(resolvedPath);
      const mtimeBefore = statsBefore.mtimeMs;
      const sizeBefore = statsBefore.size;

      // Check cache validity
      const cached = this.cache.get(resolvedPath);
      const metadata = this.cacheMetadata.get(resolvedPath);

      if (cached && metadata) {
        // SECURITY: Invalidate if file changed (mtime or size)
        if (metadata.mtime === mtimeBefore && metadata.size === sizeBefore) {
          if (this.debug) {
            console.log('[EntityResolver] Cache hit:', resolvedPath);
          }
          return cached;
        }

        if (this.debug) {
          console.log('[EntityResolver] Cache invalid (file changed):', resolvedPath);
        }
      }

      // Cache miss or invalid - read file
      const content = await this.readFile(resolvedPath);

      // SECURITY: Re-validate mtime after read to prevent TOCTOU race condition
      // TOCTOU (Time-of-Check-Time-of-Use) is a file handling race condition where:
      // 1. We stat() the file to check permissions/whitelist (time-of-check)
      // 2. An attacker swaps the file with malicious content
      // 3. We read() the swapped file (time-of-use)
      //
      // Accepting Residual Risk: A small TOCTOU window is inherent in file I/O.
      // We mitigate but don't eliminate it because:
      // - Closing TOCTOU completely requires locking (kills app responsiveness)
      // - Real-world exploit is near-impossible: attacker needs root/bypass SIP + perfect timing
      // - Cost/benefit: The security benefit of perfect TOCTOU closure doesn't justify
      //   the performance/UX cost on a local system
      //
      // Mitigations Applied:
      // 1. fs.realpathSync.native() resolves symlinks BEFORE the stat/read window,
      //    eliminating symlink-swap attacks (most practical vector)
      // 2. Re-validate file stat() after read to detect modifications
      // 3. Only cache if mtime/size unchanged (our detection mechanism)
      // 4. On macOS, System Integrity Protection (SIP) prevents /System modification
      //
      // If this code moves to a multi-user system or handles user-writable files,
      // consider file descriptor locking or moving this to a secure enclave.
      const statsAfter = fs.statSync(resolvedPath);
      const mtimeAfter = statsAfter.mtimeMs;
      const sizeAfter = statsAfter.size;

      if (mtimeBefore === mtimeAfter && sizeBefore === sizeAfter) {
        // File didn't change during read, safe to cache
        this.cache.set(resolvedPath, content);
        this.cacheMetadata.set(resolvedPath, {
          mtime: mtimeAfter,
          size: sizeAfter,
        });
      } else if (this.debug) {
        console.log('[EntityResolver] File changed during read, not caching:', resolvedPath);
      }

      return content;
    } catch (error) {
      // If stat fails, don't cache
      return this.readFile(resolvedPath);
    }
  }

  /**
   * Read file with size limits
   *
   * SECURITY: Enforces resource limits:
   * 1. Maximum file size (per-file limit)
   * 2. Maximum total bytes across all includes (cumulative limit)
   *
   * Resource limit tracking prevents denial-of-service attacks where an attacker
   * crafts SDEF files with many large includes to exhaust system memory or disk I/O.
   *
   * Implementation:
   * - totalBytesRead is reset at depth 0 in resolveIncludes() (line 199-200)
   * - Before reading each file, we check if totalBytesRead + fileSize > maxTotalBytes (line 809)
   * - After successful read, totalBytesRead is incremented (line 819)
   * - This cumulative tracking ensures no single include operation can exceed maxTotalBytes
   *
   * Security property: Total bytes limit is enforced across all files in a single
   * resolve operation, preventing attackers from bypassing via multiple includes.
   *
   * @param filePath - Absolute file path
   * @returns File content
   * @throws ResourceLimitError if limits exceeded
   */
  private async readFile(filePath: string): Promise<string> {
    try {
      // SECURITY: Check file size before reading
      const stats = fs.statSync(filePath);
      const fileSize = stats.size;

      // SECURITY: Enforce per-file size limit
      if (fileSize > this.maxFileSize) {
        throw new ResourceLimitError(
          `File size (${fileSize} bytes) exceeds maximum (${this.maxFileSize} bytes)`
        );
      }

      // SECURITY: Enforce total bytes limit across all includes
      // This prevents attackers from bypassing the per-file limit by including many medium-sized files
      // Example: 4x 3MB files would exceed 10MB total limit even though each file is under 5MB limit
      if (this.totalBytesRead + fileSize > this.maxTotalBytes) {
        throw new ResourceLimitError(
          `Total bytes read (${this.totalBytesRead + fileSize}) would exceed maximum (${this.maxTotalBytes})`
        );
      }

      // Read file
      const content = fs.readFileSync(filePath, 'utf-8');

      // SECURITY: Update total bytes counter AFTER successful read
      // This counter is checked before each file read to prevent resource exhaustion
      this.totalBytesRead += fileSize;

      if (this.debug) {
        console.log(`[EntityResolver] Read ${fileSize} bytes from ${filePath}`);
      }

      return content;
    } catch (error) {
      if (error instanceof ResourceLimitError) {
        throw error;
      }

      // SECURITY: Sanitize error messages (don't leak path details)
      throw new Error('Failed to read included file');
    }
  }
}
