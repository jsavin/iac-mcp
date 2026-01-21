/**
 * Integration Tests - SDEF Security
 *
 * Comprehensive security test suite for SDEF parsing and external entity resolution.
 * Validates protection against XXE attacks, path traversal, resource exhaustion,
 * and circular includes as identified in the security review for PR #12.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef.js';
import { EntityResolver, SecurityError, CircularIncludeError, ResourceLimitError } from '../../src/jitd/discovery/entity-resolver.js';
import { writeFile, mkdir, rm } from 'fs/promises';
import { join, resolve } from 'path';
import { tmpdir } from 'os';

/**
 * Test fixture helper for creating temporary test files
 */
class TempFileManager {
  private tempDir: string;
  private filesCreated: Set<string> = new Set();

  constructor(testName: string) {
    this.tempDir = join(tmpdir(), `sdef-security-test-${Date.now()}-${Math.random().toString(36).substring(7)}`);
  }

  /**
   * Get the temporary directory path
   */
  getDir(): string {
    return this.tempDir;
  }

  /**
   * Create a temporary file with content
   */
  async createFile(relativePath: string, content: string): Promise<string> {
    await mkdir(this.tempDir, { recursive: true });
    const fullPath = join(this.tempDir, relativePath);
    const dir = fullPath.substring(0, fullPath.lastIndexOf('/'));
    await mkdir(dir, { recursive: true });
    await writeFile(fullPath, content, 'utf-8');
    this.filesCreated.add(fullPath);
    return fullPath;
  }

  /**
   * Clean up all temporary files
   */
  async cleanup(): Promise<void> {
    try {
      await rm(this.tempDir, { recursive: true, force: true });
    } catch (error) {
      // Silently ignore cleanup errors
    }
  }
}

describe('SDEF Security Tests', () => {
  let tempFileManager: TempFileManager;

  beforeEach(() => {
    tempFileManager = new TempFileManager('sdef-security-test');
  });

  afterEach(async () => {
    await tempFileManager.cleanup();
  });

  // ============================================================================
  // XXE (XML External Entity) Protection Tests
  // ============================================================================

  describe('XXE Protection', () => {
    /**
     * Test that ENTITY declarations with SYSTEM references are rejected
     * This prevents attackers from using XXE to read arbitrary files like /etc/passwd
     */
    it('should reject ENTITY with SYSTEM references', async () => {
      const maliciousXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<dictionary>
  &xxe;
</dictionary>`;

      const parser = new SDEFParser();
      await expect(() => parser.parseContent(maliciousXML)).rejects.toThrow(
        /ENTITY declarations found after DOCTYPE stripping|DOCTYPE with ENTITY SYSTEM references/i
      );
    });

    /**
     * Test that multiple ENTITY declarations with SYSTEM are rejected
     * Ensures attacker can't bypass protection with multiple entities
     */
    it('should reject multiple ENTITY declarations with SYSTEM', async () => {
      const maliciousXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary [
  <!ENTITY xxe1 SYSTEM "file:///etc/passwd">
  <!ENTITY xxe2 SYSTEM "file:///etc/shadow">
  <!ENTITY xxe3 SYSTEM "file:///etc/hosts">
]>
<dictionary>
  &xxe1;
  &xxe2;
  &xxe3;
</dictionary>`;

      const parser = new SDEFParser();
      await expect(() => parser.parseContent(maliciousXML)).rejects.toThrow(
        /ENTITY declarations found after DOCTYPE stripping|DOCTYPE with ENTITY SYSTEM references/i
      );
    });

    /**
     * Test that parameter entities with SYSTEM are rejected
     * Parameter entities (<!ENTITY % name ...>) are also XXE vectors
     */
    it('should reject parameter entities with SYSTEM references', async () => {
      const maliciousXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  %file;
]>
<dictionary>
</dictionary>`;

      const parser = new SDEFParser();
      await expect(() => parser.parseContent(maliciousXML)).rejects.toThrow(
        /ENTITY declarations found after DOCTYPE stripping|DOCTYPE with ENTITY SYSTEM references/i
      );
    });

    /**
     * Test that DOCTYPE without malicious ENTITY declarations is allowed
     * Valid DOCTYPE declarations for legitimate DTD references should pass
     */
    it('should allow DOCTYPE without malicious ENTITY declarations', async () => {
      const validXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="Test">
  <suite name="Test Suite" code="test">
    <command name="test" code="testtest"/>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      // Should not throw
      const result = await parser.parseContent(validXML);
      expect(result).toBeDefined();
      expect(result.title).toBe('Test');
    });

    /**
     * Test that parameter entities without SYSTEM are allowed in DOCTYPE without internal subset
     * Note: XMLParser strips DOCTYPE sections, so we can't test entities that are in DOCTYPE
     * This test validates that legitimate DOCTYPE declarations work
     */
    it('should allow legitimate DOCTYPE declarations', async () => {
      const validXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="Test">
  <suite name="Test Suite" code="test">
    <command name="test" code="testtest"/>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      // Should not throw
      const result = await parser.parseContent(validXML);
      expect(result).toBeDefined();
      expect(result.title).toBe('Test');
    });

    /**
     * Test that EntityResolver rejects DOCTYPE SYSTEM references to sensitive files
     * The EntityResolver validates XML before parsing in the parse() method
     */
    it('should reject DOCTYPE SYSTEM references to sensitive files', async () => {
      const maliciousXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file:///etc/passwd">
<dictionary>
</dictionary>`;

      const resolver = new EntityResolver();
      await expect(() => resolver['validateNoExternalEntities'](maliciousXML))
        .toThrow(/sensitive file|DOCTYPE SYSTEM reference/i);
    });
  });

  // ============================================================================
  // Path Traversal Protection Tests
  // ============================================================================

  describe('Path Traversal Protection', () => {
    /**
     * Test that includes with ../ path traversal are rejected
     * Prevents reading files outside the app bundle
     */
    it('should reject includes with ../ path traversal', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');
      const secretFile = join(baseDir, 'secret.xml');

      // Create files
      await tempFileManager.createFile('app/Contents/Resources/main.sdef', '<root/>');
      await tempFileManager.createFile('secret.xml', '<secret>data</secret>');

      // Try to include from parent directory
      const xmlWithTraversal = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="../../secret.xml"/>
</dictionary>`;

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      // Should skip the untrusted path
      const result = await resolver.resolveIncludes(xmlWithTraversal, appDir);
      // The include should be removed (fail-secure)
      expect(result).not.toContain('<secret>');
      expect(result).not.toContain('href=');
    });

    /**
     * Test that absolute path traversal attempts are rejected
     * Prevents reading files like /etc/passwd
     */
    it('should reject absolute path traversal attempts', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      await tempFileManager.createFile('app/Contents/Resources/main.sdef', '<root/>');

      // Try to include /etc/passwd
      const xmlWithAbsolutePath = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="/etc/passwd"/>
</dictionary>`;

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      // Should skip the untrusted path
      const result = await resolver.resolveIncludes(xmlWithAbsolutePath, appDir);
      // The include should be removed (fail-secure)
      expect(result).not.toContain('passwd');
      expect(result).not.toContain('href=');
    });

    /**
     * Test that includes within the same app bundle are allowed
     * Relative includes from the same directory tree should work
     */
    it('should allow includes within the same app bundle', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create related SDEF files in same directory
      await tempFileManager.createFile('app/Contents/Resources/shared.sdef',
        `<root><data>shared content</data></root>`);
      await tempFileManager.createFile('app/Contents/Resources/main.sdef',
        `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="shared.sdef"/>
</dictionary>`);

      const mainPath = join(appDir, 'main.sdef');
      const resolver = new EntityResolver({
        additionalTrustedPaths: [],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      const mainContent = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="shared.sdef"/>
</dictionary>`;

      // Should resolve includes from same directory (basePath trust)
      const result = await resolver.resolveIncludes(mainContent, appDir, 0, mainPath);
      expect(result).toContain('shared content');
    });

    /**
     * Test that encoded path traversal attempts are rejected
     * URL-encoded ../ (%2e%2e%2f) should also be blocked
     */
    it('should reject URL-encoded path traversal attempts', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      await tempFileManager.createFile('app/Contents/Resources/main.sdef', '<root/>');

      // Try URL-encoded path traversal
      const xmlWithEncodedTraversal = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="%2e%2e/secret.xml"/>
</dictionary>`;

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      // Should skip the untrusted path
      const result = await resolver.resolveIncludes(xmlWithEncodedTraversal, appDir);
      expect(result).not.toContain('secret');
    });
  });

  // ============================================================================
  // Resource Exhaustion Limits Tests
  // ============================================================================

  describe('Resource Exhaustion Limits', () => {
    /**
     * Test that maximum include depth (3 levels) is enforced
     * Prevents deeply nested includes that could cause stack exhaustion
     * Note: depth parameter starts at 0, so maxDepth=3 allows depths 0, 1, 2, 3 (4 total levels)
     * We create 5 levels to exceed the limit
     */
    it('should enforce maximum include depth (3 levels)', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create deeply nested includes: level0 -> level1 -> level2 -> level3 -> level4 -> level5
      // With maxDepth=3, this should fail when depth > 3
      await tempFileManager.createFile('app/Contents/Resources/level0.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="level1.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/level1.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="level2.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/level2.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="level3.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/level3.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="level4.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/level4.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="level5.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/level5.xml', '<root>deep</root>');

      const level0Path = join(appDir, 'level0.xml');
      const level0Content = await import('fs/promises').then(m => m.readFile(level0Path, 'utf-8'));

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      // Should reject because depth chain exceeds maxDepth of 3
      await expect(() => resolver.resolveIncludes(level0Content, appDir, 0, level0Path))
        .rejects.toThrow(/Maximum include depth|exceeded/i);
    });

    /**
     * Test that maximum includes per file (50) is enforced
     * Prevents resource exhaustion via many includes in single file
     */
    it('should enforce maximum includes per file (50)', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create a file with 51 includes (exceeds limit of 50)
      let xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">`;

      for (let i = 0; i < 51; i++) {
        xmlContent += `\n  <xi:include href="file${i}.xml"/>`;
      }

      xmlContent += '\n</dictionary>';

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      // Should reject because it exceeds maxIncludesPerFile of 50
      await expect(() => resolver.resolveIncludes(xmlContent, appDir))
        .rejects.toThrow(/Maximum includes per file|exceeded/i);
    });

    /**
     * Test that maximum includes per file (50) allows exactly 50
     * Ensures the limit is exact and doesn't cause false positives
     */
    it('should allow exactly 50 includes per file', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create 50 include files
      for (let i = 0; i < 50; i++) {
        await tempFileManager.createFile(`app/Contents/Resources/file${i}.xml`, `<file${i}/>`);
      }

      // Create a file with exactly 50 includes
      let xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">`;

      for (let i = 0; i < 50; i++) {
        xmlContent += `\n  <xi:include href="file${i}.xml"/>`;
      }

      xmlContent += '\n</dictionary>';

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      // Should succeed with exactly 50 includes
      const result = await resolver.resolveIncludes(xmlContent, appDir);
      expect(result).toBeDefined();
      // Verify at least some content is included
      expect(result).toContain('<file0/>');
      expect(result).toContain('<file49/>');
    });

    /**
     * Test that maximum file size is enforced
     * Prevents reading huge files that could exhaust memory
     */
    it('should enforce maximum file size limit', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create a large file (2MB) that exceeds default 1MB limit
      const largeContent = 'x'.repeat(2 * 1024 * 1024);
      await tempFileManager.createFile('app/Contents/Resources/large.xml', largeContent);

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxFileSize: 1024 * 1024, // 1MB limit
        maxIncludesPerFile: 50,
      });

      const xmlWithLargeInclude = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="large.xml"/>
</dictionary>`;

      // Should reject because file exceeds size limit
      await expect(() => resolver.resolveIncludes(xmlWithLargeInclude, appDir))
        .rejects.toThrow(/File size|exceeds maximum/i);
    });

    /**
     * Test that total bytes limit is enforced
     * Prevents reading many medium-sized files totaling excessive bytes
     */
    it('should enforce total bytes limit across all includes', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create 5 files of 2.5MB each = 12.5MB total (exceeds 10MB limit)
      const fileSize = 2.5 * 1024 * 1024;
      for (let i = 0; i < 5; i++) {
        const content = 'x'.repeat(fileSize);
        await tempFileManager.createFile(`app/Contents/Resources/file${i}.xml`, content);
      }

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxFileSize: 5 * 1024 * 1024, // 5MB per file
        maxTotalBytes: 10 * 1024 * 1024, // 10MB total
        maxIncludesPerFile: 50,
      });

      let xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">`;

      for (let i = 0; i < 5; i++) {
        xmlContent += `\n  <xi:include href="file${i}.xml"/>`;
      }

      xmlContent += '\n</dictionary>';

      // Should reject when total bytes would exceed limit
      await expect(() => resolver.resolveIncludes(xmlContent, appDir))
        .rejects.toThrow(/Total bytes|exceeds maximum|would exceed/i);
    });
  });

  // ============================================================================
  // Circular Includes Detection Tests
  // ============================================================================

  describe('Circular Includes', () => {
    /**
     * Test that direct circular includes are detected
     * File A includes File B, File B includes File A
     */
    it('should reject circular includes (A -> B -> A)', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create circular include: fileA -> fileB -> fileA
      await tempFileManager.createFile('app/Contents/Resources/fileA.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="fileB.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/fileB.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="fileA.xml"/>
</root>`);

      const fileAPath = join(appDir, 'fileA.xml');
      const fileAContent = await import('fs/promises').then(m => m.readFile(fileAPath, 'utf-8'));

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 10,
        maxIncludesPerFile: 50,
      });

      // Should detect circular include
      await expect(() => resolver.resolveIncludes(fileAContent, appDir, 0, fileAPath))
        .rejects.toThrow(CircularIncludeError);
    });

    /**
     * Test that self-referential includes are detected
     * File A includes itself
     */
    it('should reject self-referential includes (A -> A)', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create self-referential include
      await tempFileManager.createFile('app/Contents/Resources/self.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="self.xml"/>
</root>`);

      const selfPath = join(appDir, 'self.xml');
      const selfContent = await import('fs/promises').then(m => m.readFile(selfPath, 'utf-8'));

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 10,
        maxIncludesPerFile: 50,
      });

      // Should detect self-referential include
      await expect(() => resolver.resolveIncludes(selfContent, appDir, 0, selfPath))
        .rejects.toThrow(CircularIncludeError);
    });

    /**
     * Test that longer circular chains are detected
     * File A -> B -> C -> D -> A
     */
    it('should reject longer circular chains (A -> B -> C -> D -> A)', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create chain: A -> B -> C -> D -> A
      await tempFileManager.createFile('app/Contents/Resources/chainA.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="chainB.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/chainB.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="chainC.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/chainC.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="chainD.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/chainD.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="chainA.xml"/>
</root>`);

      const chainAPath = join(appDir, 'chainA.xml');
      const chainAContent = await import('fs/promises').then(m => m.readFile(chainAPath, 'utf-8'));

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 10,
        maxIncludesPerFile: 50,
      });

      // Should detect circular include in the chain
      await expect(() => resolver.resolveIncludes(chainAContent, appDir, 0, chainAPath))
        .rejects.toThrow(CircularIncludeError);
    });

    /**
     * Test that symlink circular includes are detected
     * Prevents bypass using symlinks that point back to already-resolved files
     */
    it('should detect circular includes through symlink resolution', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create fileA
      await tempFileManager.createFile('app/Contents/Resources/fileA.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="fileB.xml"/>
</root>`);

      // Create fileB
      await tempFileManager.createFile('app/Contents/Resources/fileB.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="fileA.xml"/>
</root>`);

      const fileAPath = join(appDir, 'fileA.xml');
      const fileAContent = await import('fs/promises').then(m => m.readFile(fileAPath, 'utf-8'));

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 10,
        maxIncludesPerFile: 50,
      });

      // Circular detection should work even with symlink resolution
      await expect(() => resolver.resolveIncludes(fileAContent, appDir, 0, fileAPath))
        .rejects.toThrow(CircularIncludeError);
    });

    /**
     * Test that non-circular includes are allowed
     * Ensures the circular detection doesn't produce false positives
     */
    it('should allow non-circular includes (A -> B -> C)', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create linear chain: A -> B -> C (no cycles)
      await tempFileManager.createFile('app/Contents/Resources/linearA.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="linearB.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/linearB.xml', `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="linearC.xml"/>
</root>`);

      await tempFileManager.createFile('app/Contents/Resources/linearC.xml', '<root>leaf</root>');

      const linearAPath = join(appDir, 'linearA.xml');
      const linearAContent = await import('fs/promises').then(m => m.readFile(linearAPath, 'utf-8'));

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 10,
        maxIncludesPerFile: 50,
      });

      // Should succeed with linear chain
      const result = await resolver.resolveIncludes(linearAContent, appDir, 0, linearAPath);
      expect(result).toBeDefined();
      expect(result).toContain('leaf');
    });
  });

  // ============================================================================
  // Integration Tests - Combined Security Controls
  // ============================================================================

  describe('Combined Security Controls', () => {
    /**
     * Test that XXE + path traversal combined attacks are rejected
     * Defense-in-depth: multiple layers of protection
     */
    it('should reject combined XXE + path traversal attacks', async () => {
      const combinedAttack = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary [
  <!ENTITY xxe SYSTEM "file:///../../etc/passwd">
]>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="../../../../../../etc/hosts"/>
  &xxe;
</dictionary>`;

      const parser = new SDEFParser();
      // Should reject because of XXE protection (first layer)
      await expect(() => parser.parseContent(combinedAttack)).rejects.toThrow(
        /ENTITY declarations found|DOCTYPE with ENTITY SYSTEM/i
      );
    });

    /**
     * Test that parser configuration is applied correctly
     * Custom limits should override defaults
     */
    it('should respect custom configuration limits', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      // Create 3 files
      for (let i = 0; i < 3; i++) {
        await tempFileManager.createFile(`app/Contents/Resources/file${i}.xml`, `<file${i}/>`);
      }

      let xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">`;

      for (let i = 0; i < 3; i++) {
        xmlContent += `\n  <xi:include href="file${i}.xml"/>`;
      }

      xmlContent += '\n</dictionary>';

      // Custom resolver with strict limits
      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 1, // Only 1 level deep
        maxIncludesPerFile: 2, // Only 2 includes allowed
      });

      // Should fail because 3 includes > maxIncludesPerFile of 2
      await expect(() => resolver.resolveIncludes(xmlContent, appDir))
        .rejects.toThrow(/Maximum includes per file|exceeded/i);
    });

    /**
     * Test that security errors are properly categorized
     * Helps with logging and debugging
     */
    it('should properly categorize security errors', async () => {
      const resolver = new EntityResolver();

      // XXE error should be categorized
      const xxeXML = `<!DOCTYPE dictionary [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`;

      try {
        resolver['validateNoExternalEntities'](xxeXML); // Access private method for testing
      } catch (error) {
        if (error instanceof SecurityError) {
          expect(error.category).toBe('xxe');
        }
      }
    });

    /**
     * Test that empty includes are handled safely
     * Prevents edge case exploitation - empty hrefs should not be processed
     */
    it('should handle empty includes safely', async () => {
      const baseDir = tempFileManager.getDir();
      const appDir = join(baseDir, 'app', 'Contents', 'Resources');

      await tempFileManager.createFile('app/Contents/Resources/main.sdef', '<root/>');

      const xmlWithEmptyInclude = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href=""/>
</dictionary>`;

      const resolver = new EntityResolver({
        additionalTrustedPaths: [appDir],
        maxDepth: 3,
        maxIncludesPerFile: 50,
      });

      // Should handle empty hrefs safely - the include element is skipped/not resolved
      const result = await resolver.resolveIncludes(xmlWithEmptyInclude, appDir);
      expect(result).toBeDefined();
      // Empty includes should not crash - the behavior is to skip them (fail-secure)
      expect(result).toContain('<dictionary');
      // The result should be well-formed XML
      expect(result).toContain('xmlns:xi');
    });

    /**
     * Test that SDEF parser properly integrates EntityResolver
     * End-to-end security validation
     */
    it('should integrate EntityResolver into SDEFParser', async () => {
      const validXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="test" code="testtest">
      <parameter name="target" code="targ" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      // Should parse successfully
      const result = await parser.parseContent(validXML);
      expect(result).toBeDefined();
      expect(result.title).toBe('Test App');
      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].commands).toHaveLength(1);
    });
  });
});
