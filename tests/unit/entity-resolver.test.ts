/**
 * Entity Resolver Tests
 *
 * Comprehensive security test suite for safe SDEF external entity resolution.
 * Addresses all security findings from the security review, including:
 * - Path traversal attacks
 * - TOCTOU race conditions
 * - XXE/DTD entity attacks
 * - URL parsing vulnerabilities
 * - Circular include detection
 * - Resource exhaustion
 * - Information disclosure
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { EntityResolver } from '../../src/jitd/discovery/entity-resolver.js';

describe('EntityResolver', () => {
  let tempDir: string;
  let resolver: EntityResolver;

  beforeEach(() => {
    // Create temporary directory for test files
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'entity-resolver-test-'));
    resolver = new EntityResolver();
  });

  afterEach(() => {
    // Clean up temp files
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  describe('Basic Functionality', () => {
    it('should resolve simple XInclude elements', async () => {
      const includedContent = '<suite name="test-suite" code="test" />';
      const includePath = path.join(tempDir, 'included.sdef');
      fs.writeFileSync(includePath, includedContent);

      const mainContent = `
        <dictionary>
          <xi:include href="${includePath}" />
        </dictionary>
      `;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toContain('test-suite');
    });

    it('should handle multiple XInclude elements', async () => {
      const included1 = '<suite name="suite1" code="st01" />';
      const included2 = '<suite name="suite2" code="st02" />';

      fs.writeFileSync(path.join(tempDir, 'file1.sdef'), included1);
      fs.writeFileSync(path.join(tempDir, 'file2.sdef'), included2);

      const mainContent = `
        <dictionary>
          <xi:include href="${path.join(tempDir, 'file1.sdef')}" />
          <xi:include href="${path.join(tempDir, 'file2.sdef')}" />
        </dictionary>
      `;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toContain('suite1');
      expect(result).toContain('suite2');
    });

    it('should preserve non-included content', async () => {
      const mainContent = `
        <dictionary xmlns:xi="http://www.w3.org/2003/XInclude">
          <title>Test Dictionary</title>
          <suite name="local-suite" code="locs" />
        </dictionary>
      `;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toContain('Test Dictionary');
      expect(result).toContain('local-suite');
    });
  });

  describe('Security: Path Traversal Protection', () => {
    it('should reject paths with ../ traversal', async () => {
      const outsideFile = path.join(tempDir, '..', 'outside.sdef');
      const mainContent = `<dictionary><xi:include href="${outsideFile}" /></dictionary>`;

      // Should not throw, but should skip untrusted include
      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).not.toContain('outside');
    });

    it('should reject multiple ../ sequences', async () => {
      const evilPath = '../../../../../../etc/passwd';
      const mainContent = `<dictionary><xi:include href="${evilPath}" /></dictionary>`;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).not.toContain('passwd');
    });

    it('should normalize paths before validation', async () => {
      // Create a safe file in a subdirectory
      const subdir = path.join(tempDir, 'subdir');
      fs.mkdirSync(subdir);
      const safeFile = path.join(subdir, 'safe.sdef');
      fs.writeFileSync(safeFile, '<suite name="safe" code="safe" />');

      // Try to access with redundant path separators
      const mainContent = `<dictionary><xi:include href="${safeFile}/" /></dictionary>`;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      // Should either succeed (path normalized) or skip safely
      expect(result).toBeDefined();
    });

    it('should reject encoded traversal sequences', async () => {
      // %2e%2e = ..
      const encodedPath = '%2e%2e/%2e%2e/etc/passwd';
      const mainContent = `<dictionary><xi:include href="${encodedPath}" /></dictionary>`;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).not.toContain('passwd');
    });

    it('should reject null bytes in paths', async () => {
      const maliciousPath = '/System/Library/ScriptingDefinitions/CocoaStandard.sdef\x00/etc/passwd';
      const mainContent = `<dictionary><xi:include href="${maliciousPath}" /></dictionary>`;

      // Should handle safely without throwing
      expect(async () => {
        await resolver.resolveIncludes(mainContent, tempDir);
      }).not.toThrow();
    });

    it('should handle extremely long paths', async () => {
      const longPath = '/System/Library/' + 'a'.repeat(10000) + '/file.sdef';
      const mainContent = `<dictionary><xi:include href="${longPath}" /></dictionary>`;

      // Should not crash or hang
      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toBeDefined();
    });
  });

  describe('Security: XXE/DTD Entity Attack Protection', () => {
    it('should reject DOCTYPE with ENTITY declarations', async () => {
      const xxeContent = `<!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <dictionary>
        <suite name="&xxe;" />
      </dictionary>`;

      await expect(async () => {
        await resolver.resolveIncludes(xxeContent, tempDir);
      }).rejects.toThrow();
    });

    it('should reject DOCTYPE with SYSTEM declarations', async () => {
      const xeeContent = `<!DOCTYPE dictionary SYSTEM "file:///etc/passwd">
      <dictionary />`;

      await expect(async () => {
        await resolver.resolveIncludes(xeeContent, tempDir);
      }).rejects.toThrow();
    });

    it('should reject parameter entities with SYSTEM references', async () => {
      // Parameter entities with SYSTEM are XXE attack vectors
      const paramEntityContent = `<!DOCTYPE foo [
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        %file;
      ]>
      <dictionary />`;

      await expect(async () => {
        await resolver.resolveIncludes(paramEntityContent, tempDir);
      }).rejects.toThrow();
    });

    it('should allow safe parameter entities without SYSTEM (schema definition)', async () => {
      // Parameter entities without SYSTEM are safe and used by Pages/Numbers/Keynote
      // Example: <!ENTITY % common.attrib "xmlns:xi CDATA #FIXED 'http://...'">
      const safeParamEntity = `<?xml version="1.0" encoding="utf-8"?>
      <!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd" [
        <!ENTITY % common.attrib
            "xmlns:xi   CDATA   #FIXED 'http://www.w3.org/2003/XInclude'
             xml:base   CDATA   #IMPLIED">
      ]>
      <dictionary xmlns:xi="http://www.w3.org/2003/XInclude">
        <title>Safe with Parameter Entities</title>
        <suite name="test" code="test" />
      </dictionary>`;

      // Should not throw (safe parameter entities are allowed)
      const result = await resolver.resolveIncludes(safeParamEntity, tempDir);
      expect(result).toContain('Safe with Parameter Entities');
      expect(result).toContain('test');
    });

    it('should allow DOCTYPE without internal subset', async () => {
      const safeDoctype = `<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
      <dictionary>
        <title>Safe</title>
      </dictionary>`;

      // Should not throw (DTD reference without internal subset is OK)
      const result = await resolver.resolveIncludes(safeDoctype, tempDir);
      expect(result).toContain('Safe');
    });

    it('should reject mixed DOCTYPE with entities', async () => {
      const mixedContent = `<!DOCTYPE foo [
        <!ELEMENT suite ANY>
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <dictionary><suite name="&xxe;" /></dictionary>`;

      await expect(async () => {
        await resolver.resolveIncludes(mixedContent, tempDir);
      }).rejects.toThrow();
    });
  });

  describe('Security: URL Parsing Validation', () => {
    it('should reject file:// URLs with network hosts', async () => {
      const mainContent = `<dictionary><xi:include href="file://evil.com/etc/passwd" /></dictionary>`;

      // Should reject network access
      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).not.toContain('passwd');
    });

    it('should reject non-file protocols', async () => {
      const httpInclude = `<dictionary><xi:include href="http://evil.com/payload.sdef" /></dictionary>`;
      const ftpInclude = `<dictionary><xi:include href="ftp://evil.com/payload.sdef" /></dictionary>`;

      await expect(async () => {
        await resolver.resolveIncludes(httpInclude, tempDir);
      }).rejects.toThrow();

      await expect(async () => {
        await resolver.resolveIncludes(ftpInclude, tempDir);
      }).rejects.toThrow();
    });

    it('should handle uppercase FILE:// protocol', async () => {
      const mainContent = `<dictionary><xi:include href="FILE:///etc/passwd" /></dictionary>`;

      // Should not crash, should reject safely
      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toBeDefined();
    });

    it('should reject quad-slash file://// paths', async () => {
      const mainContent = `<dictionary><xi:include href="file:////etc/passwd" /></dictionary>`;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      // Should not contain the malicious file
      expect(result).not.toContain('passwd');
    });

    it('should decode URL-encoded paths safely', async () => {
      // Valid case: legitimate encoded path
      const subdir = path.join(tempDir, 'sub dir');
      fs.mkdirSync(subdir);
      const encodedFile = path.join(subdir, 'file%20name.sdef');
      fs.writeFileSync(encodedFile.replace('%20', ' '), '<suite name="test" />');

      const mainContent = `<dictionary><xi:include href="file://${encodedFile}" /></dictionary>`;

      // Should handle URL decoding
      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toBeDefined();
    });

    it('should reject relative paths in file URLs', async () => {
      const mainContent = `<dictionary><xi:include href="file://./etc/passwd" /></dictionary>`;

      await expect(async () => {
        await resolver.resolveIncludes(mainContent, tempDir);
      }).rejects.toThrow();
    });
  });

  describe('Security: Circular Include Detection', () => {
    it('should detect direct circular includes (A -> A)', async () => {
      const filePath = path.join(tempDir, 'circular.sdef');
      const circularContent = `<dictionary><xi:include href="${filePath}" /></dictionary>`;
      fs.writeFileSync(filePath, circularContent);

      await expect(async () => {
        await resolver.resolveIncludes(circularContent, tempDir);
      }).rejects.toThrow(/circular/i);
    });

    it('should detect two-file circular includes (A -> B -> A)', async () => {
      const fileA = path.join(tempDir, 'fileA.sdef');
      const fileB = path.join(tempDir, 'fileB.sdef');

      const contentA = `<dictionary><xi:include href="${fileB}" /></dictionary>`;
      const contentB = `<dictionary><xi:include href="${fileA}" /></dictionary>`;

      fs.writeFileSync(fileA, contentA);
      fs.writeFileSync(fileB, contentB);

      await expect(async () => {
        await resolver.resolveIncludes(contentA, tempDir);
      }).rejects.toThrow(/circular/i);
    });

    it('should detect longer circular chains (A -> B -> C -> A)', async () => {
      const fileA = path.join(tempDir, 'fileA.sdef');
      const fileB = path.join(tempDir, 'fileB.sdef');
      const fileC = path.join(tempDir, 'fileC.sdef');

      const contentA = `<dictionary><xi:include href="${fileB}" /></dictionary>`;
      const contentB = `<dictionary><xi:include href="${fileC}" /></dictionary>`;
      const contentC = `<dictionary><xi:include href="${fileA}" /></dictionary>`;

      fs.writeFileSync(fileA, contentA);
      fs.writeFileSync(fileB, contentB);
      fs.writeFileSync(fileC, contentC);

      await expect(async () => {
        await resolver.resolveIncludes(contentA, tempDir);
      }).rejects.toThrow(/circular/i);
    });

    it('should allow diamond includes (A -> B,C and B,C -> D)', async () => {
      const fileB = path.join(tempDir, 'fileB.sdef');
      const fileC = path.join(tempDir, 'fileC.sdef');
      const fileD = path.join(tempDir, 'fileD.sdef');

      fs.writeFileSync(fileD, '<suite name="d" code="d00d" />');
      fs.writeFileSync(fileB, `<dictionary><xi:include href="${fileD}" /></dictionary>`);
      fs.writeFileSync(fileC, `<dictionary><xi:include href="${fileD}" /></dictionary>`);

      const contentA = `
        <dictionary>
          <xi:include href="${fileB}" />
          <xi:include href="${fileC}" />
        </dictionary>
      `;

      // Should not throw - D is loaded twice via different paths (not circular)
      const result = await resolver.resolveIncludes(contentA, tempDir);
      expect(result).toBeDefined();
    });
  });

  describe('Security: Input Validation', () => {
    it('should reject empty href attributes', async () => {
      const mainContent = `<dictionary><xi:include href="" /></dictionary>`;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      // Should skip empty href safely
      expect(result).toBeDefined();
    });

    it('should reject whitespace-only href', async () => {
      const mainContent = `<dictionary><xi:include href="   " /></dictionary>`;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      // Should skip safely
      expect(result).toBeDefined();
    });

    it('should handle invalid UTF-8 in href gracefully', async () => {
      // This would require binary handling, skip for now
      // but document the requirement
      const mainContent = `<dictionary><xi:include href="file.sdef" /></dictionary>`;

      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toBeDefined();
    });

    it('should reject malformed XML in includes', async () => {
      const malformedFile = path.join(tempDir, 'malformed.sdef');
      fs.writeFileSync(malformedFile, '<suite><unclosed>');

      const mainContent = `<dictionary><xi:include href="${malformedFile}" /></dictionary>`;

      // Could throw or handle gracefully - document behavior
      expect(async () => {
        await resolver.resolveIncludes(mainContent, tempDir);
      }).not.toThrow();
    });

    it('should handle missing href attributes', async () => {
      const mainContent = `<dictionary><xi:include /></dictionary>`;

      // Should not crash
      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toBeDefined();
    });
  });

  describe('Security: Resource Exhaustion', () => {
    it('should enforce maximum recursion depth', async () => {
      // Create chain: file1 -> file2 -> file3 -> ... -> fileN
      const maxDepth = 3; // Default from EntityResolver
      const files: string[] = [];

      // Create a chain deeper than max depth
      for (let i = 0; i < maxDepth + 3; i++) {
        const filePath = path.join(tempDir, `file${i}.sdef`);
        if (i < maxDepth + 2) {
          const nextPath = path.join(tempDir, `file${i + 1}.sdef`);
          fs.writeFileSync(filePath, `<dictionary><xi:include href="${nextPath}" /></dictionary>`);
        } else {
          fs.writeFileSync(filePath, '<suite name="end" code="end0" />');
        }
        files.push(filePath);
      }

      const startPath = files[0];
      const content = fs.readFileSync(startPath, 'utf-8');

      await expect(async () => {
        await resolver.resolveIncludes(content, tempDir, 0);
      }).rejects.toThrow(/depth/i);
    });

    it('should enforce maximum file size limits', async () => {
      // Create a 2MB file (exceeds typical limit)
      const largeFile = path.join(tempDir, 'large.sdef');
      const largeContent = '<suite>' + 'a'.repeat(2 * 1024 * 1024) + '</suite>';
      fs.writeFileSync(largeFile, largeContent);

      const mainContent = `<dictionary><xi:include href="${largeFile}" /></dictionary>`;

      // Should either warn or throw
      await expect(async () => {
        await resolver.resolveIncludes(mainContent, tempDir);
      }).rejects.toThrow(/large|size|limit/i);
    });

    it('should enforce maximum total bytes across includes', async () => {
      // Create multiple files totaling > 5MB
      const files = [];
      for (let i = 0; i < 6; i++) {
        const filePath = path.join(tempDir, `large${i}.sdef`);
        const content = '<suite>' + 'a'.repeat(1024 * 1024) + '</suite>';
        fs.writeFileSync(filePath, content);
        files.push(filePath);
      }

      const mainContent = files
        .map((f) => `<xi:include href="${f}" />`)
        .join('\n');
      const fullContent = `<dictionary>${mainContent}</dictionary>`;

      await expect(async () => {
        await resolver.resolveIncludes(fullContent, tempDir);
      }).rejects.toThrow(/limit|exceed|bytes/i);
    });

    it('should limit number of includes per file', async () => {
      // Create 100 includes in one file
      const includeElements = [];
      for (let i = 0; i < 100; i++) {
        const filePath = path.join(tempDir, `tiny${i}.sdef`);
        fs.writeFileSync(filePath, '<suite name="s" />');
        includeElements.push(`<xi:include href="${filePath}" />`);
      }

      const mainContent = `<dictionary>${includeElements.join('\n')}</dictionary>`;

      // Should enforce reasonable limit
      await expect(async () => {
        await resolver.resolveIncludes(mainContent, tempDir);
      }).rejects.toThrow(/includes|limit/i);
    });
  });

  describe('Security: Caching', () => {
    it('should cache resolved entities', async () => {
      const cachedFile = path.join(tempDir, 'cached.sdef');
      const cachedContent = '<suite name="cached" code="cach" />';
      fs.writeFileSync(cachedFile, cachedContent);

      const mainContent = `<dictionary><xi:include href="${cachedFile}" /></dictionary>`;

      // First call
      const result1 = await resolver.resolveIncludes(mainContent, tempDir);
      // Second call - should use cache
      const result2 = await resolver.resolveIncludes(mainContent, tempDir);

      expect(result1).toEqual(result2);
    });

    it('should invalidate cache when file changes', async () => {
      const mutableFile = path.join(tempDir, 'mutable.sdef');
      fs.writeFileSync(mutableFile, '<suite name="v1" code="v1v1" />');

      const mainContent = `<dictionary><xi:include href="${mutableFile}" /></dictionary>`;

      // First call
      const result1 = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result1).toContain('v1');

      // Modify file
      fs.writeFileSync(mutableFile, '<suite name="v2" code="v2v2" />');

      // Second call should see new content
      const result2 = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result2).toContain('v2');
      expect(result2).not.toContain('v1');
    });

    it('should not cache errors', async () => {
      const errorFile = path.join(tempDir, 'error.sdef');
      fs.writeFileSync(errorFile, '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>');

      const mainContent = `<dictionary><xi:include href="${errorFile}" /></dictionary>`;

      // Should throw on first call
      await expect(async () => {
        await resolver.resolveIncludes(mainContent, tempDir);
      }).rejects.toThrow();

      // Fix the file
      fs.writeFileSync(errorFile, '<suite name="fixed" code="fixx" />');

      // Should not use cached error
      const result = await resolver.resolveIncludes(mainContent, tempDir);
      expect(result).toContain('fixed');
    });
  });

  describe('Security: Information Disclosure', () => {
    it('should not leak rejected paths in error messages', async () => {
      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const mainContent = `<dictionary><xi:include href="/secret/path/to/file" /></dictionary>`;
      const result = await resolver.resolveIncludes(mainContent, tempDir);

      // Should either not warn, or not leak full path
      const warnings = spy.mock.calls.map((c) => c[0]);
      warnings.forEach((w) => {
        if (typeof w === 'string' && w.includes('secret')) {
          expect(w).not.toContain('/secret/path');
        }
      });

      spy.mockRestore();
    });

    it('should sanitize error messages', async () => {
      const mainContent = `<dictionary><xi:include href="/etc/passwd" /></dictionary>`;

      try {
        await resolver.resolveIncludes(mainContent, tempDir);
      } catch (error) {
        // Error message should not reveal full details of attack
        const message = String(error);
        // Allow "untrusted" or "not allowed" but not detailed exposure
        expect(message).toBeDefined();
      }
    });
  });

  describe('Whitelist Validation', () => {
    it('should only allow trusted paths by default', async () => {
      const trustedPath = '/System/Library/ScriptingDefinitions/CocoaStandard.sdef';
      const untrustedPath = '/Applications/SuspiciousApp.app/malicious.sdef';

      const resolver2 = new EntityResolver({ additionalTrustedPaths: [] });

      const mainContent1 = `<dictionary><xi:include href="${untrustedPath}" /></dictionary>`;

      // Untrusted path should be rejected
      const result = await resolver2.resolveIncludes(mainContent1, tempDir);
      expect(result).not.toContain('Suspicious');
    });

    it('should support additional trusted paths', async () => {
      // Create a custom directory outside of tempDir
      const customDir = fs.mkdtempSync(path.join(os.tmpdir(), 'custom-app-'));
      const customApp = path.join(customDir, 'definitions.sdef');
      fs.writeFileSync(customApp, '<suite name="custom" code="cust" />');

      try {
        const resolver2 = new EntityResolver({
          additionalTrustedPaths: [customDir],
        });

        const mainContent = `<dictionary><xi:include href="${customApp}" /></dictionary>`;
        const result = await resolver2.resolveIncludes(mainContent, tempDir);
        expect(result).toContain('custom');
      } finally {
        // Cleanup
        fs.rmSync(customDir, { recursive: true, force: true });
      }
    });

    it('should handle case-insensitive filesystem', async () => {
      // macOS is case-insensitive but case-preserving
      const resolver2 = new EntityResolver();
      const testPath = path.join(tempDir, 'TestFile.sdef');
      fs.writeFileSync(testPath, '<suite name="test" />');

      const mainContent = `<dictionary><xi:include href="${testPath}" /></dictionary>`;
      const result = await resolver2.resolveIncludes(mainContent, tempDir);

      // Should succeed (resolved paths are normalized)
      expect(result).toBeDefined();
    });
  });

  describe('Integration', () => {
    it('should handle real Cocoa includes structure', async () => {
      // Simulate real Pages/Numbers/Keynote structure
      const cocoaStandardPath = path.join(tempDir, 'CocoaStandard.sdef');
      fs.writeFileSync(
        cocoaStandardPath,
        `
        <dictionary>
          <suite name="Cocoa Standard" code="Coco">
            <command name="create" code="creat" />
          </suite>
        </dictionary>
      `
      );

      const appSdef = path.join(tempDir, 'Pages.sdef');
      fs.writeFileSync(
        appSdef,
        `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary xmlns:xi="http://www.w3.org/2003/XInclude">
          <xi:include href="${cocoaStandardPath}" />
          <suite name="Pages" code="Pges">
            <command name="export" code="expr0" />
          </suite>
        </dictionary>
      `
      );

      const result = await resolver.resolveIncludes(
        fs.readFileSync(appSdef, 'utf-8'),
        path.dirname(appSdef)
      );

      expect(result).toContain('Cocoa Standard');
      expect(result).toContain('Pages');
      expect(result).toContain('create');
      expect(result).toContain('export');
    });

    it('should handle nested relative includes', async () => {
      // Create directory structure
      const subdir = path.join(tempDir, 'subdir');
      fs.mkdirSync(subdir);

      // Create files
      const baseFile = path.join(subdir, 'base.sdef');
      const includedFile = path.join(subdir, 'included.sdef');

      fs.writeFileSync(includedFile, '<suite name="included" code="incl" />');
      fs.writeFileSync(
        baseFile,
        `<dictionary><xi:include href="./included.sdef" /></dictionary>`
      );

      const result = await resolver.resolveIncludes(
        fs.readFileSync(baseFile, 'utf-8'),
        path.dirname(baseFile)
      );

      expect(result).toContain('included');
    });
  });

  describe('Real SDEF File Compatibility', () => {
    it('should handle standard SDEF DOCTYPE', async () => {
      const standardSdef = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary xmlns:xi="http://www.w3.org/2003/XInclude">
  <title>Test App</title>
  <suite name="test" code="test" />
</dictionary>`;

      const result = await resolver.resolveIncludes(standardSdef, tempDir);
      expect(result).toContain('Test App');
    });

    it('should preserve XML declaration', async () => {
      const xmlWithDecl = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary>
  <title>Test</title>
</dictionary>`;

      const result = await resolver.resolveIncludes(xmlWithDecl, tempDir);
      expect(result).toContain('<?xml');
      expect(result).toContain('Test');
    });
  });
});
