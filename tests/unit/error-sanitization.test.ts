/**
 * Tests for Error Message Sanitization
 *
 * Security-focused tests for the error message sanitization in buildFallbackMetadata.
 * Ensures that error messages exposed in parsingStatus.errorMessage do NOT leak:
 * - File system paths
 * - User directories
 * - Stack traces
 * - System configuration
 *
 * This addresses the MODERATE security issue identified in PR bot review.
 */

import { describe, it, expect } from 'vitest';
import { buildFallbackMetadata } from '../../src/jitd/discovery/app-metadata-builder.js';
import type { AppWithSDEF } from '../../src/jitd/discovery/find-sdef.js';

/**
 * Create mock AppWithSDEF for testing
 */
function createMockApp(appName: string): AppWithSDEF {
  return {
    appName,
    bundlePath: `/Applications/${appName}.app`,
    sdefPath: `/Applications/${appName}.app/Contents/Resources/${appName}.sdef`,
  };
}

describe('Error Message Sanitization', () => {
  describe('Path sanitization', () => {
    it('should remove absolute file paths from error messages', () => {
      const app = createMockApp('TestApp');
      const error = new Error('Failed to read /Users/john/Library/Application Support/TestApp/config.json');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.status).toBe('failed');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/Users/john');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/Library');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should remove SDEF file paths from error messages', () => {
      const app = createMockApp('Safari');
      const error = new Error('XML parsing failed for /Applications/Safari.app/Contents/Resources/Safari.sdef');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('/Applications/Safari.app');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Safari.sdef');
      // Since this contains "parsing", it gets mapped to generic message
      expect(metadata.parsingStatus.errorMessage).toBe('XML parsing error in SDEF file');
    });

    it('should remove system paths from error messages', () => {
      const app = createMockApp('Finder');
      const error = new Error('Cannot access /System/Library/CoreServices/Finder.app/Contents/Info.plist');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('/System/Library');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Info.plist');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should remove home directory references (tilde)', () => {
      const app = createMockApp('App');
      const error = new Error('Failed to load ~/Documents/config.yaml');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('~/Documents');
      expect(metadata.parsingStatus.errorMessage).not.toContain('config.yaml');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should remove Windows paths (cross-platform testing)', () => {
      const app = createMockApp('App');
      const error = new Error('Failed to read C:\\Users\\John\\AppData\\config.json');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('C:\\Users\\John');
      expect(metadata.parsingStatus.errorMessage).not.toContain('AppData');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should remove multiple paths in single error message', () => {
      const app = createMockApp('App');
      const error = new Error('Copy failed: /source/file.txt to /dest/file.txt');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('/source/file.txt');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/dest/file.txt');
      // Should have two <file path> replacements
      expect(metadata.parsingStatus.errorMessage).toMatch(/<file path>.*<file path>/);
    });
  });

  describe('Stack trace sanitization', () => {
    it('should remove stack traces from error messages', () => {
      const app = createMockApp('App');
      const errorWithStack = new Error('Parsing failed');
      errorWithStack.stack = `Error: Parsing failed
    at parse (/Users/dev/project/parser.js:42:15)
    at processFile (/Users/dev/project/index.js:100:20)
    at main (/Users/dev/project/index.js:200:5)`;

      // Override message to simulate error.message including stack
      const error = new Error(errorWithStack.stack);

      const metadata = buildFallbackMetadata(app, error);

      // Should only contain first line
      expect(metadata.parsingStatus.errorMessage).not.toContain('at parse');
      expect(metadata.parsingStatus.errorMessage).not.toContain('parser.js');
      expect(metadata.parsingStatus.errorMessage).not.toContain('index.js');
      // Should not have newlines
      expect(metadata.parsingStatus.errorMessage).not.toContain('\n');
    });

    it('should keep only first line of multi-line error messages', () => {
      const app = createMockApp('App');
      const error = new Error('XML parsing error\nLine 42: Unexpected token\nColumn 15: Missing closing tag');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toContain('XML parsing error');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Line 42');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Column 15');
    });
  });

  describe('Message truncation', () => {
    it('should truncate very long error messages to 200 chars', () => {
      const app = createMockApp('App');
      const longMessage = 'A'.repeat(300);
      const error = new Error(longMessage);

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage!.length).toBeLessThanOrEqual(200);
      expect(metadata.parsingStatus.errorMessage).toMatch(/\.\.\.$/);
    });

    it('should not truncate short messages', () => {
      const app = createMockApp('App');
      const shortMessage = 'Short error';
      const error = new Error(shortMessage);

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe(shortMessage);
      expect(metadata.parsingStatus.errorMessage).not.toMatch(/\.\.\.$/);
    });

    it('should truncate at 197 chars and add ellipsis (total 200)', () => {
      const app = createMockApp('App');
      const message = 'X'.repeat(250);
      const error = new Error(message);

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toHaveLength(200);
      expect(metadata.parsingStatus.errorMessage).toBe('X'.repeat(197) + '...');
    });
  });

  describe('Generic message mapping', () => {
    it('should map ENOENT errors to generic message', () => {
      const app = createMockApp('App');
      const error = new Error('ENOENT: no such file or directory, open \'/path/to/file.sdef\'');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe('SDEF file not found or inaccessible');
      expect(metadata.parsingStatus.errorMessage).not.toContain('ENOENT');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/path/to/file.sdef');
    });

    it('should map permission denied errors to generic message', () => {
      const app = createMockApp('App');
      const error = new Error('EACCES: permission denied, access \'/restricted/file.sdef\'');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe('Permission denied reading SDEF file');
      expect(metadata.parsingStatus.errorMessage).not.toContain('EACCES');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/restricted');
    });

    it('should map XML parsing errors to generic message', () => {
      const app = createMockApp('App');
      const error = new Error('XML parse error: Unexpected token at line 42');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe('XML parsing error in SDEF file');
      expect(metadata.parsingStatus.errorMessage).not.toContain('line 42');
    });

    it('should map parse keyword errors to generic message', () => {
      const app = createMockApp('App');
      const error = new Error('Failed to parse SDEF: Invalid structure');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe('XML parsing error in SDEF file');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Invalid structure');
    });

    it('should be case-insensitive for error pattern matching', () => {
      const app = createMockApp('App');
      const error1 = new Error('PERMISSION DENIED');
      const error2 = new Error('Permission Denied');
      const error3 = new Error('permission denied');

      const metadata1 = buildFallbackMetadata(app, error1);
      const metadata2 = buildFallbackMetadata(app, error2);
      const metadata3 = buildFallbackMetadata(app, error3);

      expect(metadata1.parsingStatus.errorMessage).toBe('Permission denied reading SDEF file');
      expect(metadata2.parsingStatus.errorMessage).toBe('Permission denied reading SDEF file');
      expect(metadata3.parsingStatus.errorMessage).toBe('Permission denied reading SDEF file');
    });
  });

  describe('Non-Error input handling', () => {
    it('should handle string errors', () => {
      const app = createMockApp('App');
      const error = 'String error with /path/to/file.txt' as any;

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('/path/to/file.txt');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should handle empty error messages', () => {
      const app = createMockApp('App');
      const error = new Error('');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe('');
    });

    it('should handle null-like values', () => {
      const app = createMockApp('App');
      const error = new Error('null');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBeDefined();
    });
  });

  describe('Security validation - NO LEAKS', () => {
    it('should NEVER expose username in error messages', () => {
      const app = createMockApp('App');
      const error = new Error('Failed to access /Users/alice/Desktop/file.sdef');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('alice');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/Users/alice');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Desktop');
    });

    it('should NEVER expose full file paths', () => {
      const app = createMockApp('App');
      const error = new Error('Cannot read /Applications/MyApp.app/Contents/Resources/MyApp.sdef');

      const metadata = buildFallbackMetadata(app, error);

      // Should not contain ANY path segments
      expect(metadata.parsingStatus.errorMessage).not.toContain('/Applications');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/Contents');
      expect(metadata.parsingStatus.errorMessage).not.toContain('/Resources');
      expect(metadata.parsingStatus.errorMessage).not.toContain('.sdef');
    });

    it('should NEVER expose stack trace information', () => {
      const app = createMockApp('App');
      const errorMsg = `Error: Parse failed
    at SDEFParser.parse (/Users/dev/iac-mcp/src/parser.ts:120:15)
    at async discoverAppMetadata (/Users/dev/iac-mcp/src/mcp/handlers.ts:94:28)`;
      const error = new Error(errorMsg);

      const metadata = buildFallbackMetadata(app, error);

      // Should not contain ANY stack trace elements
      expect(metadata.parsingStatus.errorMessage).not.toContain('at ');
      expect(metadata.parsingStatus.errorMessage).not.toContain('.ts:');
      expect(metadata.parsingStatus.errorMessage).not.toContain('parser');
      expect(metadata.parsingStatus.errorMessage).not.toContain('handlers');
      expect(metadata.parsingStatus.errorMessage).not.toContain('async');
    });

    it('should NEVER expose Node.js internal paths', () => {
      const app = createMockApp('App');
      const error = new Error('Module not found: /usr/local/lib/node_modules/xml2js/index.js');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('/usr/local');
      expect(metadata.parsingStatus.errorMessage).not.toContain('node_modules');
      expect(metadata.parsingStatus.errorMessage).not.toContain('xml2js');
    });
  });

  describe('Combined sanitization scenarios', () => {
    it('should sanitize complex error with paths, stack trace, and long message', () => {
      const app = createMockApp('App');
      const longPath = '/Users/developer/Projects/my-app/node_modules/some-lib/dist/index.js';
      const errorMsg = `Failed to parse SDEF at ${longPath}: ${'X'.repeat(300)}
    at parse (${longPath}:42:15)
    at processFile (${longPath}:100:20)`;
      const error = new Error(errorMsg);

      const metadata = buildFallbackMetadata(app, error);

      // Generic message should be used (contains 'parse')
      expect(metadata.parsingStatus.errorMessage).toBe('XML parsing error in SDEF file');
    });

    it('should sanitize error with multiple security issues', () => {
      const app = createMockApp('App');
      const error = new Error('Read failed: /Users/john/file.sdef\nStack: at parser.js:42\nPath: ~/Desktop/config');

      const metadata = buildFallbackMetadata(app, error);

      // Should remove all sensitive info and keep only first line
      expect(metadata.parsingStatus.errorMessage).not.toContain('john');
      expect(metadata.parsingStatus.errorMessage).not.toContain('file.sdef');
      expect(metadata.parsingStatus.errorMessage).not.toContain('parser.js');
      expect(metadata.parsingStatus.errorMessage).not.toContain('~/Desktop');
      // Should not have newlines
      expect(metadata.parsingStatus.errorMessage).not.toContain('\n');
    });
  });

  describe('Real-world error examples', () => {
    it('should sanitize real xml2js parse error', () => {
      const app = createMockApp('BBEdit');
      const error = new Error('Error: Non-whitespace before first tag.\nLine: 0\nColumn: 1\nChar: <');

      const metadata = buildFallbackMetadata(app, error);

      // Should remove stack trace (take only first line)
      expect(metadata.parsingStatus.errorMessage).toBe('Error: Non-whitespace before first tag.');
      expect(metadata.parsingStatus.errorMessage).not.toContain('\n');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Line:');
      expect(metadata.parsingStatus.errorMessage).not.toContain('Column:');
    });

    it('should sanitize real file system error', () => {
      const app = createMockApp('CustomApp');
      const error = new Error('ENOENT: no such file or directory, open \'/Applications/CustomApp.app/Contents/Resources/CustomApp.sdef\'');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe('SDEF file not found or inaccessible');
    });

    it('should sanitize real permission error', () => {
      const app = createMockApp('SystemApp');
      const error = new Error('EACCES: permission denied, access \'/System/Library/PrivateFrameworks/App.app/Contents/Resources/App.sdef\'');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).toBe('Permission denied reading SDEF file');
    });
  });

  describe('Metadata structure validation', () => {
    it('should always include status field', () => {
      const app = createMockApp('App');
      const error = new Error('Test error');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus).toHaveProperty('status');
      expect(metadata.parsingStatus.status).toBe('failed');
    });

    it('should always include errorMessage field for failed status', () => {
      const app = createMockApp('App');
      const error = new Error('Test error');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus).toHaveProperty('errorMessage');
      expect(metadata.parsingStatus.errorMessage).toBeDefined();
    });

    it('should maintain other metadata fields', () => {
      const app = createMockApp('TestApp');
      const error = new Error('Test error');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.appName).toBe('TestApp');
      expect(metadata.bundleId).toBeDefined();
      expect(metadata.toolCount).toBe(0);
      expect(metadata.suiteNames).toEqual([]);
    });
  });
});
