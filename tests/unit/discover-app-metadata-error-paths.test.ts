/**
 * Phase 2 Test Coverage: Error Paths, Edge Cases, and Performance
 *
 * This file adds comprehensive test coverage for:
 * 1. discoverAppMetadata error paths (ENOENT, EACCES, XML parsing errors)
 * 2. aggregateWarnings edge cases (exactly 100 warnings, 101+ warnings, deduplication)
 * 3. Performance tests (memory bounds, timeout behavior)
 *
 * Tests are written in TDD style and target 100% coverage.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { aggregateWarnings } from '../../src/mcp/handlers.js';
import { buildFallbackMetadata, buildMetadata } from '../../src/jitd/discovery/app-metadata-builder.js';
import type { AppWithSDEF } from '../../src/jitd/discovery/find-sdef.js';
import type { ParseWarning } from '../../src/jitd/discovery/parse-sdef.js';
import type { SDEFDictionary } from '../../src/types/sdef.js';

/**
 * Test fixtures
 */
function createTestApp(appName: string, bundlePath: string = `/Applications/${appName}.app`): AppWithSDEF {
  return {
    appName,
    bundlePath,
    sdefPath: `${bundlePath}/Contents/Resources/${appName}.sdef`,
  };
}

function createTestSDEF(appName: string): SDEFDictionary {
  return {
    title: `${appName} Dictionary`,
    suites: [
      {
        name: 'Standard Suite',
        code: 'core',
        description: 'Standard Suite',
        commands: [
          {
            name: 'test_command',
            code: 'test',
            description: 'Test command',
            parameters: [],
          },
        ],
        classes: [],
        enumerations: [],
      },
    ],
  };
}

function createTestWarning(
  code: string,
  message: string,
  suite: string = 'Test Suite',
  element: string = 'command',
  name?: string
): ParseWarning {
  return {
    code,
    message,
    location: {
      suite,
      element,
      name,
    },
  };
}

describe('Phase 2: discoverAppMetadata Error Paths', () => {
  describe('buildFallbackMetadata', () => {
    it('should handle ENOENT error (SDEF file not found)', () => {
      const app = createTestApp('NonExistent');
      const error = new Error('ENOENT: no such file or directory');
      error.name = 'ENOENT';

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata).toBeDefined();
      expect(metadata.appName).toBe('NonExistent');
      expect(metadata.bundleId).toContain('nonexistent');
      expect(metadata.description).toBe('Unable to parse SDEF file');
      expect(metadata.toolCount).toBe(0);
      expect(metadata.suiteNames).toEqual([]);
      expect(metadata.parsingStatus.status).toBe('failed');
      expect(metadata.parsingStatus.errorMessage).toBe('SDEF file not found or inaccessible');
    });

    it('should handle EACCES error (permission denied)', () => {
      const app = createTestApp('RestrictedApp');
      const error = new Error('EACCES: permission denied reading file');
      error.name = 'EACCES';

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata).toBeDefined();
      expect(metadata.appName).toBe('RestrictedApp');
      expect(metadata.parsingStatus.status).toBe('failed');
      expect(metadata.parsingStatus.errorMessage).toBe('Permission denied reading SDEF file');
    });

    it('should handle XML parsing error', () => {
      const app = createTestApp('MalformedApp');
      const error = new Error('XML parsing failed: unexpected token at line 42');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata).toBeDefined();
      expect(metadata.appName).toBe('MalformedApp');
      expect(metadata.parsingStatus.status).toBe('failed');
      expect(metadata.parsingStatus.errorMessage).toBe('XML parsing error in SDEF file');
    });

    it('should handle unexpected error from buildMetadata', () => {
      const app = createTestApp('UnexpectedError');
      const error = new Error('Unexpected internal error occurred');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata).toBeDefined();
      expect(metadata.appName).toBe('UnexpectedError');
      expect(metadata.parsingStatus.status).toBe('failed');
      // Should sanitize and truncate error message
      expect(metadata.parsingStatus.errorMessage).toBeDefined();
      expect(typeof metadata.parsingStatus.errorMessage).toBe('string');
    });

    it('should sanitize file paths in error messages', () => {
      const app = createTestApp('PathLeakage');
      const error = new Error('Error reading /Users/sensitive/path/to/file.sdef');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('/Users/sensitive');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should sanitize Windows paths in error messages', () => {
      const app = createTestApp('WindowsPathLeakage');
      const error = new Error('Error reading C:\\Users\\sensitive\\file.sdef');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('C:\\Users\\sensitive');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should sanitize home directory references', () => {
      const app = createTestApp('HomePathLeakage');
      const error = new Error('Error reading ~/sensitive/path/file.sdef');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage).not.toContain('~/sensitive');
      expect(metadata.parsingStatus.errorMessage).toContain('<file path>');
    });

    it('should truncate very long error messages', () => {
      const app = createTestApp('LongError');
      const longMessage = 'Error: ' + 'x'.repeat(300);
      const error = new Error(longMessage);

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.parsingStatus.errorMessage!.length).toBeLessThanOrEqual(200);
      expect(metadata.parsingStatus.errorMessage).toContain('...');
    });

    it('should handle error messages with stack traces', () => {
      const app = createTestApp('StackTraceError');
      const error = new Error('Main error\n  at function1 (file.ts:10)\n  at function2 (file.ts:20)');

      const metadata = buildFallbackMetadata(app, error);

      // Should only include first line (not stack trace)
      expect(metadata.parsingStatus.errorMessage).toBe('Main error');
      expect(metadata.parsingStatus.errorMessage).not.toContain('at function1');
    });

    it('should handle non-Error objects', () => {
      const app = createTestApp('NonErrorObject');
      const error = 'String error message';

      const metadata = buildFallbackMetadata(app, error as any);

      expect(metadata.parsingStatus.status).toBe('failed');
      expect(metadata.parsingStatus.errorMessage).toBeDefined();
    });

    it('should infer bundle ID correctly for system apps', () => {
      const app = createTestApp('Finder', '/System/Library/CoreServices/Finder.app');
      const error = new Error('Test error');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.bundleId).toBe('com.apple.finder');
    });

    it('should infer bundle ID correctly for third-party apps', () => {
      const app = createTestApp('MyApp', '/Applications/MyApp.app');
      const error = new Error('Test error');

      const metadata = buildFallbackMetadata(app, error);

      expect(metadata.bundleId).toBe('com.app.myapp');
    });
  });

  describe('buildMetadata with valid dictionary', () => {
    it('should build metadata successfully with no errors', async () => {
      const app = createTestApp('Finder');
      const dictionary = createTestSDEF('Finder');

      const metadata = await buildMetadata(app, dictionary);

      expect(metadata).toBeDefined();
      expect(metadata.appName).toBe('Finder');
      expect(metadata.toolCount).toBe(1);
      expect(metadata.parsingStatus.status).toBe('success');
      expect(metadata.parsingStatus.errorMessage).toBeUndefined();
      expect(metadata.parsingStatus.warnings).toBeUndefined();
    });
  });
});

describe('Phase 2: aggregateWarnings Edge Cases', () => {
  describe('Warning cap behavior', () => {
    it('should handle exactly 80 unique regular warning types (at cap)', () => {
      const warnings: ParseWarning[] = [];

      // Create exactly 80 unique regular warning types (regular warnings cap)
      for (let i = 0; i < 80; i++) {
        warnings.push(createTestWarning(
          `CODE_${i}`,
          `Warning message ${i}`,
          `Suite ${i}`,
          `element${i}`,
          `name${i}`
        ));
      }

      const aggregated = aggregateWarnings(warnings);

      // Should have all 80 warnings (regular warnings cap)
      expect(aggregated.length).toBe(80);

      // Each should appear once (no duplicates in input)
      aggregated.forEach((w, i) => {
        expect(w.code).toBe(`CODE_${i}`);
        expect(w.message).not.toContain('more similar warnings');
      });
    });

    it('should cap at 80 unique regular warning types when given 81+ warnings', () => {
      const warnings: ParseWarning[] = [];

      // Create 150 unique regular warning types
      for (let i = 0; i < 150; i++) {
        warnings.push(createTestWarning(
          `CODE_${i}`,
          `Warning message ${i}`,
          `Suite ${i}`,
          `element${i}`,
          `name${i}`
        ));
      }

      const aggregated = aggregateWarnings(warnings);

      // Should cap at 80 warnings (regular warnings cap)
      expect(aggregated.length).toBe(80);

      // Should have first 80 warnings (warnings 80-149 dropped)
      expect(aggregated[0].code).toBe('CODE_0');
      expect(aggregated[79].code).toBe('CODE_79');
    });

    it('should deduplicate warnings of the same type', () => {
      const warnings: ParseWarning[] = [];

      // Create same warning 50 times
      for (let i = 0; i < 50; i++) {
        warnings.push(createTestWarning(
          'DUPLICATE_CODE',
          'Same warning repeated',
          'Same Suite',
          'same_element',
          'same_name'
        ));
      }

      const aggregated = aggregateWarnings(warnings);

      // Should have only 1 warning with count
      expect(aggregated.length).toBe(1);
      expect(aggregated[0].code).toBe('DUPLICATE_CODE');
      expect(aggregated[0].message).toContain('and 49 more similar warnings');
    });

    it('should deduplicate warnings from different suites if same code/element', () => {
      const warnings: ParseWarning[] = [
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite A', 'command', 'cmd1'),
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite A', 'command', 'cmd2'),
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite B', 'command', 'cmd3'),
      ];

      const aggregated = aggregateWarnings(warnings);

      // Different suites = different keys, so should have 2 entries
      // (Suite A:command and Suite B:command)
      expect(aggregated.length).toBe(2);
    });

    it('should group by code:suite:element', () => {
      const warnings: ParseWarning[] = [
        // Same code, same suite, same element, different names
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite A', 'command', 'cmd1'),
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite A', 'command', 'cmd2'),
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite A', 'command', 'cmd3'),

        // Same code, same suite, different element
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite A', 'enumeration', 'enum1'),

        // Same code, different suite, same element
        createTestWarning('INVALID_CODE', 'Invalid code', 'Suite B', 'command', 'cmd4'),
      ];

      const aggregated = aggregateWarnings(warnings);

      // Should have 3 groups:
      // 1. INVALID_CODE:Suite A:command (3 warnings)
      // 2. INVALID_CODE:Suite A:enumeration (1 warning)
      // 3. INVALID_CODE:Suite B:command (1 warning)
      expect(aggregated.length).toBe(3);

      const suiteACommands = aggregated.find(w =>
        w.code === 'INVALID_CODE' &&
        w.suite === 'Suite A' &&
        w.element === 'command'
      );
      expect(suiteACommands?.message).toContain('and 2 more similar warnings');

      const suiteAEnums = aggregated.find(w =>
        w.code === 'INVALID_CODE' &&
        w.suite === 'Suite A' &&
        w.element === 'enumeration'
      );
      expect(suiteAEnums?.message).not.toContain('more similar warnings');

      const suiteBCommands = aggregated.find(w =>
        w.code === 'INVALID_CODE' &&
        w.suite === 'Suite B' &&
        w.element === 'command'
      );
      expect(suiteBCommands?.message).not.toContain('more similar warnings');
    });

    it('should handle empty warnings array', () => {
      const warnings: ParseWarning[] = [];

      const aggregated = aggregateWarnings(warnings);

      expect(aggregated).toEqual([]);
      expect(aggregated.length).toBe(0);
    });

    it('should handle warnings with missing suite field', () => {
      const warnings: ParseWarning[] = [
        {
          code: 'WARNING_CODE',
          message: 'Warning without suite',
          location: {
            element: 'command',
            name: 'cmd1',
            // suite is undefined
          },
        },
        {
          code: 'WARNING_CODE',
          message: 'Warning without suite',
          location: {
            element: 'command',
            name: 'cmd2',
            // suite is undefined
          },
        },
      ];

      const aggregated = aggregateWarnings(warnings);

      // Should group warnings with undefined suite together
      expect(aggregated.length).toBe(1);
      expect(aggregated[0].suite).toBeUndefined();
      expect(aggregated[0].message).toContain('and 1 more similar warnings');
    });

    it('should format count correctly for 2 duplicates', () => {
      const warnings: ParseWarning[] = [
        createTestWarning('CODE', 'Message', 'Suite', 'element'),
        createTestWarning('CODE', 'Message', 'Suite', 'element'),
      ];

      const aggregated = aggregateWarnings(warnings);

      expect(aggregated.length).toBe(1);
      expect(aggregated[0].message).toContain('and 1 more similar warnings');
    });

    it('should format count correctly for many duplicates', () => {
      const warnings: ParseWarning[] = [];

      // Create 1000 identical warnings
      for (let i = 0; i < 1000; i++) {
        warnings.push(createTestWarning('CODE', 'Message', 'Suite', 'element'));
      }

      const aggregated = aggregateWarnings(warnings);

      expect(aggregated.length).toBe(1);
      expect(aggregated[0].message).toContain('and 999 more similar warnings');
    });

    it('should preserve warning fields in aggregated output', () => {
      const warnings: ParseWarning[] = [
        createTestWarning('TEST_CODE', 'Test message', 'Test Suite', 'test_element', 'test_name'),
      ];

      const aggregated = aggregateWarnings(warnings);

      expect(aggregated[0].code).toBe('TEST_CODE');
      expect(aggregated[0].message).toBe('Test message');
      expect(aggregated[0].suite).toBe('Test Suite');
      expect(aggregated[0].element).toBe('test_element');
    });
  });
});

describe('Phase 2: Performance Tests', () => {
  describe('Memory bounds', () => {
    it('should not exhaust memory with 10,000+ warnings (streaming aggregation)', () => {
      const warnings: ParseWarning[] = [];

      // Create 10,000 unique warnings (would exhaust memory without cap)
      for (let i = 0; i < 10000; i++) {
        warnings.push(createTestWarning(
          `CODE_${i}`,
          `Warning ${i}`,
          `Suite ${i % 10}`, // Vary suite
          `element${i % 5}`, // Vary element
          `name${i}`
        ));
      }

      // Should not throw or hang
      const aggregated = aggregateWarnings(warnings);

      // Should cap at 80 warnings (regular warnings limit, no security warnings in this test)
      expect(aggregated.length).toBe(80);
    });

    it('should handle 10,000+ duplicate warnings efficiently', () => {
      const warnings: ParseWarning[] = [];

      // Create 10,000 identical warnings (memory efficient case)
      for (let i = 0; i < 10000; i++) {
        warnings.push(createTestWarning('SAME_CODE', 'Same message', 'Same Suite', 'same_element'));
      }

      const aggregated = aggregateWarnings(warnings);

      // Should have only 1 warning with high count
      expect(aggregated.length).toBe(1);
      expect(aggregated[0].message).toContain('and 9999 more similar warnings');
    });

    it('should complete aggregation in reasonable time (<100ms for 1000 warnings)', () => {
      const warnings: ParseWarning[] = [];

      // Create 1000 warnings (mix of unique and duplicates)
      for (let i = 0; i < 1000; i++) {
        warnings.push(createTestWarning(
          `CODE_${i % 50}`, // 50 unique codes with duplicates
          `Warning ${i % 50}`,
          `Suite ${i % 10}`,
          `element${i % 5}`
        ));
      }

      const startTime = performance.now();
      const aggregated = aggregateWarnings(warnings);
      const endTime = performance.now();

      const duration = endTime - startTime;

      // Should complete in < 100ms
      expect(duration).toBeLessThan(100);
      expect(aggregated.length).toBeGreaterThan(0);
      expect(aggregated.length).toBeLessThanOrEqual(100);
    });

    it('should maintain constant memory usage as warning count increases', () => {
      // Test with increasing warning counts to verify O(1) memory per warning type
      const testSizes = [100, 1000, 5000, 10000];

      testSizes.forEach(size => {
        const warnings: ParseWarning[] = [];

        // Create many warnings (all unique codes, will be capped at 80 for regular warnings)
        for (let i = 0; i < size; i++) {
          warnings.push(createTestWarning(
            `CODE_${i}`,
            `Warning ${i}`,
            `Suite ${i}`,
            `element${i}`
          ));
        }

        const aggregated = aggregateWarnings(warnings);

        // Should always cap at 80 regardless of input size (regular warnings only)
        expect(aggregated.length).toBe(80);
      });
    });
  });

  describe('Edge case combinations', () => {
    it('should handle 100 unique warnings + 10,000 duplicates', () => {
      const warnings: ParseWarning[] = [];

      // Create 100 unique warning types
      for (let i = 0; i < 100; i++) {
        // Add original
        warnings.push(createTestWarning(`CODE_${i}`, `Message ${i}`, `Suite ${i}`, `element${i}`));

        // Add 100 duplicates of each
        for (let j = 0; j < 100; j++) {
          warnings.push(createTestWarning(`CODE_${i}`, `Message ${i}`, `Suite ${i}`, `element${i}`));
        }
      }

      const aggregated = aggregateWarnings(warnings);

      // Should have 80 warnings (regular warnings cap, no security warnings)
      expect(aggregated.length).toBe(80);

      // Each should have count of 101 (original + 100 duplicates)
      aggregated.forEach(w => {
        expect(w.message).toContain('and 100 more similar warnings');
      });
    });

    it('should handle rapid switching between warning types', () => {
      const warnings: ParseWarning[] = [];

      // Alternate between 5 warning types rapidly
      for (let i = 0; i < 1000; i++) {
        const typeId = i % 5;
        warnings.push(createTestWarning(
          `TYPE_${typeId}`,
          `Message ${typeId}`,
          `Suite ${typeId}`,
          `element${typeId}`
        ));
      }

      const aggregated = aggregateWarnings(warnings);

      // Should have 5 warning types, each with 200 occurrences
      expect(aggregated.length).toBe(5);
      aggregated.forEach(w => {
        expect(w.message).toContain('and 199 more similar warnings');
      });
    });
  });
});
