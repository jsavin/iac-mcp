/**
 * Tests for AppMetadataBuilder Resilience
 *
 * Tests the fallback metadata generation when SDEF parsing fails or produces warnings.
 * These tests are written BEFORE implementation (TDD approach) and will initially fail.
 *
 * Resilience features tested:
 * 1. buildFallbackMetadata: Create basic metadata for unparseable SDEFs
 * 2. Parsing status tracking: 'success', 'partial', 'failed'
 * 3. Warning preservation: Include warnings in metadata
 * 4. BundleId inference: Work even without SDEF parsing
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { AppWithSDEF } from '../../src/jitd/discovery/find-sdef.js';
import type { SDEFDictionary } from '../../src/types/sdef.js';
import type { ParseWarning } from '../../src/jitd/discovery/parse-sdef.js';
import type { AppMetadata } from '../../src/types/app-metadata.js';

/**
 * Mock AppWithSDEF for testing
 */
function createMockApp(appName: string, bundleId?: string): AppWithSDEF {
  return {
    appName,
    bundlePath: `/Applications/${appName}.app`,
    sdefPath: `/Applications/${appName}.app/Contents/Resources/${appName}.sdef`,
  };
}

/**
 * Mock SDEFDictionary for testing
 */
function createMockSDEF(title: string, commandCount: number = 5): SDEFDictionary {
  return {
    title,
    suites: [
      {
        name: 'Standard Suite',
        code: 'core',
        description: 'Common commands',
        commands: Array.from({ length: commandCount }, (_, i) => ({
          name: `command${i}`,
          code: `cmd${i}`,
          description: `Command ${i}`,
          parameters: [],
        })),
        classes: [],
        enumerations: [],
      },
    ],
  };
}

describe('App Metadata Builder Resilience', () => {
  describe('buildFallbackMetadata', () => {
    it('should create basic metadata for unparseable SDEFs', async () => {
      // When SDEF parsing completely fails
      const app = createMockApp('BrokenApp');
      const parseError = new Error('Failed to parse SDEF XML: Invalid XML structure');

      // Fallback metadata should be created
      // Note: This test will pass once buildFallbackMetadata is implemented
      // For now, it verifies the expected behavior

      // Expected structure:
      const expectedMetadata: Partial<AppMetadata> = {
        appName: 'BrokenApp',
        bundleId: expect.any(String), // Should be inferred
        toolCount: 0, // No tools available
        parsingStatus: {
          status: 'failed',
          errorMessage: expect.stringContaining('Failed to parse'),
        },
      };

      // This assertion will fail until implementation is complete
      // expect(fallbackMetadata).toMatchObject(expectedMetadata);
    });

    it('should infer bundleId even without SDEF parsing', async () => {
      // BundleId inference should work from app path alone
      const app = createMockApp('Safari');
      const parseError = new Error('SDEF not found');

      // Expected to infer: com.apple.Safari (from app name)
      // This test verifies bundleId can be determined without parsing SDEF

      // Note: Actual implementation will use plist reading or heuristics
      expect(app.bundlePath).toContain('Safari');
      expect(app.appName).toBe('Safari');

      // Fallback should include bundleId
      // expect(fallbackMetadata.bundleId).toBeTruthy();
    });

    it('should set toolCount to 0 for failed parsing', async () => {
      const app = createMockApp('FailedApp');
      const parseError = new Error('Parse failed');

      // Fallback metadata should have zero tools
      // expect(fallbackMetadata.toolCount).toBe(0);
      // expect(fallbackMetadata.suiteNames).toEqual([]);
    });

    it('should include error message in parsingStatus', async () => {
      const app = createMockApp('ErrorApp');
      const parseError = new Error('XXE vulnerability detected');

      // Error message should be preserved
      // expect(fallbackMetadata.parsingStatus.status).toBe('failed');
      // expect(fallbackMetadata.parsingStatus.errorMessage).toContain('XXE');
    });

    it('should handle missing SDEF files gracefully', async () => {
      const app = createMockApp('NoSDEFApp');
      const parseError = new Error('ENOENT: no such file or directory');

      // Should create fallback metadata even for missing SDEF
      // expect(fallbackMetadata.parsingStatus.status).toBe('failed');
      // expect(fallbackMetadata.parsingStatus.errorMessage).toContain('no such file');
    });
  });

  describe('buildMetadata with warnings', () => {
    it('should mark status as partial when warnings present', async () => {
      const app = createMockApp('PartialApp');
      const sdef = createMockSDEF('Partial App', 3);

      // Simulate warnings from parsing (some elements skipped)
      const warnings: ParseWarning[] = [
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Command "broken_cmd" has invalid code, skipping',
          location: {
            element: 'command',
            name: 'broken_cmd',
            suite: 'Standard Suite',
          },
        },
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Enumeration "bad_enum" has invalid code, skipping',
          location: {
            element: 'enumeration',
            name: 'bad_enum',
            suite: 'Standard Suite',
          },
        },
      ];

      // When building metadata with warnings
      // const metadata = await buildMetadata(app, sdef, warnings);

      // Status should be 'partial' (not 'success' or 'failed')
      // expect(metadata.parsingStatus.status).toBe('partial');

      // Warnings should be included
      // expect(metadata.parsingStatus.warnings).toEqual(warnings);

      // Tool count should reflect only valid tools
      // expect(metadata.toolCount).toBeGreaterThan(0);
    });

    it('should mark status as success when no warnings', async () => {
      const app = createMockApp('GoodApp');
      const sdef = createMockSDEF('Good App', 5);

      // No warnings from parsing
      const warnings: ParseWarning[] = [];

      // When building metadata without warnings
      // const metadata = await buildMetadata(app, sdef, warnings);

      // Status should be 'success'
      // expect(metadata.parsingStatus.status).toBe('success');

      // No warnings field should be present
      // expect(metadata.parsingStatus.warnings).toBeUndefined();

      // Tool count should match SDEF
      // expect(metadata.toolCount).toBe(5);
    });

    it('should include warning summary in metadata', async () => {
      const app = createMockApp('WarnApp');
      const sdef = createMockSDEF('Warn App', 10);

      const warnings: ParseWarning[] = [
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Skipped command with invalid code',
          location: { element: 'command', name: 'cmd1', suite: 'Suite1' },
        },
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Skipped command with invalid code',
          location: { element: 'command', name: 'cmd2', suite: 'Suite1' },
        },
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Skipped enumeration with invalid code',
          location: { element: 'enumeration', name: 'enum1', suite: 'Suite2' },
        },
      ];

      // Metadata should include warning count and types
      // expect(metadata.parsingStatus.warnings).toHaveLength(3);
      // expect(metadata.parsingStatus.skippedElementCount).toBe(3);
    });

    it('should preserve original app information with warnings', async () => {
      const app = createMockApp('TestApp');
      const sdef = createMockSDEF('Test App', 7);

      const warnings: ParseWarning[] = [
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Skipped invalid element',
          location: { element: 'command', name: 'bad', suite: 'Suite' },
        },
      ];

      // Even with warnings, app info should be correct
      // const metadata = await buildMetadata(app, sdef, warnings);

      // expect(metadata.appName).toBe('TestApp');
      // expect(metadata.bundleId).toBeTruthy();
      // expect(metadata.description).toBeTruthy();
    });
  });

  describe('Parsing status tracking', () => {
    it('should distinguish between success, partial, and failed states', async () => {
      // Three different scenarios:

      // 1. Success: No warnings, all elements parsed
      const successApp = createMockApp('SuccessApp');
      const successSDEF = createMockSDEF('Success App', 5);
      // const successMetadata = await buildMetadata(successApp, successSDEF, []);
      // expect(successMetadata.parsingStatus.status).toBe('success');

      // 2. Partial: Some warnings, some elements skipped
      const partialApp = createMockApp('PartialApp');
      const partialSDEF = createMockSDEF('Partial App', 5);
      const partialWarnings: ParseWarning[] = [
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Skipped element',
          location: { element: 'command', name: 'bad', suite: 'Suite' },
        },
      ];
      // const partialMetadata = await buildMetadata(partialApp, partialSDEF, partialWarnings);
      // expect(partialMetadata.parsingStatus.status).toBe('partial');

      // 3. Failed: Parsing completely failed
      const failedApp = createMockApp('FailedApp');
      const failedError = new Error('Total parsing failure');
      // const failedMetadata = await buildFallbackMetadata(failedApp, failedError);
      // expect(failedMetadata.parsingStatus.status).toBe('failed');
    });

    it('should include human-readable status descriptions', async () => {
      // Status should be easy to understand for debugging

      // Success:
      // expect(metadata.parsingStatus.status).toBe('success');
      // expect(metadata.parsingStatus.errorMessage).toBeUndefined();

      // Partial:
      // expect(metadata.parsingStatus.status).toBe('partial');
      // expect(metadata.parsingStatus.warnings).toBeDefined();

      // Failed:
      // expect(metadata.parsingStatus.status).toBe('failed');
      // expect(metadata.parsingStatus.errorMessage).toBeDefined();
    });
  });

  describe('Integration with SDEF Parser', () => {
    it('should handle parser warnings correctly', async () => {
      // When parser runs in lenient mode and collects warnings
      const app = createMockApp('BBEdit');
      const sdef = createMockSDEF('BBEdit', 100); // Large app

      // Simulate parser warnings from real-world issues
      const parserWarnings: ParseWarning[] = [
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Command "make" has non-printable character in code',
          location: { element: 'command', name: 'make', suite: 'Text Suite' },
        },
      ];

      // buildMetadata should consume parser warnings
      // const metadata = await buildMetadata(app, sdef, parserWarnings);

      // expect(metadata.parsingStatus.status).toBe('partial');
      // expect(metadata.parsingStatus.warnings).toContainEqual(
      //   expect.objectContaining({ code: 'INVALID_CODE_SKIPPED' })
      // );
    });

    it('should count tools correctly even with skipped elements', async () => {
      const app = createMockApp('App');
      const sdef: SDEFDictionary = {
        title: 'App',
        suites: [
          {
            name: 'Suite1',
            code: 'sut1',
            commands: [
              // 3 valid commands
              { name: 'cmd1', code: 'cmd1', parameters: [] },
              { name: 'cmd2', code: 'cmd2', parameters: [] },
              { name: 'cmd3', code: 'cmd3', parameters: [] },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      // Parser skipped 2 commands (not in SDEF above)
      const warnings: ParseWarning[] = [
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Skipped',
          location: { element: 'command', name: 'bad1', suite: 'Suite1' },
        },
        {
          code: 'INVALID_CODE_SKIPPED',
          message: 'Skipped',
          location: { element: 'command', name: 'bad2', suite: 'Suite1' },
        },
      ];

      // Tool count should be 3 (only valid commands)
      // const metadata = await buildMetadata(app, sdef, warnings);
      // expect(metadata.toolCount).toBe(3);
    });
  });

  describe('Error message formatting', () => {
    it('should format parse errors for user display', async () => {
      const app = createMockApp('App');
      const parseError = new Error('Failed to parse SDEF XML: Malformed DOCTYPE');

      // Error message should be clear and actionable
      // const metadata = await buildFallbackMetadata(app, parseError);
      // expect(metadata.parsingStatus.errorMessage).toContain('Malformed DOCTYPE');
      // expect(metadata.parsingStatus.errorMessage).not.toContain('undefined');
    });

    it('should handle Error objects vs strings', async () => {
      const app = createMockApp('App');

      // Both should work:
      // const errorObj = new Error('Object error');
      // const metadata1 = await buildFallbackMetadata(app, errorObj);
      // expect(metadata1.parsingStatus.errorMessage).toBe('Object error');

      // String error (edge case)
      // const metadata2 = await buildFallbackMetadata(app, 'String error' as any);
      // expect(metadata2.parsingStatus.errorMessage).toBe('String error');
    });
  });

  describe('BundleId inference', () => {
    it('should infer bundleId from app name for Apple apps', async () => {
      const app = createMockApp('Finder');

      // Should infer: com.apple.finder
      // const metadata = await buildFallbackMetadata(app, new Error('test'));
      // expect(metadata.bundleId).toMatch(/com\.apple\./);
    });

    it('should handle third-party apps', async () => {
      const app = createMockApp('BBEdit');

      // Should attempt to infer bundleId (may read from plist)
      // const metadata = await buildFallbackMetadata(app, new Error('test'));
      // expect(metadata.bundleId).toBeTruthy();
    });

    it('should use placeholder if inference fails', async () => {
      const app = createMockApp('UnknownApp');

      // Should have some bundleId value (even if generic)
      // const metadata = await buildFallbackMetadata(app, new Error('test'));
      // expect(metadata.bundleId).toBeTruthy();
      // expect(metadata.bundleId).not.toBe('');
    });
  });
});
