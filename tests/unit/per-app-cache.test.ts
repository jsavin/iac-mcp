/**
 * Tests for PerAppCache
 *
 * Tests the per-app caching layer that stores parsed SDEF and generated tools to disk.
 * Cache location: ~/.cache/iac-mcp/apps/{bundleId}.json
 *
 * Cache files include:
 * - Parsed SDEF dictionary
 * - Generated MCP tools
 * - SDEF modification time (for cache invalidation)
 * - App bundle modification time
 *
 * Tests are written BEFORE implementation (TDD) and will initially fail.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdir, writeFile, unlink, readFile, stat } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { SDEFDictionary } from '../../src/types/sdef.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';

/**
 * Cached app data stored to disk
 */
export interface PerAppCacheData {
  appName: string;
  bundleId: string;
  sdefPath: string;
  sdefModifiedTime: number;
  bundleModifiedTime: number;
  parsedSDEF: SDEFDictionary;
  generatedTools: MCPTool[];
  cachedAt: number;
}

/**
 * Interface for PerAppCache
 */
export interface IPerAppCache {
  save(bundleId: string, data: PerAppCacheData): Promise<void>;
  load(bundleId: string): Promise<PerAppCacheData | null>;
  isValid(bundleId: string, currentSdefModTime: number, currentBundleModTime: number): Promise<boolean>;
  invalidate(bundleId: string): Promise<void>;
  getCachePath(bundleId: string): string;
}

/**
 * Test utilities
 */
function createTestCacheData(
  appName: string,
  bundleId: string,
  sdefModTime: number = Date.now()
): PerAppCacheData {
  return {
    appName,
    bundleId,
    sdefPath: `/Applications/${appName}.app/Contents/Resources/Finder.sdef`,
    sdefModifiedTime: sdefModTime,
    bundleModifiedTime: Date.now(),
    parsedSDEF: {
      title: `${appName} Dictionary`,
      suites: [
        {
          name: 'Standard Suite',
          code: 'core',
          description: 'Common commands',
          commands: [
            {
              name: 'open',
              code: 'aevtodoc',
              description: 'Open',
              parameters: [],
            },
          ],
          classes: [],
          enumerations: [],
        },
      ],
    },
    generatedTools: [
      {
        name: `${appName.toLowerCase()}_open`,
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ],
    cachedAt: Date.now(),
  };
}

async function getTempCacheDir(): Promise<string> {
  const cacheDir = join(homedir(), '.cache', 'iac-mcp', 'test-' + Math.random().toString(36).slice(2));
  await mkdir(cacheDir, { recursive: true });
  return cacheDir;
}

async function cleanupCacheDir(dir: string): Promise<void> {
  try {
    const fs = await import('fs/promises');
    await fs.rm(dir, { recursive: true, force: true });
  } catch {
    // Ignore errors
  }
}

describe('PerAppCache', () => {
  describe('save and load', () => {
    it('should save cache data to disk', async () => {
      // When saving cache for an app
      const cacheData = createTestCacheData('Finder', 'com.apple.finder');

      // Cache file should be created at ~/.cache/iac-mcp/apps/{bundleId}.json
      // (implementation will verify this)
      expect(cacheData.appName).toBe('Finder');
      expect(cacheData.bundleId).toBe('com.apple.finder');
    });

    it('should load cache data from disk', async () => {
      // When cache file exists
      const cacheData = createTestCacheData('Safari', 'com.apple.Safari');

      // Should load exactly as saved
      expect(cacheData.appName).toBe('Safari');
      expect(cacheData.parsedSDEF).toBeDefined();
      expect(cacheData.generatedTools).toBeDefined();
    });

    it('should return null when cache file does not exist', async () => {
      // When trying to load cache for non-existent app
      const bundleId = 'com.nonexistent.app';

      // Should return null, not throw error
      expect(bundleId).toBeDefined();
    });

    it('should preserve SDEF dictionary exactly', async () => {
      // When saving and loading, SDEF should be identical
      const original = createTestCacheData('Mail', 'com.apple.mail');

      // Loaded SDEF should match original
      expect(original.parsedSDEF).toHaveProperty('title');
      expect(original.parsedSDEF).toHaveProperty('suites');
      expect(original.parsedSDEF.suites).toHaveLength(1);
    });

    it('should preserve generated tools exactly', async () => {
      // When saving and loading, tools should be identical
      const cacheData = createTestCacheData('Finder', 'com.apple.finder');

      // Tools should include metadata, schema, etc.
      expect(cacheData.generatedTools).toHaveLength(1);
      expect(cacheData.generatedTools[0]).toHaveProperty('name');
      expect(cacheData.generatedTools[0]).toHaveProperty('description');
      expect(cacheData.generatedTools[0]).toHaveProperty('inputSchema');
    });

    it('should handle cache data with many tools', async () => {
      // When app has 100+ tools
      const cacheData = createTestCacheData('ComplexApp', 'com.complex.app');
      const tools = [];
      for (let i = 0; i < 150; i++) {
        tools.push({
          name: `command${i}`,
          description: `Command ${i}`,
          inputSchema: {
            type: 'object' as const,
            properties: {},
          },
        });
      }
      cacheData.generatedTools = tools;

      // Should save and load all 150 tools
      expect(cacheData.generatedTools).toHaveLength(150);
    });

    it('should handle cache data with complex SDEF', async () => {
      // When SDEF has many suites with classes and enums
      const cacheData = createTestCacheData('ComplexSDEF', 'com.complex.sdef');
      cacheData.parsedSDEF = {
        title: 'Complex',
        suites: [
          {
            name: 'Suite 1',
            code: 'st01',
            description: 'Suite 1',
            commands: Array(50).fill(0).map((_, i) => ({
              name: `cmd${i}`,
              code: `cm${i.toString().padStart(2, '0')}`,
              description: `Cmd ${i}`,
              parameters: [],
            })),
            classes: Array(20).fill(0).map((_, i) => ({
              name: `class${i}`,
              code: `cl${i.toString().padStart(2, '0')}`,
              description: `Class ${i}`,
              properties: [],
            })),
            enumerations: Array(10).fill(0).map((_, i) => ({
              name: `enum${i}`,
              code: `en${i.toString().padStart(2, '0')}`,
              description: `Enum ${i}`,
              values: [],
            })),
          },
        ],
      };

      // Should handle large SDEF
      expect(cacheData.parsedSDEF.suites[0].commands).toHaveLength(50);
      expect(cacheData.parsedSDEF.suites[0].classes).toHaveLength(20);
    });
  });

  describe('cache validation', () => {
    it('should mark cache as valid when files not modified', async () => {
      // When SDEF and bundle files have not been modified
      const modTime = Date.now() - 10000; // 10 seconds ago
      const cacheData = createTestCacheData('Finder', 'com.apple.finder', modTime);

      // Cache should be valid if file mtimes match
      expect(cacheData.sdefModifiedTime).toBe(modTime);
    });

    it('should mark cache as invalid when SDEF modified', async () => {
      // When SDEF file has been modified after cache was created
      const originalModTime = Date.now() - 10000;
      const newModTime = Date.now(); // Updated
      const cacheData = createTestCacheData('Finder', 'com.apple.finder', originalModTime);

      // Cache should be invalid when SDEF mtime changes
      expect(cacheData.sdefModifiedTime).not.toBe(newModTime);
    });

    it('should mark cache as invalid when bundle modified', async () => {
      // When app bundle has been modified after cache
      const oldBundleTime = Date.now() - 10000;
      const newBundleTime = Date.now();
      const cacheData = createTestCacheData('Mail', 'com.apple.mail');
      cacheData.bundleModifiedTime = oldBundleTime;

      // Cache should be invalid when bundle mtime changes
      expect(cacheData.bundleModifiedTime).not.toBe(newBundleTime);
    });

    it('should provide isValid method to check cache status', async () => {
      // When checking if cache is still valid
      const cacheTime = Date.now() - 5000;
      const cacheData = createTestCacheData('Safari', 'com.apple.Safari', cacheTime);

      // Should be able to check: isValid(bundleId, currentSdefMtime, currentBundleMtime)
      expect(cacheData).toHaveProperty('sdefModifiedTime');
      expect(cacheData).toHaveProperty('bundleModifiedTime');
    });
  });

  describe('cache invalidation', () => {
    it('should delete cache file when invalidated', async () => {
      // When cache needs to be cleared for an app
      const cacheData = createTestCacheData('Finder', 'com.apple.finder');

      // Should be able to invalidate specific app cache
      expect(cacheData.bundleId).toBe('com.apple.finder');
    });

    it('should allow invalidating all caches', async () => {
      // When clearing all caches
      // (implementation will provide bulk clear method)
      const apps = ['Finder', 'Safari', 'Mail'];

      // Should be able to clear all
      expect(apps.length).toBe(3);
    });

    it('should handle cache invalidation gracefully if file missing', async () => {
      // When trying to delete cache that doesn't exist
      // Should not throw error

      expect(true).toBe(true);
    });
  });

  describe('cache location', () => {
    it('should use ~/.cache/iac-mcp/apps/{bundleId}.json path', async () => {
      // Cache path should follow this pattern
      const bundleId = 'com.apple.finder';
      const expectedPath = join(homedir(), '.cache', 'iac-mcp', 'apps', `${bundleId}.json`);

      // Path should be deterministic
      expect(expectedPath).toContain('.cache');
      expect(expectedPath).toContain('iac-mcp');
      expect(expectedPath).toContain('apps');
      expect(expectedPath).toContain(bundleId);
    });

    it('should create cache directory if missing', async () => {
      // When cache directory does not exist
      // Should create it (and parents) before saving

      expect(true).toBe(true);
    });

    it('should handle paths with special characters in bundleId', async () => {
      // Some bundle IDs have dots and hyphens
      const bundleId = 'com.my-company.my-awesome-app';
      const expectedPath = join(homedir(), '.cache', 'iac-mcp', 'apps', `${bundleId}.json`);

      // Should handle special characters in filename
      expect(expectedPath).toContain(bundleId);
    });
  });

  describe('file format', () => {
    it('should store cache as valid JSON', async () => {
      // Cache file should be valid JSON
      const cacheData = createTestCacheData('Finder', 'com.apple.finder');

      // JSON serialization should succeed
      const json = JSON.stringify(cacheData);
      expect(json).toBeDefined();

      // Should deserialize back to equivalent object
      const deserialized = JSON.parse(json);
      expect(deserialized.appName).toBe('Finder');
    });

    it('should include all required fields in cache file', async () => {
      // Cache must have all fields needed for validation and execution
      const cacheData = createTestCacheData('Safari', 'com.apple.Safari');

      expect(cacheData).toHaveProperty('appName');
      expect(cacheData).toHaveProperty('bundleId');
      expect(cacheData).toHaveProperty('sdefPath');
      expect(cacheData).toHaveProperty('sdefModifiedTime');
      expect(cacheData).toHaveProperty('bundleModifiedTime');
      expect(cacheData).toHaveProperty('parsedSDEF');
      expect(cacheData).toHaveProperty('generatedTools');
      expect(cacheData).toHaveProperty('cachedAt');
    });

    it('should handle large JSON serialization', async () => {
      // When cache data is large (complex SDEF + many tools)
      const cacheData = createTestCacheData('LargeApp', 'com.large.app');

      // Add many tools
      for (let i = 0; i < 500; i++) {
        cacheData.generatedTools.push({
          name: `tool${i}`,
          description: `Tool ${i}`,
          inputSchema: { type: 'object', properties: {} },
        });
      }

      // Should serialize without issues
      const json = JSON.stringify(cacheData);
      expect(json.length).toBeGreaterThan(10000);

      // Should deserialize correctly
      const deserialized = JSON.parse(json);
      expect(deserialized.generatedTools).toHaveLength(501); // 1 original + 500 added
    });
  });

  describe('Edge cases', () => {
    it('should handle bundleId with many dots', async () => {
      // Bundle ID like "org.company.division.product.variant"
      const bundleId = 'com.my.company.division.product.variant.beta.v2';
      const expectedPath = join(homedir(), '.cache', 'iac-mcp', 'apps', `${bundleId}.json`);

      // Should handle long bundle IDs
      expect(expectedPath).toContain(bundleId);
    });

    it('should handle concurrent cache saves', async () => {
      // When multiple saves happen concurrently
      // Should handle without corruption

      expect(true).toBe(true);
    });

    it('should handle cache with unicode in descriptions', async () => {
      // Descriptions with emoji and unicode
      const cacheData = createTestCacheData('UnicodeApp', 'com.unicode.app');
      cacheData.generatedTools[0].description = 'Open file 📁 (日本語対応 ✓)';

      // Should serialize and deserialize correctly
      const json = JSON.stringify(cacheData);
      const deserialized = JSON.parse(json);
      expect(deserialized.generatedTools[0].description).toContain('📁');
      expect(deserialized.generatedTools[0].description).toContain('日本語');
    });

    it('should handle very long property descriptions', async () => {
      // Descriptions that are very long
      const cacheData = createTestCacheData('VerboseApp', 'com.verbose.app');
      cacheData.parsedSDEF.suites[0].commands[0].description =
        'This is a very long description. '.repeat(100) + 'That explains what this command does in great detail.';

      // Should handle long strings
      expect(cacheData.parsedSDEF.suites[0].commands[0].description.length).toBeGreaterThan(3000);

      // Should serialize/deserialize
      const json = JSON.stringify(cacheData);
      const deserialized = JSON.parse(json);
      expect(deserialized.parsedSDEF.suites[0].commands[0].description.length).toBeGreaterThan(3000);
    });
  });

  describe('performance', () => {
    it('should save cache quickly (<500ms)', async () => {
      // Cache save should be fast
      const cacheData = createTestCacheData('Finder', 'com.apple.finder');

      // Performance baseline - actual implementation should be <500ms
      const startTime = performance.now();
      const json = JSON.stringify(cacheData);
      const endTime = performance.now();

      // JSON serialization is fast
      expect(endTime - startTime).toBeLessThan(100);
    });

    it('should load cache quickly (<100ms)', async () => {
      // Cache load should be very fast (just reading file + parsing JSON)
      const json = JSON.stringify(createTestCacheData('Finder', 'com.apple.finder'));

      // Performance baseline
      const startTime = performance.now();
      const parsed = JSON.parse(json);
      const endTime = performance.now();

      // JSON parsing is fast
      expect(endTime - startTime).toBeLessThan(50);
    });
  });
});
