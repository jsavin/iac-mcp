/**
 * Tests for ToolCache class
 *
 * These tests validate the caching system that stores parsed SDEF data
 * and generated MCP tools to speed up startup times.
 *
 * Tests are written BEFORE implementation (TDD) and will initially fail.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, writeFile, unlink, stat, readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import type { SDEFDictionary } from '../../src/types/sdef.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';

// Import the ToolCache class (to be implemented)
// This will fail until implementation exists
import { ToolCache, CachedAppData, CacheManifest, CACHE_VERSION } from '../../src/jitd/cache/tool-cache.js';

/**
 * Test fixtures and utilities
 */

// Create sample SDEF dictionary for testing
function createSampleSDEF(appName: string): SDEFDictionary {
  return {
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
            description: 'Open a file',
            parameters: [],
          },
        ],
        classes: [],
        enumerations: [],
      },
    ],
  };
}

// Create sample MCP tool for testing
function createSampleTool(appName: string, commandName: string): MCPTool {
  return {
    name: `${appName.toLowerCase()}_${commandName}`,
    description: `${commandName} command for ${appName}`,
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'Target for the command',
        },
      },
      required: ['target'],
    },
    _metadata: {
      appName,
      bundleId: `com.apple.${appName.toLowerCase()}`,
      commandName,
      commandCode: 'aevtodoc',
      suiteName: 'Standard Suite',
      resultType: { kind: 'primitive', type: 'boolean' },
    },
  };
}

// Create sample cached app data
function createSampleCachedApp(
  appName: string,
  bundlePath: string,
  sdefPath: string,
  modifiedTime: number = Date.now()
): CachedAppData {
  return {
    appName,
    bundlePath,
    bundleId: `com.apple.${appName.toLowerCase()}`,
    sdefPath,
    sdefModifiedTime: modifiedTime,
    bundleModifiedTime: modifiedTime,
    parsedSDEF: createSampleSDEF(appName),
    generatedTools: [
      createSampleTool(appName, 'open'),
      createSampleTool(appName, 'close'),
    ],
    cachedAt: Date.now(),
  };
}

// Create a temporary test directory
async function createTestDir(): Promise<string> {
  const testDir = join(tmpdir(), `iac-mcp-test-${Date.now()}`);
  await mkdir(testDir, { recursive: true });
  return testDir;
}

// Create a temporary test file with given modification time
async function createTestFile(
  filePath: string,
  content: string = 'test',
  modifiedTime?: number
): Promise<void> {
  // Check if path already exists as a directory (e.g., .app bundles)
  if (existsSync(filePath)) {
    const stats = await stat(filePath);
    if (stats.isDirectory()) {
      // Just set the modification time on the directory
      if (modifiedTime) {
        const fs = await import('fs');
        const date = new Date(modifiedTime);
        fs.utimesSync(filePath, date, date);
      }
      return;
    }
  }

  // Create a new file with content
  await writeFile(filePath, content);
  if (modifiedTime) {
    // Note: We'll use utimes to set modification time
    const fs = await import('fs');
    const date = new Date(modifiedTime);
    fs.utimesSync(filePath, date, date);
  }
}

// Cleanup test directory
async function cleanupTestDir(testDir: string): Promise<void> {
  try {
    const fs = await import('fs');
    if (existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  } catch (error) {
    // Ignore cleanup errors
  }
}

/**
 * Test Suite: ToolCache
 */
describe('ToolCache', () => {
  let testCacheDir: string;
  let cache: ToolCache;

  beforeEach(async () => {
    // Create fresh test directory for each test
    testCacheDir = await createTestDir();
    cache = new ToolCache(testCacheDir);
  });

  afterEach(async () => {
    // Cleanup test directory after each test
    await cleanupTestDir(testCacheDir);
  });

  /**
   * Test Group: Cache Loading
   */
  describe('load() - Cache Loading Tests', () => {
    it('should load valid cache manifest from disk', async () => {
      // Arrange: Create a valid cache file
      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Finder',
            '/System/Library/CoreServices/Finder.app',
            '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef'
          ),
        ],
      };

      const cacheFile = join(testCacheDir, 'tool-cache.json');
      await writeFile(cacheFile, JSON.stringify(manifest, null, 2));

      // Act: Load cache
      const loaded = await cache.load();

      // Assert: Cache loaded successfully
      expect(loaded).not.toBeNull();
      expect(loaded?.version).toBe(CACHE_VERSION);
      expect(loaded?.apps).toHaveLength(1);
      expect(loaded?.apps[0].appName).toBe('Finder');
      expect(loaded?.apps[0].generatedTools).toHaveLength(2);
    });

    it('should return null when cache file does not exist', async () => {
      // Act: Try to load non-existent cache
      const loaded = await cache.load();

      // Assert: Returns null
      expect(loaded).toBeNull();
    });

    it('should return null when cache version does not match (version mismatch)', async () => {
      // Arrange: Create cache with wrong version
      const manifest = {
        version: '0.0.0', // Wrong version
        cachedAt: Date.now(),
        apps: [],
      };

      const cacheFile = join(testCacheDir, 'tool-cache.json');
      await writeFile(cacheFile, JSON.stringify(manifest));

      // Act: Try to load cache with wrong version
      const loaded = await cache.load();

      // Assert: Returns null due to version mismatch
      expect(loaded).toBeNull();
    });

    it('should return null when cache is corrupted (invalid JSON)', async () => {
      // Arrange: Create corrupted cache file
      const cacheFile = join(testCacheDir, 'tool-cache.json');
      await writeFile(cacheFile, '{invalid json content}');

      // Act: Try to load corrupted cache
      const loaded = await cache.load();

      // Assert: Returns null
      expect(loaded).toBeNull();
    });

    it('should successfully parse and return cache manifest with multiple apps', async () => {
      // Arrange: Create cache with multiple apps
      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Finder',
            '/Applications/Finder.app',
            '/Applications/Finder.app/Contents/Resources/Finder.sdef'
          ),
          createSampleCachedApp(
            'Safari',
            '/Applications/Safari.app',
            '/Applications/Safari.app/Contents/Resources/Safari.sdef'
          ),
          createSampleCachedApp(
            'Mail',
            '/Applications/Mail.app',
            '/Applications/Mail.app/Contents/Resources/Mail.sdef'
          ),
        ],
      };

      const cacheFile = join(testCacheDir, 'tool-cache.json');
      await writeFile(cacheFile, JSON.stringify(manifest, null, 2));

      // Act: Load cache
      const loaded = await cache.load();

      // Assert: All apps loaded correctly
      expect(loaded).not.toBeNull();
      expect(loaded?.apps).toHaveLength(3);
      expect(loaded?.apps.map(a => a.appName)).toEqual(['Finder', 'Safari', 'Mail']);

      // Verify each app has tools
      for (const app of loaded!.apps) {
        expect(app.generatedTools.length).toBeGreaterThan(0);
        expect(app.parsedSDEF.title).toContain(app.appName);
      }
    });
  });

  /**
   * Test Group: Cache Saving
   */
  describe('save() - Cache Saving Tests', () => {
    it('should save cache manifest to disk', async () => {
      // Arrange: Create manifest to save
      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Finder',
            '/Applications/Finder.app',
            '/Applications/Finder.app/Contents/Resources/Finder.sdef'
          ),
        ],
      };

      // Act: Save cache
      await cache.save(manifest);

      // Assert: Cache file exists and contains correct data
      const cacheFile = join(testCacheDir, 'tool-cache.json');
      expect(existsSync(cacheFile)).toBe(true);

      const savedContent = await readFile(cacheFile, 'utf-8');
      const savedManifest = JSON.parse(savedContent);

      expect(savedManifest.version).toBe(CACHE_VERSION);
      expect(savedManifest.apps).toHaveLength(1);
      expect(savedManifest.apps[0].appName).toBe('Finder');
    });

    it('should create cache directory if it does not exist', async () => {
      // Arrange: Use non-existent nested directory
      const nestedCacheDir = join(testCacheDir, 'nested', 'cache', 'dir');
      const nestedCache = new ToolCache(nestedCacheDir);

      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [],
      };

      // Act: Save cache (should create directory)
      await nestedCache.save(manifest);

      // Assert: Directory and file created
      expect(existsSync(nestedCacheDir)).toBe(true);
      expect(existsSync(join(nestedCacheDir, 'tool-cache.json'))).toBe(true);
    });

    it('should overwrite existing cache file', async () => {
      // Arrange: Save initial cache
      const manifest1: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Finder',
            '/Applications/Finder.app',
            '/Applications/Finder.app/Contents/Resources/Finder.sdef'
          ),
        ],
      };
      await cache.save(manifest1);

      // Act: Save new cache (overwrite)
      const manifest2: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Safari',
            '/Applications/Safari.app',
            '/Applications/Safari.app/Contents/Resources/Safari.sdef'
          ),
          createSampleCachedApp(
            'Mail',
            '/Applications/Mail.app',
            '/Applications/Mail.app/Contents/Resources/Mail.sdef'
          ),
        ],
      };
      await cache.save(manifest2);

      // Assert: New cache replaces old cache
      const loaded = await cache.load();
      expect(loaded?.apps).toHaveLength(2);
      expect(loaded?.apps.map(a => a.appName)).toEqual(['Safari', 'Mail']);
    });

    it('should handle permission errors gracefully', async () => {
      // Arrange: Create cache in read-only directory (if possible)
      // Note: This test might be platform-specific
      const readonlyDir = join(testCacheDir, 'readonly');
      await mkdir(readonlyDir, { recursive: true });

      const fs = await import('fs');
      try {
        fs.chmodSync(readonlyDir, 0o444); // Read-only

        const readonlyCache = new ToolCache(readonlyDir);
        const manifest: CacheManifest = {
          version: CACHE_VERSION,
          cachedAt: Date.now(),
          apps: [],
        };

        // Act: Try to save (should not throw)
        await expect(readonlyCache.save(manifest)).resolves.not.toThrow();

        // Cleanup: Restore permissions
        fs.chmodSync(readonlyDir, 0o755);
      } catch (error) {
        // Skip test if we can't create read-only directory
        fs.chmodSync(readonlyDir, 0o755); // Restore for cleanup
      }
    });

    it('should verify saved cache can be reloaded', async () => {
      // Arrange: Create comprehensive manifest
      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Finder',
            '/Applications/Finder.app',
            '/Applications/Finder.app/Contents/Resources/Finder.sdef',
            1700000000000
          ),
          createSampleCachedApp(
            'Safari',
            '/Applications/Safari.app',
            '/Applications/Safari.app/Contents/Resources/Safari.sdef',
            1700000000000
          ),
        ],
      };

      // Act: Save and reload
      await cache.save(manifest);
      const reloaded = await cache.load();

      // Assert: Reloaded cache matches original
      expect(reloaded).not.toBeNull();
      expect(reloaded?.version).toBe(manifest.version);
      expect(reloaded?.apps).toHaveLength(manifest.apps.length);

      for (let i = 0; i < manifest.apps.length; i++) {
        expect(reloaded?.apps[i].appName).toBe(manifest.apps[i].appName);
        expect(reloaded?.apps[i].bundlePath).toBe(manifest.apps[i].bundlePath);
        expect(reloaded?.apps[i].sdefPath).toBe(manifest.apps[i].sdefPath);
        expect(reloaded?.apps[i].generatedTools).toHaveLength(
          manifest.apps[i].generatedTools.length
        );
      }
    });
  });

  /**
   * Test Group: Cache Validation
   */
  describe('isValid() - Cache Validation Tests', () => {
    let testBundlePath: string;
    let testSdefPath: string;
    let testModifiedTime: number;

    beforeEach(async () => {
      // Create test files with known modification times
      testBundlePath = join(testCacheDir, 'TestApp.app');
      testSdefPath = join(testCacheDir, 'TestApp.sdef');
      testModifiedTime = Date.now() - 10000; // 10 seconds ago

      await mkdir(testBundlePath, { recursive: true });
      await createTestFile(testBundlePath, 'bundle', testModifiedTime);
      await createTestFile(testSdefPath, 'sdef', testModifiedTime);
    });

    it('should return true for valid cache (unmodified app bundle)', async () => {
      // Arrange: Create cached app with correct modification times
      const stats = await stat(testBundlePath);
      const sdefStats = await stat(testSdefPath);

      const cached = createSampleCachedApp(
        'TestApp',
        testBundlePath,
        testSdefPath,
        testModifiedTime
      );
      cached.bundleModifiedTime = stats.mtimeMs;
      cached.sdefModifiedTime = sdefStats.mtimeMs;

      // Act: Validate cache
      const valid = await cache.isValid(cached);

      // Assert: Cache is valid
      expect(valid).toBe(true);
    });

    it('should return false when bundle modification time changed', async () => {
      // Arrange: Create cached app with old modification time
      const cached = createSampleCachedApp(
        'TestApp',
        testBundlePath,
        testSdefPath,
        testModifiedTime
      );

      // Act: Modify bundle after cache creation
      await new Promise(resolve => setTimeout(resolve, 10)); // Ensure time difference
      await createTestFile(testBundlePath, 'modified bundle', Date.now());

      const valid = await cache.isValid(cached);

      // Assert: Cache is invalid due to bundle modification
      expect(valid).toBe(false);
    });

    it('should return false when SDEF file modification time changed', async () => {
      // Arrange: Create cached app with correct bundle time
      const stats = await stat(testBundlePath);
      const cached = createSampleCachedApp(
        'TestApp',
        testBundlePath,
        testSdefPath,
        testModifiedTime
      );
      cached.bundleModifiedTime = stats.mtimeMs;

      // Act: Modify SDEF after cache creation
      await new Promise(resolve => setTimeout(resolve, 10)); // Ensure time difference
      await createTestFile(testSdefPath, 'modified sdef', Date.now());

      const valid = await cache.isValid(cached);

      // Assert: Cache is invalid due to SDEF modification
      expect(valid).toBe(false);
    });

    it('should return false when bundle path does not exist', async () => {
      // Arrange: Create cached app with non-existent bundle
      const cached = createSampleCachedApp(
        'NonExistentApp',
        '/Applications/NonExistentApp.app',
        testSdefPath,
        testModifiedTime
      );

      // Ensure SDEF exists but bundle doesn't
      const sdefStats = await stat(testSdefPath);
      cached.sdefModifiedTime = sdefStats.mtimeMs;

      // Act: Validate cache
      const valid = await cache.isValid(cached);

      // Assert: Cache is invalid due to missing bundle
      expect(valid).toBe(false);
    });

    it('should return false when SDEF path does not exist', async () => {
      // Arrange: Create cached app with non-existent SDEF
      const bundleStats = await stat(testBundlePath);
      const cached = createSampleCachedApp(
        'TestApp',
        testBundlePath,
        '/Applications/NonExistent.sdef',
        testModifiedTime
      );
      cached.bundleModifiedTime = bundleStats.mtimeMs;

      // Act: Validate cache
      const valid = await cache.isValid(cached);

      // Assert: Cache is invalid due to missing SDEF
      expect(valid).toBe(false);
    });

    it('should return true when both paths exist with same modification times', async () => {
      // Arrange: Create cached app with exact current modification times
      const bundleStats = await stat(testBundlePath);
      const sdefStats = await stat(testSdefPath);

      const cached = createSampleCachedApp(
        'TestApp',
        testBundlePath,
        testSdefPath,
        testModifiedTime
      );
      cached.bundleModifiedTime = bundleStats.mtimeMs;
      cached.sdefModifiedTime = sdefStats.mtimeMs;

      // Act: Validate cache
      const valid = await cache.isValid(cached);

      // Assert: Cache is valid
      expect(valid).toBe(true);
    });
  });

  /**
   * Test Group: Cache Invalidation
   */
  describe('invalidate() - Cache Invalidation Tests', () => {
    it('should delete cache file successfully', async () => {
      // Arrange: Create and save a cache
      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Finder',
            '/Applications/Finder.app',
            '/Applications/Finder.app/Contents/Resources/Finder.sdef'
          ),
        ],
      };
      await cache.save(manifest);

      const cacheFile = join(testCacheDir, 'tool-cache.json');
      expect(existsSync(cacheFile)).toBe(true);

      // Act: Invalidate cache
      await cache.invalidate();

      // Assert: Cache file deleted
      expect(existsSync(cacheFile)).toBe(false);
    });

    it('should handle gracefully when file does not exist', async () => {
      // Arrange: No cache file exists
      const cacheFile = join(testCacheDir, 'tool-cache.json');
      expect(existsSync(cacheFile)).toBe(false);

      // Act: Invalidate (should not throw)
      await expect(cache.invalidate()).resolves.not.toThrow();

      // Assert: Still no cache file
      expect(existsSync(cacheFile)).toBe(false);
    });

    it('should return null after invalidation when attempting to load', async () => {
      // Arrange: Create and save a cache
      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'Finder',
            '/Applications/Finder.app',
            '/Applications/Finder.app/Contents/Resources/Finder.sdef'
          ),
        ],
      };
      await cache.save(manifest);

      // Verify cache exists
      const loaded1 = await cache.load();
      expect(loaded1).not.toBeNull();

      // Act: Invalidate cache
      await cache.invalidate();

      // Assert: Loading returns null
      const loaded2 = await cache.load();
      expect(loaded2).toBeNull();
    });
  });

  /**
   * Test Group: Integration Tests
   */
  describe('Integration Tests - Full Cache Lifecycle', () => {
    it('should handle full cycle: save → load → validate → modify → invalidate', async () => {
      // Step 1: Create test files
      const bundlePath = join(testCacheDir, 'TestApp.app');
      const sdefPath = join(testCacheDir, 'TestApp.sdef');
      await mkdir(bundlePath, { recursive: true });
      await createTestFile(bundlePath, 'bundle');
      await createTestFile(sdefPath, 'sdef');

      // Step 2: Save cache
      const bundleStats = await stat(bundlePath);
      const sdefStats = await stat(sdefPath);

      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          {
            ...createSampleCachedApp('TestApp', bundlePath, sdefPath),
            bundleModifiedTime: bundleStats.mtimeMs,
            sdefModifiedTime: sdefStats.mtimeMs,
          },
        ],
      };
      await cache.save(manifest);

      // Step 3: Load cache
      const loaded = await cache.load();
      expect(loaded).not.toBeNull();
      expect(loaded?.apps).toHaveLength(1);

      // Step 4: Validate cache (should be valid)
      const valid1 = await cache.isValid(loaded!.apps[0]);
      expect(valid1).toBe(true);

      // Step 5: Modify bundle
      await new Promise(resolve => setTimeout(resolve, 10));
      await createTestFile(bundlePath, 'modified bundle', Date.now());

      // Step 6: Validate cache (should be invalid)
      const valid2 = await cache.isValid(loaded!.apps[0]);
      expect(valid2).toBe(false);

      // Step 7: Invalidate cache
      await cache.invalidate();

      // Step 8: Load cache (should be null)
      const loaded2 = await cache.load();
      expect(loaded2).toBeNull();
    });

    it('should handle multiple apps in single cache manifest', async () => {
      // Arrange: Create test files for multiple apps
      const apps = ['Finder', 'Safari', 'Mail'];
      const cachedApps: CachedAppData[] = [];

      for (const appName of apps) {
        const bundlePath = join(testCacheDir, `${appName}.app`);
        const sdefPath = join(testCacheDir, `${appName}.sdef`);

        await mkdir(bundlePath, { recursive: true });
        await createTestFile(bundlePath, `${appName} bundle`);
        await createTestFile(sdefPath, `${appName} sdef`);

        const bundleStats = await stat(bundlePath);
        const sdefStats = await stat(sdefPath);

        cachedApps.push({
          ...createSampleCachedApp(appName, bundlePath, sdefPath),
          bundleModifiedTime: bundleStats.mtimeMs,
          sdefModifiedTime: sdefStats.mtimeMs,
        });
      }

      const manifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: cachedApps,
      };

      // Act: Save and reload
      await cache.save(manifest);
      const loaded = await cache.load();

      // Assert: All apps loaded
      expect(loaded).not.toBeNull();
      expect(loaded?.apps).toHaveLength(3);
      expect(loaded?.apps.map(a => a.appName).sort()).toEqual(apps.sort());

      // Validate all apps
      for (const app of loaded!.apps) {
        const valid = await cache.isValid(app);
        expect(valid).toBe(true);
      }

      // Modify one app
      const safariBundle = join(testCacheDir, 'Safari.app');
      await new Promise(resolve => setTimeout(resolve, 10));
      await createTestFile(safariBundle, 'modified Safari bundle', Date.now());

      // Validate again - Safari should be invalid, others valid
      for (const app of loaded!.apps) {
        const valid = await cache.isValid(app);
        if (app.appName === 'Safari') {
          expect(valid).toBe(false);
        } else {
          expect(valid).toBe(true);
        }
      }
    });

    it('should handle concurrent load/save operations without corruption', async () => {
      // Arrange: Create initial manifest
      const manifest1: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'App1',
            '/Applications/App1.app',
            '/Applications/App1.sdef'
          ),
        ],
      };

      // Act: Perform concurrent operations
      // Note: In a real scenario, this might be more complex
      // For now, we test that save and load don't interfere
      await Promise.all([
        cache.save(manifest1),
        cache.load().catch(() => null), // Might fail if file doesn't exist yet
      ]);

      // Give file system time to settle
      await new Promise(resolve => setTimeout(resolve, 50));

      // Save another manifest
      const manifest2: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [
          createSampleCachedApp(
            'App2',
            '/Applications/App2.app',
            '/Applications/App2.sdef'
          ),
        ],
      };
      await cache.save(manifest2);

      // Assert: Latest manifest is loadable and not corrupted
      const loaded = await cache.load();
      expect(loaded).not.toBeNull();
      expect(loaded?.apps).toHaveLength(1);
      expect(loaded?.apps[0].appName).toBe('App2'); // Latest save wins

      // Verify JSON is well-formed
      const cacheFile = join(testCacheDir, 'tool-cache.json');
      const content = await readFile(cacheFile, 'utf-8');
      expect(() => JSON.parse(content)).not.toThrow();
    });
  });
});
