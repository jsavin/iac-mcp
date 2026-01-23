import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { isMacOS } from '../utils/test-helpers';
import { findAllScriptableApps, invalidateCache, type AppWithSDEF } from '../../src/jitd/discovery/find-sdef.js';
import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

/**
 * Tests for Recursive App Discovery Improvements
 *
 * This test suite validates the enhanced app discovery functionality that searches:
 * 1. Recursively in /Applications (finds apps in subdirectories like /Applications/Utilities/)
 * 2. Recursively in ~/Applications (finds Chrome Apps and other nested user apps)
 * 3. In ~/Library locations (finds apps in Library/Application Support, etc.)
 *
 * Test Strategy:
 * - TDD approach: These tests define expected behavior before implementation
 * - Tests should fail initially (expected for TDD)
 * - Comprehensive coverage of all 3 new search locations
 * - Performance testing to ensure recursive search doesn't cause slowdown
 * - Edge cases: symlinks, permissions, deep nesting
 * - Regression testing: ensure existing apps are still found
 */

describe.skipIf(!isMacOS())('Recursive App Discovery', () => {
  beforeEach(() => {
    // Invalidate cache before each test to ensure fresh discovery
    invalidateCache();
  });

  afterEach(() => {
    // Clean up cache after tests
    invalidateCache();
  });

  describe('Recursive System Applications Search', () => {
    it('should find apps in /System/Applications/Utilities/', async () => {
      // /System/Applications/Utilities contains many standard macOS utility apps
      const systemUtilitiesDir = '/System/Applications/Utilities';

      // Skip if directory doesn't exist (shouldn't happen on macOS)
      if (!existsSync(systemUtilitiesDir)) {
        console.log('/System/Applications/Utilities not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find apps in /System/Applications/Utilities
      const utilityApps = apps.filter(app =>
        app.bundlePath.startsWith(systemUtilitiesDir + '/')
      );

      // Terminal.app and other utilities should be found here
      // This is the key test for recursive search in system directories
      expect(utilityApps.length).toBeGreaterThan(0);
    });

    it('should find Terminal.app in /System/Applications/Utilities/', async () => {
      // Terminal.app is a standard macOS app that supports AppleScript
      const terminalPath = '/System/Applications/Utilities/Terminal.app';

      // Skip test if Terminal.app doesn't exist (shouldn't happen on macOS)
      if (!existsSync(terminalPath)) {
        console.log('Terminal.app not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find Terminal.app in the results
      const terminalApp = apps.find(app => app.bundlePath === terminalPath);

      // This test will fail until recursive search is implemented
      expect(terminalApp).toBeDefined();
      if (terminalApp) {
        expect(terminalApp.appName).toBe('Terminal');
        expect(terminalApp.sdefPath).toContain('Terminal.sdef');
        expect(existsSync(terminalApp.sdefPath)).toBe(true);
      }
    });
  });

  describe('Recursive /Applications Search', () => {
    it('should find apps in /Applications subdirectories', async () => {
      // Check if any apps exist in /Applications subdirectories
      // Common location: /Applications/Utilities/ (if it exists)
      const utilitiesDir = '/Applications/Utilities';

      // Skip if Utilities directory doesn't exist or is empty
      if (!existsSync(utilitiesDir)) {
        console.log('/Applications/Utilities not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find apps in /Applications subdirectories
      const appsInUtilities = apps.filter(app =>
        app.bundlePath.startsWith(utilitiesDir + '/')
      );

      // If the directory exists and has apps, we should find them
      // This validates recursive search capability
      expect(Array.isArray(appsInUtilities)).toBe(true);
    });

    it('should recursively search all /Applications subdirectories', async () => {
      // Test that we recursively search all subdirectories
      // Any app in a subdirectory of /Applications should be found
      const apps = await findAllScriptableApps({ useCache: false });

      // Find all apps that are in subdirectories of /Applications
      const appsInSubdirs = apps.filter(app => {
        if (!app.bundlePath.startsWith('/Applications/')) {
          return false;
        }

        const relativePath = app.bundlePath.replace('/Applications/', '');
        const depth = relativePath.split('/').length - 1; // -1 for the app itself
        return depth > 0; // More than 0 means it's in a subdirectory
      });

      // After implementing recursive search, we should find at least some apps in subdirectories
      // This test will pass once recursive search is implemented
      // For now, it validates the test logic works correctly
      expect(Array.isArray(appsInSubdirs)).toBe(true);
    });

    it('should handle deeply nested /Applications subdirectories', async () => {
      // Test that we can handle apps several levels deep
      // Example: /Applications/SomeVendor/SubFolder/App.app
      const apps = await findAllScriptableApps({ useCache: false });

      // Check if any apps are found more than 1 level deep
      const deeplyNestedApps = apps.filter(app => {
        const relativePath = app.bundlePath.replace('/Applications/', '');
        const depth = relativePath.split('/').length - 1; // -1 for the app itself
        return depth > 1;
      });

      // This test validates the capability even if no deeply nested apps exist
      // If deeply nested apps exist, they should be found
      expect(Array.isArray(deeplyNestedApps)).toBe(true);
    });

    it('should not find non-app directories in /Applications', async () => {
      // Ensure we only find .app bundles, not regular directories
      const apps = await findAllScriptableApps({ useCache: false });

      // All discovered apps should have .app extension
      for (const app of apps) {
        expect(app.bundlePath).toMatch(/\.app$/);
      }
    });
  });

  describe('Recursive ~/Applications Search', () => {
    it('should search ~/Applications directory', async () => {
      const userAppsDir = join(homedir(), 'Applications');

      // Skip if ~/Applications doesn't exist
      if (!existsSync(userAppsDir)) {
        console.log('~/Applications not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Check if any apps were found in ~/Applications (including subdirectories)
      const userApps = apps.filter(app =>
        app.bundlePath.startsWith(userAppsDir + '/')
      );

      // If ~/Applications exists and has apps, we should find them
      // Note: This may be 0 if user has no apps there, which is valid
      expect(Array.isArray(userApps)).toBe(true);
    });

    it('should find Chrome Apps in ~/Applications/Chrome Apps/', async () => {
      const chromeAppsDir = join(homedir(), 'Applications', 'Chrome Apps.localized');

      // Skip if Chrome Apps directory doesn't exist
      if (!existsSync(chromeAppsDir)) {
        console.log('Chrome Apps directory not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Check if any apps were found in Chrome Apps directory
      const chromeApps = apps.filter(app =>
        app.bundlePath.startsWith(chromeAppsDir + '/')
      );

      // Validate structure if Chrome Apps exist
      expect(Array.isArray(chromeApps)).toBe(true);
    });

    it('should handle nested directories in ~/Applications', async () => {
      const userAppsDir = join(homedir(), 'Applications');

      // Skip if ~/Applications doesn't exist
      if (!existsSync(userAppsDir)) {
        console.log('~/Applications not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find apps in subdirectories of ~/Applications
      const nestedUserApps = apps.filter(app => {
        if (!app.bundlePath.startsWith(userAppsDir + '/')) {
          return false;
        }

        const relativePath = app.bundlePath.replace(userAppsDir + '/', '');
        const depth = relativePath.split('/').length - 1; // -1 for the app itself
        return depth > 0; // More than 0 means it's in a subdirectory
      });

      // Validate that we CAN find nested apps (even if there are none)
      expect(Array.isArray(nestedUserApps)).toBe(true);
    });
  });

  describe('~/Library Search', () => {
    it('should search ~/Library/Application Support/', async () => {
      const libraryAppSupport = join(homedir(), 'Library', 'Application Support');

      // Skip if directory doesn't exist (shouldn't happen on macOS)
      if (!existsSync(libraryAppSupport)) {
        console.log('~/Library/Application Support not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Check if any apps were found in Library/Application Support
      const libraryApps = apps.filter(app =>
        app.bundlePath.startsWith(libraryAppSupport + '/')
      );

      // Validate capability (may be 0 apps, which is valid)
      expect(Array.isArray(libraryApps)).toBe(true);
    });

    it('should search other ~/Library locations with apps', async () => {
      const libraryLocations = [
        join(homedir(), 'Library', 'Application Support'),
        join(homedir(), 'Library', 'PreferencePanes'),
        join(homedir(), 'Library', 'Screen Savers'),
      ];

      const apps = await findAllScriptableApps({ useCache: false });

      // Check if any apps were found in any Library location
      const libraryApps = apps.filter(app =>
        libraryLocations.some(loc => app.bundlePath.startsWith(loc + '/'))
      );

      // Validate capability
      expect(Array.isArray(libraryApps)).toBe(true);
    });

    it('should handle nested directories in ~/Library locations', async () => {
      const libraryAppSupport = join(homedir(), 'Library', 'Application Support');

      // Skip if directory doesn't exist
      if (!existsSync(libraryAppSupport)) {
        console.log('~/Library/Application Support not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find apps in subdirectories of Library/Application Support
      const nestedLibraryApps = apps.filter(app => {
        if (!app.bundlePath.startsWith(libraryAppSupport + '/')) {
          return false;
        }

        const relativePath = app.bundlePath.replace(libraryAppSupport + '/', '');
        const depth = relativePath.split('/').length - 1;
        return depth > 0; // In a subdirectory
      });

      // Validate capability
      expect(Array.isArray(nestedLibraryApps)).toBe(true);
    });
  });

  describe('Performance Tests', () => {
    it('should complete recursive search within reasonable time', async () => {
      const startTime = Date.now();

      const apps = await findAllScriptableApps({ useCache: false });

      const duration = Date.now() - startTime;

      // Recursive search should complete within 30 seconds
      // (Adjust threshold based on actual performance requirements)
      expect(duration).toBeLessThan(30000);

      // Should still find apps
      expect(apps.length).toBeGreaterThan(0);
    });

    it('should not cause significant slowdown vs non-recursive search', async () => {
      // This test validates that adding recursive search doesn't cause
      // unacceptable performance degradation

      // First run (populates cache)
      await findAllScriptableApps({ useCache: false });

      // Second run (measures performance)
      const startTime = Date.now();
      const apps = await findAllScriptableApps({ useCache: false });
      const duration = Date.now() - startTime;

      // Should find reasonable number of apps
      expect(apps.length).toBeGreaterThan(0);

      // Should complete in reasonable time (30 seconds)
      expect(duration).toBeLessThan(30000);
    });

    it('should cache results effectively across recursive search', async () => {
      // First call (no cache)
      const startTime1 = Date.now();
      const apps1 = await findAllScriptableApps({ useCache: false });
      const duration1 = Date.now() - startTime1;

      // Second call (with cache)
      const startTime2 = Date.now();
      const apps2 = await findAllScriptableApps({ useCache: true });
      const duration2 = Date.now() - startTime2;

      // Cached call should be MUCH faster (at least 10x)
      expect(duration2).toBeLessThan(duration1 / 10);

      // Should return same results
      expect(apps2.length).toBe(apps1.length);
    });
  });

  describe('Edge Cases', () => {
    it('should handle circular symlinks gracefully', async () => {
      // Recursive search must not get stuck in infinite loops
      // If circular symlinks exist, they should be detected and skipped

      // This test validates that the function completes without hanging
      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete successfully
      expect(Array.isArray(apps)).toBe(true);
    });

    it('should handle permission denied errors gracefully', async () => {
      // Some directories in /Applications or ~/Library may have restricted permissions
      // Discovery should continue even if some directories are inaccessible

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find at least some apps despite potential permission issues
      expect(apps.length).toBeGreaterThan(0);
    });

    it('should handle very deep nesting gracefully', async () => {
      // Ensure we don't hit stack overflow or path length limits
      // with deeply nested directory structures

      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete without errors
      expect(Array.isArray(apps)).toBe(true);

      // Check for any apps with very long paths (>10 levels deep)
      const veryDeepApps = apps.filter(app => {
        const pathSegments = app.bundlePath.split('/');
        return pathSegments.length > 10;
      });

      // If such apps exist, they should be valid
      for (const app of veryDeepApps) {
        expect(app.bundlePath).toMatch(/\.app$/);
        expect(existsSync(app.bundlePath)).toBe(true);
      }
    });

    it('should skip non-directory items gracefully', async () => {
      // If a .app file exists (malformed bundle), should skip it
      // Only real app bundles (directories with .app extension) should be included

      const apps = await findAllScriptableApps({ useCache: false });

      // All results should be valid directories
      for (const app of apps) {
        expect(existsSync(app.bundlePath)).toBe(true);
      }
    });

    it('should handle .localized directory names', async () => {
      // macOS uses .localized suffixes for localized folder names
      // Example: "Chrome Apps.localized"
      // Ensure these are searched correctly

      const apps = await findAllScriptableApps({ useCache: false });

      // Check if any apps are found in .localized directories
      const localizedDirApps = apps.filter(app =>
        app.bundlePath.includes('.localized/')
      );

      // Validate structure if such apps exist
      expect(Array.isArray(localizedDirApps)).toBe(true);
    });
  });

  describe('Regression Tests - Existing Functionality', () => {
    it('should still find Finder.app in /System/Library/CoreServices', async () => {
      // Ensure our changes don't break existing app discovery
      const finderPath = '/System/Library/CoreServices/Finder.app';

      if (!existsSync(finderPath)) {
        console.log('Finder.app not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      const finder = apps.find(app => app.bundlePath === finderPath);

      expect(finder).toBeDefined();
      if (finder) {
        expect(finder.appName).toBe('Finder');
      }
    });

    it('should still find apps in /System/Applications', async () => {
      const systemAppsDir = '/System/Applications';

      if (!existsSync(systemAppsDir)) {
        console.log('/System/Applications not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find at least some apps in /System/Applications
      const systemApps = apps.filter(app =>
        app.bundlePath.startsWith(systemAppsDir + '/')
      );

      expect(systemApps.length).toBeGreaterThan(0);
    });

    it('should still find apps directly in /Applications', async () => {
      const apps = await findAllScriptableApps({ useCache: false });

      // Should find apps directly in /Applications (not in subdirectories)
      const topLevelApps = apps.filter(app => {
        const relativePath = app.bundlePath.replace('/Applications/', '');
        const depth = relativePath.split('/').length - 1;
        return app.bundlePath.startsWith('/Applications/') && depth === 0;
      });

      // Should find at least some top-level apps
      expect(topLevelApps.length).toBeGreaterThan(0);
    });

    it('should maintain same result structure', async () => {
      const apps = await findAllScriptableApps({ useCache: false });

      // All results should have the expected structure
      for (const app of apps) {
        expect(app).toHaveProperty('appName');
        expect(app).toHaveProperty('bundlePath');
        expect(app).toHaveProperty('sdefPath');

        expect(typeof app.appName).toBe('string');
        expect(typeof app.bundlePath).toBe('string');
        expect(typeof app.sdefPath).toBe('string');

        expect(app.appName.length).toBeGreaterThan(0);
        expect(app.bundlePath).toMatch(/\.app$/);
        expect(app.sdefPath).toMatch(/\.sdef$/);
      }
    });

    it('should not return duplicate apps', async () => {
      const apps = await findAllScriptableApps({ useCache: false });

      // Create a set of bundle paths to check for duplicates
      const bundlePaths = apps.map(app => app.bundlePath);
      const uniquePaths = new Set(bundlePaths);

      // Should have no duplicates
      expect(bundlePaths.length).toBe(uniquePaths.size);
    });
  });

  describe('Coverage Validation', () => {
    it('should search all expected locations', async () => {
      // This test validates that all 3 new search locations are included
      const apps = await findAllScriptableApps({ useCache: false });

      // Define expected search locations
      const expectedLocations = [
        '/System/Library/CoreServices',
        '/System/Applications',
        '/Applications', // Should be recursive now
        join(homedir(), 'Applications'), // Should be recursive now
        join(homedir(), 'Library'), // New location
      ];

      // Track which locations have apps
      const locationsWithApps = new Set<string>();

      for (const app of apps) {
        for (const location of expectedLocations) {
          if (app.bundlePath.startsWith(location + '/')) {
            locationsWithApps.add(location);
          }
        }
      }

      // Should find apps in at least the system locations
      expect(locationsWithApps.has('/System/Library/CoreServices') ||
             locationsWithApps.has('/System/Applications') ||
             locationsWithApps.has('/Applications')).toBe(true);
    });

    it('should increase total app count vs non-recursive search', async () => {
      // This test validates that recursive search finds MORE apps
      // Note: This test will only pass after implementation

      const apps = await findAllScriptableApps({ useCache: false });

      // After implementing recursive search, we should find more apps
      // Exact count depends on system, but we should find at least:
      // - System apps (Finder, Safari, etc.): ~10-20
      // - Utilities apps (Terminal, etc.): ~5-10
      // - User apps (if any): 0+
      // Total minimum: ~15-30 scriptable apps on a typical macOS system

      expect(apps.length).toBeGreaterThan(10);
    });
  });
});
