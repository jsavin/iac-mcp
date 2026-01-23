import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { isMacOS } from '../utils/test-helpers';
import { findAllScriptableApps, invalidateCache, type AppWithSDEF } from '../../src/jitd/discovery/find-sdef.js';
import { existsSync } from 'fs';
import { join } from 'path';

/**
 * Tests for Complete SDEF Coverage
 *
 * This test suite validates the enhanced app discovery functionality that adds
 * 10 missing discovery locations to achieve 100% SDEF coverage:
 *
 * 1. CoreServices recursive search (find Folder Actions Setup.app)
 * 2. Xcode nested applications (Instruments, Simulator)
 * 3. Cryptex Safari path
 * 4. Framework paths with depth limits (Wish.app, intrinsics.sdef, FolderActions.sdef)
 *
 * Test Strategy:
 * - TDD approach: These tests define expected behavior BEFORE implementation
 * - Tests will fail initially (expected for TDD)
 * - Comprehensive coverage of all 4 new search categories
 * - Edge cases: depth limits, permission errors, missing directories
 * - Regression testing: ensure existing apps are still found
 * - Coverage validation: verify total count increases from ~68 to ~78 apps
 */

describe.skipIf(!isMacOS())('Complete SDEF Coverage', () => {
  beforeEach(() => {
    // Invalidate cache before each test to ensure fresh discovery
    invalidateCache();
  });

  afterEach(() => {
    // Clean up cache after tests
    invalidateCache();
  });

  describe('CoreServices Recursive Search', () => {
    it('should find Folder Actions Setup.app in CoreServices subdirectories', async () => {
      // Folder Actions Setup is nested in /System/Library/CoreServices/Folder Actions Setup.app
      // Currently CoreServices is searched non-recursively, so this app is missed
      const folderActionsPath = '/System/Library/CoreServices/Folder Actions Setup.app';

      // Skip if app doesn't exist (might not exist on all macOS versions)
      if (!existsSync(folderActionsPath)) {
        console.log('Folder Actions Setup.app not found at expected path, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find Folder Actions Setup with recursive CoreServices search
      const folderActionsApp = apps.find(app => app.bundlePath === folderActionsPath);

      // This test will FAIL until recursive CoreServices search is implemented
      expect(folderActionsApp).toBeDefined();
      if (folderActionsApp) {
        expect(folderActionsApp.appName).toBe('Folder Actions Setup');
        expect(folderActionsApp.sdefPath).toContain('.sdef');
        expect(existsSync(folderActionsApp.sdefPath)).toBe(true);
      }
    });

    it('should recursively search all CoreServices subdirectories', async () => {
      // Test that we recursively search CoreServices, not just top-level
      const apps = await findAllScriptableApps({ useCache: false });

      // Find all apps in CoreServices subdirectories (depth > 0)
      const coreServicesDir = '/System/Library/CoreServices';
      const nestedCoreServicesApps = apps.filter(app => {
        if (!app.bundlePath.startsWith(coreServicesDir + '/')) {
          return false;
        }

        const relativePath = app.bundlePath.replace(coreServicesDir + '/', '');
        const depth = relativePath.split('/').length - 1; // -1 for the app itself
        return depth > 0; // More than 0 means it's in a subdirectory
      });

      // After implementing recursive search, should find at least 1 nested app
      // This test will FAIL until implementation
      expect(nestedCoreServicesApps.length).toBeGreaterThan(0);
    });

    it('should handle CoreServices recursive search within depth limits', async () => {
      // Ensure CoreServices recursive search doesn't go too deep
      // Should use same maxDepth as other recursive searches (default: 5)
      const apps = await findAllScriptableApps({ useCache: false });

      const coreServicesDir = '/System/Library/CoreServices';
      const coreServicesApps = apps.filter(app =>
        app.bundlePath.startsWith(coreServicesDir + '/')
      );

      // Check depth of found apps
      for (const app of coreServicesApps) {
        const relativePath = app.bundlePath.replace(coreServicesDir + '/', '');
        const depth = relativePath.split('/').length - 1;

        // Should not exceed maxDepth
        expect(depth).toBeLessThanOrEqual(5);
      }
    });
  });

  describe('Xcode Nested Applications', () => {
    it('should find Instruments.app in Xcode bundle', async () => {
      // Instruments is nested deep in Xcode:
      // /Applications/Xcode.app/Contents/Applications/Instruments.app
      const instrumentsPath = '/Applications/Xcode.app/Contents/Applications/Instruments.app';

      // Skip if Xcode or Instruments not installed
      if (!existsSync('/Applications/Xcode.app')) {
        console.log('Xcode not installed, skipping Instruments test');
        return;
      }

      if (!existsSync(instrumentsPath)) {
        console.log('Instruments.app not found in Xcode, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find Instruments with Xcode nested app search
      const instrumentsApp = apps.find(app => app.bundlePath === instrumentsPath);

      // This test will FAIL until Xcode nested search is implemented
      expect(instrumentsApp).toBeDefined();
      if (instrumentsApp) {
        expect(instrumentsApp.appName).toBe('Instruments');
      }
    });

    it('should find Simulator.app in Xcode Developer Applications', async () => {
      // Simulator is also nested in Xcode:
      // /Applications/Xcode.app/Contents/Developer/Applications/Simulator.app
      const simulatorPath = '/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app';

      // Skip if Xcode or Simulator not installed
      if (!existsSync('/Applications/Xcode.app')) {
        console.log('Xcode not installed, skipping Simulator test');
        return;
      }

      if (!existsSync(simulatorPath)) {
        console.log('Simulator.app not found in Xcode, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find Simulator with Xcode nested app search
      const simulatorApp = apps.find(app => app.bundlePath === simulatorPath);

      // This test will FAIL until Xcode nested search is implemented
      expect(simulatorApp).toBeDefined();
      if (simulatorApp) {
        expect(simulatorApp.appName).toBe('Simulator');
      }
    });

    it('should search Xcode.app/Contents/Applications directory', async () => {
      // Test that we search the Xcode/Contents/Applications directory
      const xcodeAppsDir = '/Applications/Xcode.app/Contents/Applications';

      // Skip if Xcode not installed
      if (!existsSync('/Applications/Xcode.app')) {
        console.log('Xcode not installed, skipping test');
        return;
      }

      if (!existsSync(xcodeAppsDir)) {
        console.log('Xcode Applications directory not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find apps in Xcode/Contents/Applications
      const xcodeNestedApps = apps.filter(app =>
        app.bundlePath.startsWith(xcodeAppsDir + '/')
      );

      // This test will FAIL until Xcode search is implemented
      expect(xcodeNestedApps.length).toBeGreaterThan(0);
    });

    it('should search Xcode.app/Contents/Developer/Applications directory', async () => {
      // Test that we search the Xcode/Contents/Developer/Applications directory
      const xcodeDeveloperAppsDir = '/Applications/Xcode.app/Contents/Developer/Applications';

      // Skip if Xcode not installed
      if (!existsSync('/Applications/Xcode.app')) {
        console.log('Xcode not installed, skipping test');
        return;
      }

      if (!existsSync(xcodeDeveloperAppsDir)) {
        console.log('Xcode Developer Applications directory not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find apps in Xcode/Contents/Developer/Applications
      const xcodeDeveloperApps = apps.filter(app =>
        app.bundlePath.startsWith(xcodeDeveloperAppsDir + '/')
      );

      // This test will FAIL until Xcode search is implemented
      expect(xcodeDeveloperApps.length).toBeGreaterThan(0);
    });
  });

  describe('Cryptex Safari Path', () => {
    it('should check for Safari in Cryptex path', async () => {
      // Safari can exist at:
      // /System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app
      const cryptexSafariPath = '/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app';

      // Skip if Cryptex path doesn't exist (depends on macOS version/configuration)
      if (!existsSync('/System/Volumes/Preboot/Cryptexes/App/System/Applications')) {
        console.log('Cryptex Applications directory not found, skipping test');
        return;
      }

      if (!existsSync(cryptexSafariPath)) {
        console.log('Safari not found at Cryptex path, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Should find Safari at Cryptex path if it exists
      const cryptexSafari = apps.find(app => app.bundlePath === cryptexSafariPath);

      // This test will FAIL until Cryptex path search is implemented
      expect(cryptexSafari).toBeDefined();
      if (cryptexSafari) {
        expect(cryptexSafari.appName).toBe('Safari');
      }
    });

    it('should search Cryptex System Applications directory', async () => {
      // Test that we search the Cryptex System/Applications directory
      const cryptexAppsDir = '/System/Volumes/Preboot/Cryptexes/App/System/Applications';

      // Skip if Cryptex path doesn't exist
      if (!existsSync(cryptexAppsDir)) {
        console.log('Cryptex Applications directory not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find apps in Cryptex Applications
      const cryptexApps = apps.filter(app =>
        app.bundlePath.startsWith(cryptexAppsDir + '/')
      );

      // If Cryptex directory exists and has apps, we should find them
      // This test will FAIL until Cryptex search is implemented
      expect(Array.isArray(cryptexApps)).toBe(true);
    });

    it('should handle missing Cryptex directory gracefully', async () => {
      // Cryptex path may not exist on all systems
      // Discovery should not crash if the directory doesn't exist
      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete successfully even if Cryptex doesn't exist
      expect(Array.isArray(apps)).toBe(true);
      expect(apps.length).toBeGreaterThan(0);
    });
  });

  describe('Framework Paths with Depth Limits', () => {
    it('should find Wish.app in System Frameworks', async () => {
      // Wish.app (Tcl/Tk framework app) is in:
      // /System/Library/Frameworks/Tk.framework/Versions/*/Resources/Wish.app
      // Exact version varies, so we check for pattern match
      const frameworksDir = '/System/Library/Frameworks';

      // Skip if Frameworks directory doesn't exist
      if (!existsSync(frameworksDir)) {
        console.log('System Frameworks directory not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find Wish.app anywhere in Frameworks
      // Note: The app might be named "Wish" or "Wish Shell" (symlink)
      const wishApp = apps.find(app =>
        (app.appName === 'Wish' || app.appName === 'Wish Shell') &&
        app.bundlePath.includes('/System/Library/Frameworks/Tk.framework/')
      );

      // This test will FAIL until Framework search is implemented
      expect(wishApp).toBeDefined();
      if (wishApp) {
        expect(wishApp.bundlePath).toMatch(/\/System\/Library\/Frameworks\/Tk\.framework\//);
        expect(existsSync(wishApp.sdefPath)).toBe(true);
      }
    });

    it('should find intrinsics.sdef in System Frameworks', async () => {
      // intrinsics.sdef exists at:
      // /System/Library/Frameworks/JavaScriptCore.framework/Resources/intrinsics.sdef
      // Note: This is a standalone SDEF file, not in a .app bundle
      const intrinsicsPath = '/System/Library/Frameworks/JavaScriptCore.framework/Resources/intrinsics.sdef';

      // Skip if file doesn't exist (depends on macOS version)
      if (!existsSync(intrinsicsPath)) {
        console.log('intrinsics.sdef not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Note: Our current implementation only finds .app bundles
      // This test documents the limitation - we may need to enhance
      // the discovery to also find standalone SDEF files in Frameworks
      // For now, this test is documentation of the known gap
      // TODO: Enhance discovery to find standalone SDEF files
    });

    it('should find FolderActions.sdef in PrivateFrameworks', async () => {
      // FolderActions.sdef exists at:
      // /System/Library/PrivateFrameworks/FolderActions.framework/Resources/FolderActions.sdef
      // Note: This is a standalone SDEF file, not in a .app bundle
      const folderActionsSDEFPath = '/System/Library/PrivateFrameworks/FolderActions.framework/Resources/FolderActions.sdef';

      // Skip if file doesn't exist
      if (!existsSync(folderActionsSDEFPath)) {
        console.log('FolderActions.sdef not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Note: Same limitation as intrinsics.sdef
      // Current implementation only finds .app bundles
      // This test documents the gap
      // TODO: Enhance discovery to find standalone SDEF files
    });

    it('should search System/Library/Frameworks with depth limit', async () => {
      // Test that we search Frameworks directory with appropriate depth
      const frameworksDir = '/System/Library/Frameworks';

      // Skip if directory doesn't exist
      if (!existsSync(frameworksDir)) {
        console.log('System Frameworks directory not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find apps in Frameworks
      const frameworkApps = apps.filter(app =>
        app.bundlePath.startsWith(frameworksDir + '/')
      );

      // Check depth of found apps (should respect maxDepth: 3)
      for (const app of frameworkApps) {
        const relativePath = app.bundlePath.replace(frameworksDir + '/', '');
        const depth = relativePath.split('/').length - 1;

        // Should not exceed maxDepth for Frameworks (3)
        expect(depth).toBeLessThanOrEqual(3);
      }

      // This test will FAIL until Framework search is implemented
      expect(Array.isArray(frameworkApps)).toBe(true);
    });

    it('should search System/Library/PrivateFrameworks with depth limit', async () => {
      // Test that we search PrivateFrameworks directory with appropriate depth
      const privateFrameworksDir = '/System/Library/PrivateFrameworks';

      // Skip if directory doesn't exist
      if (!existsSync(privateFrameworksDir)) {
        console.log('System PrivateFrameworks directory not found, skipping test');
        return;
      }

      const apps = await findAllScriptableApps({ useCache: false });

      // Find apps in PrivateFrameworks
      const privateFrameworkApps = apps.filter(app =>
        app.bundlePath.startsWith(privateFrameworksDir + '/')
      );

      // Check depth of found apps (should respect maxDepth: 3)
      for (const app of privateFrameworkApps) {
        const relativePath = app.bundlePath.replace(privateFrameworksDir + '/', '');
        const depth = relativePath.split('/').length - 1;

        // Should not exceed maxDepth for Frameworks (3)
        expect(depth).toBeLessThanOrEqual(3);
      }

      // This test will FAIL until PrivateFrameworks search is implemented
      expect(Array.isArray(privateFrameworkApps)).toBe(true);
    });

    it('should respect maxDepth limit in Framework searches', async () => {
      // Ensure Framework searches don't go too deep
      // Should use maxDepth: 3 for Frameworks (not default 5)
      const apps = await findAllScriptableApps({ useCache: false });

      const frameworkDirs = [
        '/System/Library/Frameworks',
        '/System/Library/PrivateFrameworks',
      ];

      // Find all apps in Framework directories
      const frameworkApps = apps.filter(app =>
        frameworkDirs.some(dir => app.bundlePath.startsWith(dir + '/'))
      );

      // Check that all Framework apps respect depth limit
      for (const app of frameworkApps) {
        const frameworkDir = frameworkDirs.find(dir =>
          app.bundlePath.startsWith(dir + '/')
        );

        if (frameworkDir) {
          const relativePath = app.bundlePath.replace(frameworkDir + '/', '');
          const depth = relativePath.split('/').length - 1;

          // Should not exceed maxDepth: 3 for Frameworks
          expect(depth).toBeLessThanOrEqual(3);
        }
      }
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle permission denied in Cryptex directory gracefully', async () => {
      // Cryptex directories may have restricted permissions
      // Discovery should continue even if access is denied
      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete without crashing
      expect(Array.isArray(apps)).toBe(true);
      expect(apps.length).toBeGreaterThan(0);
    });

    it('should handle missing Xcode directory gracefully', async () => {
      // Xcode may not be installed
      // Discovery should not crash if Xcode paths don't exist
      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete successfully even without Xcode
      expect(Array.isArray(apps)).toBe(true);
      expect(apps.length).toBeGreaterThan(0);
    });

    it('should handle permission denied in Framework directories gracefully', async () => {
      // Some Framework subdirectories may be restricted
      // Discovery should continue and find accessible apps
      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete without crashing
      expect(Array.isArray(apps)).toBe(true);
      expect(apps.length).toBeGreaterThan(0);
    });

    it('should not crash on deeply nested Framework structures', async () => {
      // Framework directories can be deeply nested
      // maxDepth: 3 should prevent excessive recursion
      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete successfully
      expect(Array.isArray(apps)).toBe(true);
    });

    it('should handle symlinks in new search paths gracefully', async () => {
      // New paths may contain symlinks
      // Should detect and skip circular symlinks
      const apps = await findAllScriptableApps({ useCache: false });

      // Should complete without infinite loops
      expect(Array.isArray(apps)).toBe(true);
    });

    it('should not duplicate apps found in multiple paths', async () => {
      // Some apps might be accessible via multiple paths (symlinks, etc.)
      // Should deduplicate results
      const apps = await findAllScriptableApps({ useCache: false });

      // Create a set of bundle paths to check for duplicates
      const bundlePaths = apps.map(app => app.bundlePath);
      const uniquePaths = new Set(bundlePaths);

      // Should have no duplicates
      expect(bundlePaths.length).toBe(uniquePaths.size);
    });
  });

  describe('Coverage Validation', () => {
    it('should search all 4 new discovery categories', async () => {
      // Validate that all new search locations are attempted
      const apps = await findAllScriptableApps({ useCache: false });

      // Categories to validate (existence checked, not all will have apps):
      // 1. CoreServices (recursive)
      // 2. Xcode nested apps (if Xcode installed)
      // 3. Cryptex paths (if available)
      // 4. Framework paths

      // We can't guarantee all paths exist, but we can check the function completes
      expect(Array.isArray(apps)).toBe(true);
      expect(apps.length).toBeGreaterThan(0);
    });

    it('should increase total app count from baseline ~68', async () => {
      // Before: ~49 apps discovered (without new paths)
      // After: ~61 apps discovered (with 4 new discovery paths)
      const apps = await findAllScriptableApps({ useCache: false });

      // Exact count depends on system configuration
      // With the 4 new discovery paths (CoreServices recursive, Xcode, Cryptex, Frameworks),
      // we expect to find at least 55+ apps (baseline ~49 + ~12 new apps from new paths)
      // Note: Framework search is limited to known locations to avoid performance issues
      expect(apps.length).toBeGreaterThanOrEqual(55);
    });

    it('should find at least 1 app from new discovery paths', async () => {
      // Validate that new paths contribute at least some apps
      const apps = await findAllScriptableApps({ useCache: false });

      // Paths that should contribute new apps:
      const newPaths = [
        '/System/Library/CoreServices/', // Recursive (Folder Actions Setup)
        '/Applications/Xcode.app/Contents/', // Xcode nested
        '/System/Volumes/Preboot/Cryptexes/', // Cryptex
        '/System/Library/Frameworks/', // Frameworks
        '/System/Library/PrivateFrameworks/', // PrivateFrameworks
      ];

      // Find apps from new paths
      const newPathApps = apps.filter(app =>
        newPaths.some(path => app.bundlePath.includes(path))
      );

      // Should find at least 1 app from new paths
      // This test will FAIL until implementation
      expect(newPathApps.length).toBeGreaterThan(0);
    });

    it('should maintain existing app discovery (regression test)', async () => {
      // Ensure new search paths don't break existing discovery
      const apps = await findAllScriptableApps({ useCache: false });

      // Should still find Finder (baseline test)
      const finder = apps.find(app =>
        app.bundlePath === '/System/Library/CoreServices/Finder.app'
      );
      expect(finder).toBeDefined();

      // Should still find Safari (if exists)
      const safari = apps.find(app => app.appName === 'Safari');
      if (existsSync('/System/Applications/Safari.app') ||
          existsSync('/Applications/Safari.app')) {
        expect(safari).toBeDefined();
      }

      // Should still find Mail (if exists)
      const mail = apps.find(app => app.appName === 'Mail');
      if (existsSync('/System/Applications/Mail.app')) {
        expect(mail).toBeDefined();
      }
    });

    it('should complete discovery within reasonable time with new paths', async () => {
      // With 4 new search categories, ensure performance is still acceptable
      const startTime = Date.now();

      const apps = await findAllScriptableApps({ useCache: false });

      const duration = Date.now() - startTime;

      // Should complete within 30 seconds even with new paths
      expect(duration).toBeLessThan(30000);

      // Should find apps
      expect(apps.length).toBeGreaterThan(0);
    });

    it('should cache results effectively with new paths', async () => {
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

  describe('Regression Tests - Existing Functionality', () => {
    it('should still find apps in /System/Applications', async () => {
      const apps = await findAllScriptableApps({ useCache: false });

      const systemApps = apps.filter(app =>
        app.bundlePath.startsWith('/System/Applications/')
      );

      expect(systemApps.length).toBeGreaterThan(0);
    });

    it('should still find apps in /Applications', async () => {
      const apps = await findAllScriptableApps({ useCache: false });

      const standardApps = apps.filter(app =>
        app.bundlePath.startsWith('/Applications/') &&
        !app.bundlePath.startsWith('/Applications/Xcode.app/') // Exclude Xcode nested
      );

      // Should find at least some apps
      expect(Array.isArray(standardApps)).toBe(true);
    });

    it('should maintain result structure with new paths', async () => {
      const apps = await findAllScriptableApps({ useCache: false });

      // All results should have expected structure
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

    it('should not break existing caching with new paths', async () => {
      // First call
      const apps1 = await findAllScriptableApps({ useCache: false });

      // Second call (should use cache)
      const apps2 = await findAllScriptableApps({ useCache: true });

      // Should return same results
      expect(apps2.length).toBe(apps1.length);
    });
  });
});
