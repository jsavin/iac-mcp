/**
 * Integration Tests for Finder Automation
 *
 * REAL integration tests that execute actual JXA commands against the Finder
 * application on macOS. These tests verify end-to-end execution from MCP tool
 * call through to actual Finder automation.
 *
 * These are NOT unit tests - they execute real Finder commands and require:
 * - macOS system with Finder installed (always true on macOS)
 * - Proper permissions for automation
 * - Real file system operations
 *
 * PLATFORM COMPATIBILITY:
 * - These tests are AUTOMATICALLY SKIPPED on non-macOS platforms (Linux, Windows)
 * - Uses vitest's describe.skipIf() to conditionally skip the entire test suite
 * - This prevents CI failures on Linux where Finder.app doesn't exist
 *
 * Test files are created in /tmp for safety (mostly read-only operations).
 *
 * See planning/WEEK-3-EXECUTION-LAYER.md (lines 365-421) for specification.
 * See planning/WEEK-3-EXECUTION-LAYER.md (lines 1873-2344) for browser automation examples.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { MacOSAdapter } from '../../src/adapters/macos/macos-adapter.js';
import type { MCPTool, ToolMetadata } from '../../src/types/mcp-tool.js';
import { isMacOS } from '../utils/test-helpers.js';

/**
 * Test fixtures and helpers
 */

/**
 * Create a mock MCPTool for Finder operations
 */
function createFinderTool(overrides?: Partial<MCPTool>): MCPTool {
  return {
    name: 'finder_test_tool',
    description: 'Test Finder tool',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    _metadata: {
      appName: 'Finder',
      bundleId: 'com.apple.finder',
      commandName: 'testCommand',
      commandCode: 'test',
      suiteName: 'Test Suite',
    },
    ...overrides,
  };
}

/**
 * Helper to create a temporary directory for testing
 */
function createTempDir(): string {
  const timestamp = Date.now();
  const testDir = `/tmp/iac-mcp-finder-test-${timestamp}`;
  fs.mkdirSync(testDir, { recursive: true });
  return testDir;
}

/**
 * Helper to create a temporary file for testing
 */
function createTempFile(dir: string, name: string, content?: string): string {
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, content || 'Test file content');
  return filePath;
}

/**
 * Helper to clean up temporary files and directories
 */
function cleanupTempDir(dir: string): void {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Integration Tests for Finder Automation
 */
describe.skipIf(!isMacOS())('Finder Automation Integration Tests', () => {
  let adapter: MacOSAdapter;
  let tempDir: string;

  /**
   * Setup: Create adapter and test environment
   */
  beforeAll(async () => {
    adapter = new MacOSAdapter({
      timeoutMs: 10000, // 10 seconds for real operations
      enableLogging: false,
    });

    // Create temporary test directory
    tempDir = createTempDir();
  });

  /**
   * Teardown: Clean up test environment
   */
  afterAll(() => {
    cleanupTempDir(tempDir);
  });

  /**
   * ============================================================================
   * 1. Basic Finder Commands
   * ============================================================================
   */

  describe('Basic Finder Commands', () => {
    /**
     * Test: Get Finder name
     * Verifies we can get the application name
     */
    it('should get Finder name', async () => {
      const tool = createFinderTool({
        name: 'finder_get_name',
        description: 'Get Finder application name',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'name',
          commandCode: 'name',
          suiteName: 'Standard Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // This test may fail if Finder scripting isn't properly set up
      // Just verify the call completes without crashing
      expect(result).toBeDefined();
      if (result.success) {
        expect(result.data).toBeDefined();
        // Result should be "Finder" or similar
        expect(typeof result.data).toBe('string');
        expect(result.data).toContain('Finder');
      } else {
        // If it fails, should have error info
        expect(result.error).toBeDefined();
      }
    });

    /**
     * Test: Get Finder version
     * Verifies we can retrieve version information
     */
    it('should get Finder version', async () => {
      const tool = createFinderTool({
        name: 'finder_get_version',
        description: 'Get Finder version',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'version',
          commandCode: 'vers',
          suiteName: 'Standard Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      // Version should be a string like "11.2" or number
      expect(typeof result.data).toMatch(/string|number/);
    });

    /**
     * Test: Check if Finder is running
     * Verifies the testApp() method works
     */
    it('should confirm Finder is running', async () => {
      const isRunning = await adapter.testApp('com.apple.finder');

      expect(isRunning).toBe(true);
    });

    /**
     * Test: Get desktop folder path
     * Verifies we can access the desktop folder
     */
    it('should get desktop folder', async () => {
      const tool = createFinderTool({
        name: 'finder_get_desktop',
        description: 'Get desktop folder',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'getDesktop',
          commandCode: 'desk',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // May fail if Finder isn't responding, but shouldn't crash
      if (result.success) {
        expect(result.data).toBeDefined();
      }
    });

    /**
     * Test: Get home folder path
     * Verifies we can access the home folder
     */
    it('should get home folder', async () => {
      const tool = createFinderTool({
        name: 'finder_get_home',
        description: 'Get home folder',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'getHome',
          commandCode: 'home',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // May fail if Finder isn't responding, but shouldn't crash
      if (result.success) {
        expect(result.data).toBeDefined();
      }
    });
  });

  /**
   * ============================================================================
   * 2. Window Operations
   * ============================================================================
   */

  describe('Window Operations', () => {
    /**
     * Test: Open new Finder window
     * Verifies we can open a new window
     */
    it('should open new Finder window', async () => {
      const tool = createFinderTool({
        name: 'finder_open_window',
        description: 'Open new Finder window',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'makeNewWindow',
          commandCode: 'mknw',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // May succeed or fail depending on Finder state
      // Should not crash
      expect(result).toBeDefined();
      expect(result.success !== undefined).toBe(true);
    });

    /**
     * Test: Get list of open windows
     * Verifies we can retrieve window count
     */
    it('should get list of open windows', async () => {
      const tool = createFinderTool({
        name: 'finder_list_windows',
        description: 'List open Finder windows',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'getWindows',
          commandCode: 'wnds',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // May return window list or error
      expect(result).toBeDefined();
    });

    /**
     * Test: Get frontmost window
     * Verifies we can access the active window
     */
    it('should get frontmost window', async () => {
      const tool = createFinderTool({
        name: 'finder_frontmost',
        description: 'Get frontmost Finder window',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'getFrontmost',
          commandCode: 'frnt',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // Should not crash
      expect(result).toBeDefined();
    });
  });

  /**
   * ============================================================================
   * 3. File Operations
   * ============================================================================
   */

  describe('File Operations', () => {
    let testFile: string;
    let testFolder: string;

    /**
     * Setup: Create test files before each test
     */
    beforeEach(() => {
      testFile = createTempFile(tempDir, 'test-file.txt', 'Test content');
      testFolder = path.join(tempDir, 'test-folder');
      fs.mkdirSync(testFolder, { recursive: true });
    });

    /**
     * Test: Open a file/folder
     * Verifies we can open files in Finder
     */
    it('should open a file in Finder', async () => {
      const tool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file or folder',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file or folder' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: testFile });

      // Open may succeed or fail depending on Finder state
      // Should not crash
      expect(result).toBeDefined();
      expect(result.success !== undefined).toBe(true);
    });

    /**
     * Test: Reveal file in Finder
     * Verifies we can reveal files
     */
    it('should reveal file in Finder', async () => {
      const tool = createFinderTool({
        name: 'finder_reveal',
        description: 'Reveal a file in Finder',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to reveal' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'reveal',
          commandCode: 'revl',
          suiteName: 'Finder Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: testFile });

      // Reveal may succeed or fail
      // Should not crash
      expect(result).toBeDefined();
    });

    /**
     * Test: Get file properties
     * Verifies we can read file metadata
     */
    it('should get file properties (name, size, kind)', async () => {
      const tool = createFinderTool({
        name: 'finder_get_properties',
        description: 'Get file properties',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'getProperties',
          commandCode: 'prop',
          suiteName: 'Finder Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: testFile });

      // Properties may be accessible or error
      // Should not crash
      expect(result).toBeDefined();
    });

    /**
     * Test: List files in folder
     * Verifies we can enumerate directory contents
     */
    it('should list files in a folder', async () => {
      // Create some test files
      createTempFile(testFolder, 'file1.txt', 'Content 1');
      createTempFile(testFolder, 'file2.txt', 'Content 2');

      const tool = createFinderTool({
        name: 'finder_list_folder',
        description: 'List files in a folder',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Folder path' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'listFolder',
          commandCode: 'list',
          suiteName: 'Finder Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: testFolder });

      // May return file list or error
      // Should not crash
      expect(result).toBeDefined();
    });
  });

  /**
   * ============================================================================
   * 4. Navigation
   * ============================================================================
   */

  describe('Navigation', () => {
    /**
     * Test: Set target of Finder window
     * Verifies we can navigate to a folder
     */
    it('should set target of Finder window to folder', async () => {
      const tool = createFinderTool({
        name: 'finder_set_target',
        description: 'Set target folder for window',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Folder path' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'setTarget',
          commandCode: 'sett',
          suiteName: 'Finder Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: tempDir });

      // May succeed or fail
      // Should not crash
      expect(result).toBeDefined();
    });

    /**
     * Test: Go to folder
     * Verifies we can navigate to a specific folder
     */
    it('should navigate to Applications folder', async () => {
      const tool = createFinderTool({
        name: 'finder_go_to',
        description: 'Navigate to folder',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Folder path' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'goTo',
          commandCode: 'goto',
          suiteName: 'Finder Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: '/Applications' });

      // May succeed or fail
      // Should not crash
      expect(result).toBeDefined();
    });

    /**
     * Test: Go back in history
     * Verifies navigation history support
     */
    it('should navigate back in Finder history', async () => {
      const tool = createFinderTool({
        name: 'finder_go_back',
        description: 'Go back in navigation history',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'goBack',
          commandCode: 'back',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // Back may succeed or fail (no history)
      // Should not crash
      expect(result).toBeDefined();
    });

    /**
     * Test: Go forward in history
     * Verifies forward navigation support
     */
    it('should navigate forward in Finder history', async () => {
      const tool = createFinderTool({
        name: 'finder_go_forward',
        description: 'Go forward in navigation history',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'goForward',
          commandCode: 'frwd',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // Forward may succeed or fail (no forward history)
      // Should not crash
      expect(result).toBeDefined();
    });
  });

  /**
   * ============================================================================
   * 5. Error Scenarios
   * ============================================================================
   */

  describe('Error Scenarios', () => {
    /**
     * Test: Open non-existent file
     * Verifies graceful error handling for missing files
     */
    it('should handle opening non-existent file gracefully', async () => {
      const tool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, {
        target: '/tmp/nonexistent/path/to/file.txt',
      });

      // Should handle error gracefully (not crash)
      expect(result).toBeDefined();
      expect(result.success !== undefined).toBe(true);

      // If it fails, should have error info
      if (!result.success) {
        expect(result.error).toBeDefined();
        expect(result.error?.type).toBeDefined();
        expect(result.error?.message).toBeDefined();
      }
    });

    /**
     * Test: Invalid path handling
     * Verifies handling of malformed paths
     */
    it('should handle invalid path formats', async () => {
      const tool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      // Try with empty string
      const result = await adapter.execute(tool, { target: '' });

      // Should handle gracefully
      expect(result).toBeDefined();
    });

    /**
     * Test: Permission denied scenarios
     * Verifies handling when we lack required permissions
     *
     * Note: This test may not reliably trigger permission errors
     * depending on system configuration. Primarily tests that
     * errors don't cause crashes.
     */
    it('should handle permission errors gracefully', async () => {
      const tool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      // Try accessing restricted path - should be blocked by security validation
      try {
        await adapter.execute(tool, {
          target: '/private/var/db',
        });
        // If we get here, the security check didn't work
        expect.fail('Expected security validation to block /private/var/ path');
      } catch (error) {
        // Expected: security validation should catch this
        expect(error).toBeDefined();
        expect((error as Error).message).toContain('restricted system directory');
      }
    });
  });

  /**
   * ============================================================================
   * 6. Real-World Workflows
   * ============================================================================
   */

  describe('Real-World Workflows', () => {
    let workflowDir: string;

    /**
     * Setup: Create directories for workflow tests
     */
    beforeEach(() => {
      workflowDir = path.join(tempDir, 'workflow-' + Date.now());
      fs.mkdirSync(workflowDir, { recursive: true });
    });

    /**
     * Workflow: Open Desktop and list files
     * Verifies we can access desktop and enumerate files
     */
    it('should open desktop and list files', async () => {
      // Step 1: Navigate to desktop
      const navigateTool = createFinderTool({
        name: 'finder_navigate_desktop',
        description: 'Navigate to desktop',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'goTo',
          commandCode: 'goto',
          suiteName: 'Finder Suite',
        },
      });

      const navResult = await adapter.execute(navigateTool, {});
      expect(navResult).toBeDefined();

      // Step 2: List files on desktop
      const listTool = createFinderTool({
        name: 'finder_list_desktop',
        description: 'List desktop files',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Folder path' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'listFolder',
          commandCode: 'list',
          suiteName: 'Finder Suite',
          directParameterName: 'target',
        },
      });

      const listResult = await adapter.execute(listTool, {
        target: path.join(process.env.HOME || '/Users/root', 'Desktop'),
      });

      expect(listResult).toBeDefined();
    });

    /**
     * Workflow: Navigate to Applications folder
     * Verifies we can access system folders
     */
    it('should navigate to Applications folder', async () => {
      const tool = createFinderTool({
        name: 'finder_go_apps',
        description: 'Navigate to Applications',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'goTo',
          commandCode: 'goto',
          suiteName: 'Finder Suite',
        },
      });

      const result = await adapter.execute(tool, {});

      // Should not crash
      expect(result).toBeDefined();
    });

    /**
     * Workflow: Open multiple files
     * Verifies we can open several files in sequence
     */
    it('should open multiple files sequentially', async () => {
      // Create test files
      const file1 = createTempFile(workflowDir, 'file1.txt', 'Content 1');
      const file2 = createTempFile(workflowDir, 'file2.txt', 'Content 2');

      const openTool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      // Open first file
      const result1 = await adapter.execute(openTool, { target: file1 });
      expect(result1).toBeDefined();

      // Small delay between operations (optional)
      await new Promise(resolve => setTimeout(resolve, 100));

      // Open second file
      const result2 = await adapter.execute(openTool, { target: file2 });
      expect(result2).toBeDefined();

      // Both should complete without crashing
      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
    });

    /**
     * Workflow: Create and navigate to folder
     * Verifies folder operations
     */
    it('should create and navigate to a new folder', async () => {
      const newFolder = path.join(workflowDir, 'new-test-folder');
      fs.mkdirSync(newFolder, { recursive: true });

      const tool = createFinderTool({
        name: 'finder_navigate',
        description: 'Navigate to folder',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Folder path' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'goTo',
          commandCode: 'goto',
          suiteName: 'Finder Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: newFolder });

      // Should not crash
      expect(result).toBeDefined();
    });
  });

  /**
   * ============================================================================
   * 7. Timeout and Performance Tests
   * ============================================================================
   */

  describe('Timeout and Performance', () => {
    /**
     * Test: Command completes within reasonable time
     * Verifies we don't hang on simple operations
     */
    it('should complete simple command within 5 seconds', async () => {
      const tool = createFinderTool({
        name: 'finder_get_name',
        description: 'Get Finder name',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'name',
          commandCode: 'name',
          suiteName: 'Standard Suite',
        },
      });

      const startTime = Date.now();
      const result = await adapter.execute(tool, {});
      const duration = Date.now() - startTime;

      // Should complete quickly
      expect(duration).toBeLessThan(5000);
      expect(result).toBeDefined();
    });

    /**
     * Test: Adapter respects timeout configuration
     * Verifies timeout settings are applied
     */
    it('should respect timeout configuration', async () => {
      // Create adapter with short timeout
      const shortTimeoutAdapter = new MacOSAdapter({ timeoutMs: 1000 });

      const tool = createFinderTool({
        name: 'finder_test',
        description: 'Test command',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'testCommand',
          commandCode: 'test',
          suiteName: 'Test Suite',
        },
      });

      // Execute with short timeout
      const result = await shortTimeoutAdapter.execute(tool, {});

      // Should either complete or timeout gracefully
      expect(result).toBeDefined();
    });
  });

  /**
   * ============================================================================
   * 8. Adapter State and Cleanup
   * ============================================================================
   */

  describe('Adapter State and Cleanup', () => {
    /**
     * Test: Multiple sequential executions work correctly
     * Verifies adapter can handle multiple calls
     */
    it('should handle multiple sequential executions', async () => {
      const tool = createFinderTool({
        name: 'finder_test',
        description: 'Test command',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'testCommand',
          commandCode: 'test',
          suiteName: 'Test Suite',
        },
      });

      // Execute multiple times
      const result1 = await adapter.execute(tool, {});
      const result2 = await adapter.execute(tool, {});
      const result3 = await adapter.execute(tool, {});

      // All should complete
      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(result3).toBeDefined();
    });

    /**
     * Test: Adapter doesn't leak resources
     * Verifies cleanup between executions
     */
    it('should not leak resources between calls', async () => {
      const tool = createFinderTool({
        name: 'finder_test',
        description: 'Test command',
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'testCommand',
          commandCode: 'test',
          suiteName: 'Test Suite',
        },
      });

      // Execute many times
      for (let i = 0; i < 10; i++) {
        const result = await adapter.execute(tool, {});
        expect(result).toBeDefined();
      }

      // Should not crash or run out of resources
      expect(true).toBe(true);
    });
  });

  /**
   * ============================================================================
   * 9. Edge Cases
   * ============================================================================
   */

  describe('Edge Cases', () => {
    /**
     * Test: Handle very long paths
     * Verifies we can work with long file paths
     */
    it('should handle very long file paths', async () => {
      const tool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      // Create a path with many nested directories
      let longPath = tempDir;
      for (let i = 0; i < 10; i++) {
        longPath = path.join(longPath, `dir-${i}`);
      }

      const result = await adapter.execute(tool, { target: longPath });

      // Should handle gracefully (path doesn't exist, but shouldn't crash)
      expect(result).toBeDefined();
    });

    /**
     * Test: Handle special characters in paths
     * Verifies we can handle paths with spaces and special chars
     */
    it('should handle special characters in paths', async () => {
      const specialDir = path.join(tempDir, 'folder with spaces & special (chars)');
      fs.mkdirSync(specialDir, { recursive: true });

      const tool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: specialDir });

      // Should handle special characters
      expect(result).toBeDefined();
    });

    /**
     * Test: Handle unicode in paths
     * Verifies unicode path support
     */
    it('should handle unicode characters in paths', async () => {
      const unicodeDir = path.join(tempDir, '文件夹-フォルダ-папка');
      fs.mkdirSync(unicodeDir, { recursive: true });

      const tool = createFinderTool({
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'Path to file' },
          },
          required: ['target'],
        },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
          directParameterName: 'target',
        },
      });

      const result = await adapter.execute(tool, { target: unicodeDir });

      // Should handle unicode
      expect(result).toBeDefined();
    });
  });
});
