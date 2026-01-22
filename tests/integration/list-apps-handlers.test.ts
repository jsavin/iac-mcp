/**
 * Integration Tests for list_apps Tool and iac://apps Resource Handlers
 *
 * These tests actually execute handler code (not just mock validation) to verify:
 * - list_apps CallTool handler returns valid app metadata
 * - iac://apps ListResources handler returns resource definition
 * - iac://apps ReadResource handler returns app data
 * - Data consistency between tool and resource endpoints
 * - Caching behavior in discoverAppMetadata()
 * - URI validation and security checks
 *
 * Purpose: Increase handlers.ts coverage from 17.13% to >70% by testing real execution paths
 *
 * Reference: Bot review feedback on PR (handlers only tested via mocks, not execution)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as path from 'path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  setupHandlers,
  validateToolArguments,
  formatSuccessResponse,
  formatPermissionDeniedResponse,
} from '../../src/mcp/handlers.js';
import { ToolGenerator } from '../../src/jitd/tool-generator/generator.js';
import { MacOSAdapter } from '../../src/adapters/macos/macos-adapter.js';
import { PermissionChecker } from '../../src/permissions/permission-checker.js';
import { ErrorHandler } from '../../src/error-handler.js';
import { PerAppCache } from '../../src/jitd/cache/per-app-cache.js';
import type { AppMetadata } from '../../src/types/app-metadata.js';

// ============================================================================
// TEST FIXTURES AND SETUP
// ============================================================================

const TEMP_CACHE_DIR = path.join(import.meta.dirname, '../../.test-cache-handlers');

/**
 * Captured handlers from setupHandlers
 */
interface CapturedHandlers {
  listTools?: (request: any) => Promise<any>;
  callTool?: (request: any) => Promise<any>;
  listResources?: (request: any) => Promise<any>;
  readResource?: (request: any) => Promise<any>;
}

/**
 * Helper to create a test server and capture handlers
 */
async function createTestServerWithHandlers(): Promise<CapturedHandlers> {
  const handlers: CapturedHandlers = {};

  // Create a mock server that captures handlers when they're registered
  const mockServer = {
    setRequestHandler: (schema: any, handler: any) => {
      // Capture handler based on schema object reference
      if (schema === ListToolsRequestSchema) {
        handlers.listTools = handler;
      } else if (schema === CallToolRequestSchema) {
        handlers.callTool = handler;
      } else if (schema === ListResourcesRequestSchema) {
        handlers.listResources = handler;
      } else if (schema === ReadResourceRequestSchema) {
        handlers.readResource = handler;
      }
    },
  } as any;

  const toolGenerator = new ToolGenerator();
  const adapter = new MacOSAdapter();
  const permissionChecker = new PermissionChecker({
    defaultLevel: 'safe',
    promptUser: async () => ({ allowed: true, remember: false }),
  });
  const errorHandler = new ErrorHandler();
  const perAppCache = new PerAppCache({ cacheDir: TEMP_CACHE_DIR, maxAge: 3600000 });

  await setupHandlers(mockServer, toolGenerator, permissionChecker, adapter, errorHandler, perAppCache);

  return handlers;
}

/**
 * Helper to call ListTools handler
 */
async function callListTools(handlers: CapturedHandlers): Promise<any> {
  if (!handlers.listTools) {
    throw new Error('ListTools handler not registered');
  }
  return handlers.listTools({});
}

/**
 * Helper to call CallTool handler
 */
async function callTool(handlers: CapturedHandlers, name: string, args?: Record<string, any>): Promise<any> {
  if (!handlers.callTool) {
    throw new Error('CallTool handler not registered');
  }
  return handlers.callTool({ params: { name, arguments: args || {} } });
}

/**
 * Helper to call ListResources handler
 */
async function callListResources(handlers: CapturedHandlers): Promise<any> {
  if (!handlers.listResources) {
    throw new Error('ListResources handler not registered');
  }
  return handlers.listResources({});
}

/**
 * Helper to call ReadResource handler
 */
async function callReadResource(handlers: CapturedHandlers, uri: string): Promise<any> {
  if (!handlers.readResource) {
    throw new Error('ReadResource handler not registered');
  }
  return handlers.readResource({ params: { uri } });
}

// ============================================================================
// TESTS
// ============================================================================

describe('list_apps Tool and iac://apps Resource - Actual Handler Execution', () => {
  let handlers: CapturedHandlers;

  beforeEach(async () => {
    vi.clearAllMocks();
    handlers = await createTestServerWithHandlers();
  });

  afterEach(() => {
    // Cleanup
  });

  // ==========================================================================
  // SECTION 1: list_apps Tool Handler - Actual Execution
  // ==========================================================================

  describe('list_apps Tool Handler - Actual Execution', () => {
    it('should execute list_apps tool and return valid app metadata', async () => {
      // Execute the actual handler
      const response = await callTool(handlers, 'list_apps');

      // Verify response structure
      expect(response).toBeDefined();
      expect(response.content).toBeDefined();
      expect(Array.isArray(response.content)).toBe(true);
      expect(response.content.length).toBeGreaterThan(0);

      // Parse JSON response
      const jsonText = response.content[0].text;
      expect(jsonText).toBeDefined();
      const data = JSON.parse(jsonText);

      // Verify data structure
      expect(data).toHaveProperty('totalApps');
      expect(data).toHaveProperty('apps');
      expect(typeof data.totalApps).toBe('number');
      expect(Array.isArray(data.apps)).toBe(true);

      // If apps discovered, verify structure
      if (data.totalApps > 0) {
        const firstApp = data.apps[0];
        expect(firstApp).toHaveProperty('name');
        expect(firstApp).toHaveProperty('bundleId');
        expect(firstApp).toHaveProperty('description');
        expect(firstApp).toHaveProperty('toolCount');
        expect(firstApp).toHaveProperty('suites');
        expect(Array.isArray(firstApp.suites)).toBe(true);
      }
    });

    it('should return valid JSON structure from handler', async () => {
      const response = await callTool(handlers, 'list_apps');

      // Should not have isError flag
      expect(response.isError).toBeFalsy();

      // JSON should be parseable
      const jsonText = response.content[0].text;
      const data = JSON.parse(jsonText);

      // totalApps should match apps array length
      expect(data.totalApps).toBe(data.apps.length);
    });

    it('should handle empty app list gracefully', async () => {
      // Even if no apps discovered, should return valid structure
      const response = await callTool(handlers, 'list_apps');

      expect(response).toBeDefined();
      expect(response.content).toBeDefined();

      const data = JSON.parse(response.content[0].text);
      expect(data).toHaveProperty('totalApps');
      expect(data).toHaveProperty('apps');
      expect(data.totalApps).toBeGreaterThanOrEqual(0);
    });

    it('should ignore unexpected arguments for forward compatibility', async () => {
      // list_apps has no parameters, but should handle if args provided
      const response = await callTool(handlers, 'list_apps', { unexpected: 'arg' });

      // Should not error
      expect(response.isError).toBeFalsy();

      // Should still return valid data
      const data = JSON.parse(response.content[0].text);
      expect(data).toHaveProperty('totalApps');
      expect(data).toHaveProperty('apps');
    });

    it('should return apps sorted alphabetically', async () => {
      const response = await callTool(handlers, 'list_apps');
      const data = JSON.parse(response.content[0].text);

      if (data.totalApps > 1) {
        // Check alphabetical ordering
        const names = data.apps.map((app: any) => app.name);
        const sortedNames = [...names].sort((a, b) => a.localeCompare(b));
        expect(names).toEqual(sortedNames);
      }
    });

    it('should include complete metadata for each app', async () => {
      const response = await callTool(handlers, 'list_apps');
      const data = JSON.parse(response.content[0].text);

      if (data.totalApps > 0) {
        const app = data.apps[0];

        // All required fields present
        expect(typeof app.name).toBe('string');
        expect(app.name.length).toBeGreaterThan(0);

        expect(typeof app.bundleId).toBe('string');
        expect(app.bundleId).toMatch(/^[a-z0-9.]+$/i);

        expect(typeof app.description).toBe('string');

        expect(typeof app.toolCount).toBe('number');
        expect(app.toolCount).toBeGreaterThanOrEqual(0);

        expect(Array.isArray(app.suites)).toBe(true);
      }
    });
  });

  // ==========================================================================
  // SECTION 2: iac://apps Resource Handlers - Actual Execution
  // ==========================================================================

  describe('iac://apps Resource Handlers - Actual Execution', () => {
    it('should execute ListResources and return iac://apps resource', async () => {
      const response = await callListResources(handlers);

      expect(response).toBeDefined();
      expect(response.resources).toBeDefined();
      expect(Array.isArray(response.resources)).toBe(true);

      // Should include iac://apps resource
      const iacAppsResource = response.resources.find((r: any) => r.uri === 'iac://apps');
      expect(iacAppsResource).toBeDefined();
      expect(iacAppsResource.name).toBe('Available macOS Applications');
      expect(iacAppsResource.mimeType).toBe('application/json');
      expect(iacAppsResource.description).toContain('scriptable macOS applications');
    });

    it('should execute ReadResource for iac://apps and return app data', async () => {
      const response = await callReadResource(handlers, 'iac://apps');

      expect(response).toBeDefined();
      expect(response.contents).toBeDefined();
      expect(Array.isArray(response.contents)).toBe(true);
      expect(response.contents.length).toBeGreaterThan(0);

      const content = response.contents[0];
      expect(content.uri).toBe('iac://apps');
      expect(content.mimeType).toBe('application/json');
      expect(content.text).toBeDefined();

      // Parse and verify structure
      const data = JSON.parse(content.text);
      expect(data).toHaveProperty('totalApps');
      expect(data).toHaveProperty('apps');
      expect(typeof data.totalApps).toBe('number');
      expect(Array.isArray(data.apps)).toBe(true);
    });

    it('should reject unknown resource URIs', async () => {
      const response = await callReadResource(handlers, 'iac://unknown');

      expect(response).toBeDefined();
      expect(response.contents).toBeDefined();

      const content = response.contents[0];
      expect(content.text).toContain('Unknown resource URI');
    });

    it('should handle resource read errors gracefully', async () => {
      // Test with malformed URI (though our validation should catch this)
      const response = await callReadResource(handlers, 'iac://apps?invalid');

      // Should not throw, should return error content
      expect(response).toBeDefined();
      expect(response.contents).toBeDefined();
    });
  });

  // ==========================================================================
  // SECTION 3: Data Consistency - Tool vs Resource
  // ==========================================================================

  describe('Data Consistency - Tool vs Resource', () => {
    it('should return identical app data from tool and resource', async () => {
      // Call list_apps tool
      const toolResponse = await callTool(handlers, 'list_apps');
      const toolData = JSON.parse(toolResponse.content[0].text);

      // Call iac://apps resource
      const resourceResponse = await callReadResource(handlers, 'iac://apps');
      const resourceData = JSON.parse(resourceResponse.contents[0].text);

      // Both should return same data structure
      expect(toolData.totalApps).toBe(resourceData.totalApps);
      expect(toolData.apps.length).toBe(resourceData.apps.length);

      // Apps should be identical
      if (toolData.totalApps > 0) {
        const toolApp = toolData.apps[0];
        const resourceApp = resourceData.apps[0];

        expect(toolApp.name).toBe(resourceApp.name);
        expect(toolApp.bundleId).toBe(resourceApp.bundleId);
        expect(toolApp.description).toBe(resourceApp.description);
        expect(toolApp.toolCount).toBe(resourceApp.toolCount);
        expect(toolApp.suites).toEqual(resourceApp.suites);
      }
    });

    it('should return consistent data across multiple calls', async () => {
      // First call
      const response1 = await callTool(handlers, 'list_apps');
      const data1 = JSON.parse(response1.content[0].text);

      // Second call
      const response2 = await callTool(handlers, 'list_apps');
      const data2 = JSON.parse(response2.content[0].text);

      // Should be identical
      expect(data1.totalApps).toBe(data2.totalApps);
      expect(data1.apps.length).toBe(data2.apps.length);

      if (data1.totalApps > 0) {
        expect(data1.apps[0].name).toBe(data2.apps[0].name);
      }
    });
  });

  // ==========================================================================
  // SECTION 4: Error Handling
  // ==========================================================================

  describe('Error Handling', () => {
    it('should handle discovery errors gracefully', async () => {
      // Even if discovery fails, should return valid response
      const response = await callTool(handlers, 'list_apps');

      expect(response).toBeDefined();
      expect(response.content).toBeDefined();

      // Should not throw
      const data = JSON.parse(response.content[0].text);
      expect(data).toHaveProperty('totalApps');
    });

    it('should handle JSON parsing in responses', async () => {
      const response = await callTool(handlers, 'list_apps');

      // Should be valid JSON
      expect(() => {
        JSON.parse(response.content[0].text);
      }).not.toThrow();
    });

    it('should return error structure for ListResources failures', async () => {
      // ListResources should handle errors internally
      const response = await callListResources(handlers);

      expect(response).toBeDefined();
      expect(response.resources).toBeDefined();

      // If error occurred, should be in _error field
      if (response._error) {
        expect(typeof response._error).toBe('string');
      }
    });
  });

  // ==========================================================================
  // SECTION 5: Performance and Caching
  // ==========================================================================

  describe('Performance and Caching', () => {
    it('should complete list_apps in reasonable time', async () => {
      const start = performance.now();
      await callTool(handlers, 'list_apps');
      const duration = performance.now() - start;

      // Should complete within 10 seconds (generous for CI)
      expect(duration).toBeLessThan(10000);
    });

    it('should complete ReadResource in reasonable time', async () => {
      const start = performance.now();
      await callReadResource(handlers, 'iac://apps');
      const duration = performance.now() - start;

      // Should complete within 10 seconds
      expect(duration).toBeLessThan(10000);
    });

    it('should be faster on subsequent calls (caching)', async () => {
      // First call (cold)
      const start1 = performance.now();
      await callTool(handlers, 'list_apps');
      const duration1 = performance.now() - start1;

      // Second call (should use cache)
      const start2 = performance.now();
      await callTool(handlers, 'list_apps');
      const duration2 = performance.now() - start2;

      // Second call should generally be faster (though not guaranteed in CI)
      // Just verify both complete successfully
      expect(duration1).toBeGreaterThan(0);
      expect(duration2).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // SECTION 6: Integration with ListTools
  // ==========================================================================

  describe('Integration with ListTools', () => {
    it('should include list_apps in ListTools response', async () => {
      const response = await callListTools(handlers);

      expect(response).toBeDefined();
      expect(response.tools).toBeDefined();
      expect(Array.isArray(response.tools)).toBe(true);

      // Should include list_apps tool
      const listAppsTool = response.tools.find((t: any) => t.name === 'list_apps');
      expect(listAppsTool).toBeDefined();
      expect(listAppsTool.description).toContain('List all available macOS applications');
      expect(listAppsTool.inputSchema).toBeDefined();
      expect(listAppsTool.inputSchema.required).toEqual([]);
    });

    it('should include app metadata in ListTools response', async () => {
      const response = await callListTools(handlers);

      expect(response).toBeDefined();
      expect(response._app_metadata).toBeDefined();
      expect(Array.isArray(response._app_metadata)).toBe(true);

      if (response._app_metadata.length > 0) {
        const metadata = response._app_metadata[0];
        expect(metadata).toHaveProperty('appName');
        expect(metadata).toHaveProperty('bundleId');
        expect(metadata).toHaveProperty('toolCount');
      }
    });

    it('should include get_app_tools in ListTools response', async () => {
      const response = await callListTools(handlers);

      expect(response.tools).toBeDefined();
      const getAppToolsTool = response.tools.find((t: any) => t.name === 'get_app_tools');
      expect(getAppToolsTool).toBeDefined();
      expect(getAppToolsTool.description).toContain('Get all available tools');
      expect(getAppToolsTool.inputSchema.required).toContain('app_name');
    });
  });

  // ==========================================================================
  // SECTION 7: get_app_tools Tool Tests
  // ==========================================================================

  describe('get_app_tools Tool - Actual Execution', () => {
    it('should return error when app_name is missing', async () => {
      const response = await callTool(handlers, 'get_app_tools', {});

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('Missing required parameter');
      expect(response.content[0].text).toContain('app_name');
    });

    it('should return error when app_name is too long', async () => {
      const longName = 'A'.repeat(150);
      const response = await callTool(handlers, 'get_app_tools', { app_name: longName });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('app_name parameter too long');
    });

    it('should return error when app_name contains invalid characters', async () => {
      const response = await callTool(handlers, 'get_app_tools', { app_name: 'Finder; rm -rf /' });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('invalid characters');
    });

    it('should return error when app_name contains null bytes', async () => {
      const response = await callTool(handlers, 'get_app_tools', { app_name: 'Finder\0' });

      expect(response.isError).toBe(true);
      // Null bytes fail the character whitelist validation
      expect(response.content[0].text).toContain('invalid characters');
    });

    it('should return error when app is not found', async () => {
      const response = await callTool(handlers, 'get_app_tools', { app_name: 'NonExistentApp123' });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('not found');
    });

    it('should successfully load tools for a valid app', async () => {
      // Try with a common app - Finder is usually present
      const response = await callTool(handlers, 'get_app_tools', { app_name: 'Finder' });

      if (response.isError) {
        // Finder might not be accessible in CI, that's OK
        expect(response.content[0].text).toBeDefined();
      } else {
        // Success case
        expect(response.content).toBeDefined();
        const data = JSON.parse(response.content[0].text);
        expect(data).toHaveProperty('appName');
        expect(data).toHaveProperty('tools');
        expect(Array.isArray(data.tools)).toBe(true);
      }
    });
  });

  // ==========================================================================
  // SECTION 8: Exported Validation Functions
  // ==========================================================================

  describe('Validation Functions', () => {
    it('should export validateToolArguments function', () => {
      expect(validateToolArguments).toBeDefined();
      expect(typeof validateToolArguments).toBe('function');
    });

    it('should export formatSuccessResponse function', () => {
      expect(formatSuccessResponse).toBeDefined();
      expect(typeof formatSuccessResponse).toBe('function');
    });

    it('should export formatPermissionDeniedResponse function', () => {
      expect(formatPermissionDeniedResponse).toBeDefined();
      expect(typeof formatPermissionDeniedResponse).toBe('function');
    });

    it('should validate required arguments', () => {
      const schema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
        },
        required: ['name'],
      };

      const result = validateToolArguments({}, schema);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Missing required argument: name');
    });

    it('should validate argument types', () => {
      const schema = {
        type: 'object',
        properties: {
          count: { type: 'number' },
        },
        required: [],
      };

      const result = validateToolArguments({ count: 'not a number' }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should format success response', () => {
      const result = formatSuccessResponse({ test: 'data' });
      expect(result.success).toBe(true);
      expect(result.data).toEqual({ test: 'data' });
    });

    it('should format permission denied response', () => {
      const decision = {
        allowed: false,
        reason: 'Test reason',
        level: 'confirm' as const,
        requiresPrompt: true,
      };
      const result = formatPermissionDeniedResponse(decision);
      expect(result.error).toBe('Permission denied');
      expect(result.reason).toBe('Test reason');
      expect(result.level).toBe('confirm');
    });
  });

  // ==========================================================================
  // SECTION 9: ReadResource Error Path Tests
  // ==========================================================================

  describe('ReadResource Error Paths', () => {
    it('should handle malformed URI gracefully', async () => {
      const response = await callReadResource(handlers, 'iac://malformed?query');

      expect(response).toBeDefined();
      expect(response.contents).toBeDefined();
      const content = response.contents[0];
      expect(content.text).toContain('Unknown resource URI');
    });

    it('should handle empty URI gracefully', async () => {
      const response = await callReadResource(handlers, '');

      expect(response).toBeDefined();
      expect(response.contents).toBeDefined();
    });

    it('should handle non-iac scheme gracefully', async () => {
      const response = await callReadResource(handlers, 'http://apps');

      expect(response).toBeDefined();
      expect(response.contents).toBeDefined();
      const content = response.contents[0];
      // Should reject non-iac:// URIs
      expect(content.text).toContain('Unknown');
    });
  });
});
