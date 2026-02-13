/**
 * Integration Tests for System Events MCP Integration
 *
 * Tests the MCP server integration for System Events UI automation tools:
 * - All 6 System Events tools appear in ListTools response
 * - CallTool routes correctly with parameter validation
 * - CallTool routes to SystemEventsExecutor for valid parameters
 * - Error handling when executor is not configured or throws
 *
 * Uses IACMCPServer with disableJxaExecution: true so no real JXA runs.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { IACMCPServer } from '../../src/mcp/server.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ToolGenerator } from '../../src/jitd/tool-generator/generator.js';
import { PermissionChecker } from '../../src/permissions/permission-checker.js';
import { MacOSAdapter } from '../../src/adapters/macos/macos-adapter.js';
import { ErrorHandler } from '../../src/error-handler.js';
import { PerAppCache } from '../../src/jitd/cache/per-app-cache.js';
import { QueryExecutor } from '../../src/execution/query-executor.js';
import { ReferenceStore } from '../../src/execution/reference-store.js';
import { setupHandlers } from '../../src/mcp/handlers.js';

/**
 * The 6 System Events tool names that should appear in ListTools.
 */
const SYSTEM_EVENTS_TOOL_NAMES = [
  'iac_mcp_activate_app',
  'iac_mcp_ui_snapshot',
  'iac_mcp_click_menu',
  'iac_mcp_send_keystroke',
  'iac_mcp_click_element',
  'iac_mcp_set_value',
];

describe('System Events MCP Integration', () => {
  let server: IACMCPServer;

  beforeEach(async () => {
    server = new IACMCPServer({ enableLogging: false, disableJxaExecution: true });
    await server.initialize();
  });

  afterEach(async () => {
    try {
      await server.stop();
    } catch {
      // Server may not have been started in all tests
    }
  });

  describe('ListTools Integration', () => {
    it('should include system events tools in ListTools response', async () => {
      const response = await server.handleRequest({
        method: 'tools/list',
        params: {},
      });
      const tools = response.tools as MCPTool[];

      for (const toolName of SYSTEM_EVENTS_TOOL_NAMES) {
        const tool = tools.find(t => t.name === toolName);
        expect(tool, `Expected tool "${toolName}" to be present in ListTools`).toBeDefined();
      }

      // Verify exactly 6 system events tools
      const seTools = tools.filter(t => SYSTEM_EVENTS_TOOL_NAMES.includes(t.name));
      expect(seTools).toHaveLength(6);
    });
  });

  describe('CallTool routing - parameter validation', () => {
    it('should reject iac_mcp_activate_app with missing app parameter', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_activate_app',
          arguments: {},
        },
      });

      expect(response.isError).toBe(true);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(result.error).toBe('invalid_parameter');
    });

    it('should reject iac_mcp_ui_snapshot with missing app parameter', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_ui_snapshot',
          arguments: {},
        },
      });

      expect(response.isError).toBe(true);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(result.error).toBe('invalid_parameter');
    });

    it('should reject iac_mcp_click_menu with missing parameters', async () => {
      // Missing both app and menu_path
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_click_menu',
          arguments: {},
        },
      });

      expect(response.isError).toBe(true);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(result.error).toBe('invalid_parameter');
    });

    it('should reject iac_mcp_send_keystroke with missing parameters', async () => {
      // Missing both app and key
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_send_keystroke',
          arguments: {},
        },
      });

      expect(response.isError).toBe(true);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(result.error).toBe('invalid_parameter');
    });

    it('should reject iac_mcp_click_element with missing ref parameter', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_click_element',
          arguments: {},
        },
      });

      expect(response.isError).toBe(true);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(result.error).toBe('invalid_parameter');
    });

    it('should reject iac_mcp_set_value with missing parameters', async () => {
      // Missing both ref and value
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_set_value',
          arguments: {},
        },
      });

      expect(response.isError).toBe(true);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(result.error).toBe('invalid_parameter');
    });
  });

  describe('CallTool routing - execution', () => {
    it('should route iac_mcp_activate_app to SystemEventsExecutor', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_activate_app',
          arguments: { app: 'Calendar' },
        },
      });

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      // With disableJxaExecution, executor returns mock success
      expect(result.success).toBe(true);
      expect(result.app).toBe('Calendar');
    });

    it('should route iac_mcp_ui_snapshot to SystemEventsExecutor', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_ui_snapshot',
          arguments: { app: 'Calendar', max_depth: 2 },
        },
      });

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      // With disableJxaExecution, executor returns empty windows
      expect(result.app).toBe('Calendar');
      expect(result.windows).toBeDefined();
      expect(Array.isArray(result.windows)).toBe(true);
    });

    it('should route iac_mcp_click_menu to SystemEventsExecutor', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_click_menu',
          arguments: { app: 'Calendar', menu_path: 'View > Go to Today' },
        },
      });

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      // With disableJxaExecution, executor returns mock success
      expect(result.success).toBe(true);
    });

    it('should route iac_mcp_send_keystroke to SystemEventsExecutor', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_send_keystroke',
          arguments: { app: 'Calendar', key: 'n', modifiers: ['cmd'] },
        },
      });

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      // With disableJxaExecution, executor returns mock success
      expect(result.success).toBe(true);
    });

    it('should route iac_mcp_click_element to SystemEventsExecutor', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_click_element',
          arguments: { ref: 'ref_00000000-0000-0000-0000-000000000000' },
        },
      });

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      // With disableJxaExecution and non-existent ref, executor should return error
      // The executor tries to look up the ref in the ReferenceStore and fails
      expect(result.success).toBe(false);
    });

    it('should route iac_mcp_set_value to SystemEventsExecutor', async () => {
      const response = await server.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_set_value',
          arguments: { ref: 'ref_00000000-0000-0000-0000-000000000000', value: 'test' },
        },
      });

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      // With disableJxaExecution and non-existent ref, executor should return error
      expect(result.success).toBe(false);
    });
  });

  describe('Error handling', () => {
    it('should handle when systemEventsExecutor is not configured', async () => {
      // Create a raw MCP server and call setupHandlers without systemEventsExecutor
      const rawServer = new Server(
        { name: 'test-server', version: '0.1.0' },
        { capabilities: { tools: {}, resources: {} } }
      );

      const generator = new ToolGenerator({ strictValidation: true, namingStrategy: 'app_prefix' });
      const permissionChecker = new PermissionChecker();
      const adapter = new MacOSAdapter({ timeoutMs: 5000, enableLogging: false });
      const errorHandler = new ErrorHandler();
      const perAppCache = new PerAppCache('/tmp/iac-test-cache');
      const referenceStore = new ReferenceStore(15 * 60 * 1000);
      const queryExecutor = new QueryExecutor(referenceStore);

      // Setup handlers WITHOUT systemEventsExecutor (pass undefined)
      await setupHandlers(
        rawServer,
        generator,
        permissionChecker,
        adapter,
        errorHandler,
        perAppCache,
        queryExecutor,
        undefined // No systemEventsExecutor
      );

      // Access the handler directly via the server's internal _requestHandlers
      const callToolHandler = (rawServer as unknown as {
        _requestHandlers: Map<string, (request: unknown) => Promise<unknown>>;
      })._requestHandlers?.get('tools/call');

      expect(callToolHandler).toBeDefined();

      // Call each system events tool and verify "not configured" error
      for (const toolName of SYSTEM_EVENTS_TOOL_NAMES) {
        // Build valid arguments for each tool
        let args: Record<string, unknown>;
        switch (toolName) {
          case 'iac_mcp_activate_app':
            args = { app: 'Calendar' };
            break;
          case 'iac_mcp_ui_snapshot':
            args = { app: 'Calendar' };
            break;
          case 'iac_mcp_click_menu':
            args = { app: 'Calendar', menu_path: 'File > New' };
            break;
          case 'iac_mcp_send_keystroke':
            args = { app: 'Calendar', key: 'n' };
            break;
          case 'iac_mcp_click_element':
            args = { ref: 'ref_test' };
            break;
          case 'iac_mcp_set_value':
            args = { ref: 'ref_test', value: 'hello' };
            break;
          default:
            args = {};
        }

        const response = await callToolHandler!({
          method: 'tools/call',
          params: { name: toolName, arguments: args },
        }) as { content: Array<{ text: string }>; isError?: boolean };

        expect(response.isError, `Expected isError for "${toolName}" when executor not configured`).toBe(true);
        const result = JSON.parse(response.content[0].text);
        expect(result.error).toBe('system_events_not_available');
        expect(result.message).toContain('System Events executor not configured');
      }
    });

    it('should handle executor throwing errors', async () => {
      // Create server normally, but spy on the executor methods to throw
      const testServer = new IACMCPServer({ enableLogging: false, disableJxaExecution: true });
      await testServer.initialize();

      // Access the internal systemEventsExecutor and mock it to throw
      const executor = (testServer as unknown as { systemEventsExecutor: { activateApp: () => Promise<unknown> } }).systemEventsExecutor;
      const originalActivateApp = executor.activateApp.bind(executor);

      // Replace activateApp to throw an error
      executor.activateApp = vi.fn().mockRejectedValue(new Error('Simulated executor failure'));

      const response = await testServer.handleRequest({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_activate_app',
          arguments: { app: 'Calendar' },
        },
      });

      expect(response.isError).toBe(true);
      const result = JSON.parse((response.content as Array<{ text: string }>)[0].text);
      expect(result.success).toBe(false);
      expect(result.error).toContain('Simulated executor failure');

      // Restore original
      executor.activateApp = originalActivateApp;
    });
  });
});
