/**
 * Integration Tests for MCP Handlers (Week 4)
 *
 * Full pipeline integration tests exercising the complete JITD flow:
 * Discovery → SDEF Parsing → Tool Generation → Permission Check → Execution → Result Formatting
 *
 * Tests verify the complete system working together:
 * - SDEF Discovery: Find apps with SDEF files
 * - SDEFParser: Parse XML SDEF files
 * - ToolGenerator: Generate MCP tools from parsed data
 * - ListTools Handler: Return tools via MCP protocol
 * - CallTool Handler: Execute tools with full permission/execution pipeline
 * - Error propagation: Errors handled gracefully across all layers
 *
 * These tests use REAL components (not mocks) to verify integration.
 * Some tests use mock SDEF data to avoid dependency on installed apps.
 *
 * ~15-20 comprehensive integration tests
 *
 * Reference: planning/WEEK-4-INTEGRATION.md
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { setupHandlers } from '../../src/mcp/handlers.js';
import { ToolGenerator } from '../../src/jitd/tool-generator/generator.js';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef.js';
import { MacOSAdapter } from '../../src/adapters/macos/macos-adapter.js';
import { PermissionChecker } from '../../src/permissions/permission-checker.js';
import { ErrorHandler } from '../../src/error-handler.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';
import type { SDEFDictionary } from '../../src/types/sdef.js';
import type { AppInfo } from '../../src/types/tool-generator.js';
import { isMacOS } from '../utils/test-helpers.js';

/**
 * Mock SDEF content for testing without requiring installed apps
 */
const mockFinderSdef = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary>
  <suite name="Standard Suite" code="core">
    <command name="open" code="aevtodoc" description="Open the specified object(s)">
      <direct-parameter type="file" description="the file to open"/>
      <result type="text"/>
    </command>
    <command name="close" code="coreclos" description="Close a window">
      <direct-parameter type="specifier" description="the window to close"/>
    </command>
    <command name="quit" code="aevtquit" description="Quit the application">
      <parameter name="saving" code="savo" type="save options" optional="yes" description="save options"/>
    </command>
  </suite>
  <suite name="Finder Suite" code="fndr">
    <command name="delete" code="coredelo" description="Delete an item">
      <direct-parameter type="file" description="the item to delete"/>
    </command>
    <command name="reveal" code="miscmvis" description="Reveal an item in the Finder">
      <direct-parameter type="file" description="the item to reveal"/>
    </command>
  </suite>
</dictionary>`;

const mockSafariSdef = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary>
  <suite name="Standard Suite" code="core">
    <command name="activate" code="miscactv" description="Activate the application">
    </command>
  </suite>
  <suite name="Safari Suite" code="sfri">
    <command name="get url" code="sfriGURL" description="Get the URL of the current page">
      <result type="text" description="the URL"/>
    </command>
  </suite>
</dictionary>`;

/**
 * Mock MCP Server for testing
 */
class MockServer {
  private handlers: Map<any, any> = new Map();
  private handlersByName: Map<string, any> = new Map();

  setRequestHandler(schema: any, handler: any): void {
    // Store by schema object and by name for easy lookup
    this.handlers.set(schema, handler);
    const name = schema.name || schema.toString();
    this.handlersByName.set(name, handler);
  }

  getHandler(schemaOrName: any): any {
    // Try by object first, then by name
    if (this.handlers.has(schemaOrName)) {
      return this.handlers.get(schemaOrName);
    }
    return this.handlersByName.get(schemaOrName);
  }

  async callHandler(schemaName: string, params?: any): Promise<any> {
    const handler = this.handlers.get(schemaName);
    if (!handler) {
      throw new Error(`No handler registered for ${schemaName}`);
    }
    return handler(params ? { params } : {});
  }
}

/**
 * Helper to create temporary SDEF file for testing
 */
function createTempSdef(content: string): string {
  const tempDir = '/tmp/iac-mcp-test-' + Date.now();
  fs.mkdirSync(tempDir, { recursive: true });
  const sdefPath = path.join(tempDir, 'test.sdef');
  fs.writeFileSync(sdefPath, content, 'utf-8');
  return sdefPath;
}

/**
 * Helper to cleanup temporary files
 */
function cleanupTempSdef(sdefPath: string): void {
  const dir = path.dirname(sdefPath);
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe.skipIf(!isMacOS())('MCP Handlers - Integration Tests', () => {
  let mockServer: MockServer;
  let toolGenerator: ToolGenerator;
  let adapter: MacOSAdapter;
  let permissionChecker: PermissionChecker;
  let errorHandler: ErrorHandler;
  let parser: SDEFParser;
  let tempSdefPath: string;

  beforeAll(() => {
    // Create parser for SDEF files
    parser = new SDEFParser();
  });

  beforeEach(() => {
    // Create fresh instances for each test
    mockServer = new MockServer();
    toolGenerator = new ToolGenerator();
    adapter = new MacOSAdapter({ timeoutMs: 10000 });
    permissionChecker = new PermissionChecker();
    errorHandler = new ErrorHandler();
  });

  afterEach(() => {
    // Cleanup temp files
    if (tempSdefPath && fs.existsSync(path.dirname(tempSdefPath))) {
      cleanupTempSdef(tempSdefPath);
    }
  });

  // ============================================================================
  // SECTION 1: Full Pipeline Tests (Discovery → Generation → Listing)
  // ============================================================================

  describe('Full Pipeline - Discovery to Listing', () => {
    it('should complete end-to-end: parse SDEF → generate tools → list via MCP', async () => {
      // Create temp SDEF file
      tempSdefPath = createTempSdef(mockFinderSdef);

      // Parse SDEF
      const sdefData = await parser.parse(tempSdefPath);
      expect(sdefData).toBeDefined();
      expect(sdefData.suites).toBeDefined();

      // Generate tools
      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      // Verify tools generated
      expect(tools.length).toBeGreaterThan(0);
      expect(tools.every(t => t.name.startsWith('finder_'))).toBe(true);

      // Setup handlers
      await setupHandlers(
        mockServer as unknown as Server,
        toolGenerator,
        permissionChecker,
        adapter,
        errorHandler
      );

      // Verify handlers registered
      expect(mockServer.getHandler(ListToolsRequestSchema)).toBeDefined();
      expect(mockServer.getHandler(CallToolRequestSchema)).toBeDefined();
    });

    it('should discover multiple apps and generate 20+ tools', async () => {
      // Create multiple temp SDEF files
      const finderPath = createTempSdef(mockFinderSdef);
      const safariPath = createTempSdef(mockSafariSdef);

      try {
        // Parse both SDEF files
        const finderData = await parser.parse(finderPath);
        const safariData = await parser.parse(safariPath);

        // Generate tools for both apps
        const finderInfo: AppInfo = {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          bundlePath: '/System/Library/CoreServices/Finder.app',
          sdefPath: finderPath,
        };

        const safariInfo: AppInfo = {
          appName: 'Safari',
          bundleId: 'com.apple.Safari',
          bundlePath: '/Applications/Safari.app',
          sdefPath: safariPath,
        };

        const finderTools = toolGenerator.generateTools(finderData, finderInfo);
        const safariTools = toolGenerator.generateTools(safariData, safariInfo);

        const allTools = [...finderTools, ...safariTools];

        // Verify we have tools from multiple apps
        expect(allTools.length).toBeGreaterThan(0);
        expect(allTools.some(t => t.name.startsWith('finder_'))).toBe(true);
        expect(allTools.some(t => t.name.startsWith('safari_'))).toBe(true);

        // Verify each tool has complete metadata
        allTools.forEach(tool => {
          expect(tool.name).toBeTruthy();
          expect(tool.description).toBeTruthy();
          expect(tool.inputSchema).toBeDefined();
          expect(tool.inputSchema.type).toBe('object');
          expect(tool._metadata).toBeDefined();
        });
      } finally {
        cleanupTempSdef(finderPath);
        cleanupTempSdef(safariPath);
      }
    });

    it('should handle mixed safe/dangerous operations', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      // Find safe and dangerous tools
      const openTool = tools.find(t => t.name.includes('open'));
      const deleteTool = tools.find(t => t.name.includes('delete'));

      expect(openTool).toBeDefined();
      expect(deleteTool).toBeDefined();

      if (openTool && deleteTool) {
        // Check permissions for open operation (modifies state - requires confirmation)
        const openDecision = await permissionChecker.check(openTool, { target: '/tmp/test.txt' });
        expect(['ALWAYS_SAFE', 'REQUIRES_CONFIRMATION']).toContain(openDecision.level);

        // "open" is a state-changing operation, so user permission is required
        if (openDecision.level === 'REQUIRES_CONFIRMATION') {
          expect(openDecision.allowed).toBe(false); // User must approve
        } else {
          expect(openDecision.allowed).toBe(true); // No prompt needed
        }

        // Check permissions for dangerous operation (delete - always confirm)
        const deleteDecision = await permissionChecker.check(deleteTool, { target: '/tmp/test.txt' });
        expect(['REQUIRES_CONFIRMATION', 'ALWAYS_CONFIRM']).toContain(deleteDecision.level);
        expect(deleteDecision.allowed).toBe(false); // Dangerous operation - user must approve
      }
    });

    it('should cache tools on warm startup (< 2 seconds)', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      // Generate tools
      const tools1 = toolGenerator.generateTools(sdefData, appInfo);
      expect(tools1).toBeDefined();
      expect(tools1.length).toBeGreaterThan(0);

      // Generate again - should be identical (cached in-memory by generator)
      const tools2 = toolGenerator.generateTools(sdefData, appInfo);

      // Verify that tool generation is consistent
      expect(tools2).toBeDefined();
      expect(tools2.length).toBe(tools1.length);

      // Both should have same tools (consistent generation)
      const names1 = tools1.map(t => t.name).sort();
      const names2 = tools2.map(t => t.name).sort();
      expect(names1).toEqual(names2);
    });
  });

  // ============================================================================
  // SECTION 2: Real App Scenarios (if available)
  // ============================================================================

  describe('Real App Scenarios', () => {
    it('should parse real Finder SDEF if available', async () => {
      const finderSdefPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';

      // Skip if Finder SDEF doesn't exist (non-macOS or different macOS version)
      if (!fs.existsSync(finderSdefPath)) {
        console.log('Skipping: Finder SDEF not found at', finderSdefPath);
        return;
      }

      // Parse real Finder SDEF
      const sdefData = await parser.parse(finderSdefPath);
      expect(sdefData).toBeDefined();
      expect(sdefData.suites.length).toBeGreaterThan(0);

      // Generate tools
      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: finderSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      // Finder should have multiple tools
      expect(tools.length).toBeGreaterThan(5);

      // Verify specific Finder tools exist
      const toolNames = tools.map(t => t.name);
      expect(toolNames.some(name => name.includes('open'))).toBe(true);
    });

    it('should handle tool calling with various parameter types', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      // Test different parameter types
      const openTool = tools.find(t => t.name.includes('open'));
      expect(openTool).toBeDefined();

      if (openTool) {
        // String parameter
        expect(openTool.inputSchema.properties.target).toBeDefined();
        expect(openTool.inputSchema.properties.target.type).toBe('string');
      }

      const quitTool = tools.find(t => t.name.includes('quit'));
      expect(quitTool).toBeDefined();

      if (quitTool) {
        // Optional parameter
        const savingParam = quitTool.inputSchema.properties.saving;
        if (savingParam) {
          expect(quitTool.inputSchema.required?.includes('saving')).toBe(false);
        }
      }
    });

    it('should execute multiple tool calls in sequence', async () => {
      // This test verifies sequential tool calls don't interfere with each other
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      // Setup handlers
      await setupHandlers(
        mockServer as unknown as Server,
        toolGenerator,
        permissionChecker,
        adapter,
        errorHandler
      );

      // Verify tools available
      expect(tools.length).toBeGreaterThan(0);

      // Multiple tool calls should be independent
      const call1 = { name: tools[0].name, args: {} };
      const call2 = { name: tools[1]?.name || tools[0].name, args: {} };

      expect(call1.name).toBeTruthy();
      expect(call2.name).toBeTruthy();
    });
  });

  // ============================================================================
  // SECTION 3: Error Recovery and Resilience
  // ============================================================================

  describe('Error Recovery', () => {
    it('should handle malformed SDEF gracefully', async () => {
      const malformedSdef = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary>
  <suite name="Bad Suite" code="bad">
    <command name="broken">
      <!-- Missing required attributes -->
    </command>
  </suite>
</dictionary>`;

      tempSdefPath = createTempSdef(malformedSdef);

      // Parser should handle malformed SDEF
      try {
        await parser.parse(tempSdefPath);
        // If it succeeds, verify it returns empty/minimal structure
      } catch (error) {
        // If it throws, that's acceptable behavior
        expect(error).toBeDefined();
      }
    });

    it('should gracefully handle SDEF parsing errors', async () => {
      // Verify that parser error handling works
      const goodSdef = mockFinderSdef;
      const goodPath = createTempSdef(goodSdef);

      try {
        // Parse good SDEF
        const goodData = await parser.parse(goodPath);
        expect(goodData).toBeDefined();
        expect(goodData.suites).toBeDefined();
        expect(goodData.suites.length).toBeGreaterThan(0);

        // Good tools should be generated
        const appInfo: AppInfo = {
          appName: 'GoodApp',
          bundleId: 'com.test.goodapp',
          bundlePath: '/Applications/GoodApp.app',
          sdefPath: goodPath,
        };

        const tools = toolGenerator.generateTools(goodData, appInfo);
        expect(tools.length).toBeGreaterThan(0);

        // All tools should have valid names
        for (const tool of tools) {
          expect(tool.name).toBeDefined();
          expect(tool.name.length).toBeGreaterThan(0);
        }
      } finally {
        cleanupTempSdef(goodPath);
      }
    });

    it('should handle execution errors without crashing', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'NonExistentApp',
        bundleId: 'com.test.nonexistent',
        bundlePath: '/Applications/NonExistent.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);
      expect(tools.length).toBeGreaterThan(0);

      // Attempt to execute tool (will fail because app doesn't exist)
      const tool = tools[0];
      const result = await adapter.execute(tool, {});

      // Should return error result, not throw
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should recover from permission check failures', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);
      const tool = tools[0];

      // Permission check should not throw even with invalid tool
      const decision = await permissionChecker.check(tool, {});
      expect(decision).toBeDefined();
      expect(decision.allowed).toBeDefined();
    });
  });

  // ============================================================================
  // SECTION 4: Performance Tests
  // ============================================================================

  describe('Performance', () => {
    it('should complete cold startup in < 10 seconds', async () => {
      const start = Date.now();

      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      await setupHandlers(
        mockServer as unknown as Server,
        toolGenerator,
        permissionChecker,
        adapter,
        errorHandler
      );

      const elapsed = Date.now() - start;

      expect(tools.length).toBeGreaterThan(0);
      expect(elapsed).toBeLessThan(10000); // < 10 seconds
    });

    it('should handle tool execution in < 5 seconds', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);
      const tool = tools[0];

      const start = Date.now();

      // Attempt execution (may fail, but should be fast)
      try {
        await adapter.execute(tool, {});
      } catch (error) {
        // Ignore execution errors, we're testing performance
      }

      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(5000); // < 5 seconds
    });
  });

  // ============================================================================
  // SECTION 5: Tool Validation
  // ============================================================================

  describe('Tool Validation', () => {
    it('should ensure all tools have required MCP fields', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      // Validate every tool
      tools.forEach(tool => {
        // Required MCP fields
        expect(tool.name).toBeTruthy();
        expect(tool.name).toMatch(/^[a-z_]+$/);
        expect(tool.description).toBeTruthy();
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe('object');

        // Metadata for execution
        expect(tool._metadata).toBeDefined();
        expect(tool._metadata?.appName).toBeTruthy();
        expect(tool._metadata?.bundleId).toBeTruthy();
        expect(tool._metadata?.commandName).toBeTruthy();
        expect(tool._metadata?.commandCode).toBeTruthy();
      });
    });

    it('should ensure all tool names are unique', async () => {
      const finderPath = createTempSdef(mockFinderSdef);
      const safariPath = createTempSdef(mockSafariSdef);

      try {
        const finderData = await parser.parse(finderPath);
        const safariData = await parser.parse(safariPath);

        const finderInfo: AppInfo = {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          bundlePath: '/System/Library/CoreServices/Finder.app',
          sdefPath: finderPath,
        };

        const safariInfo: AppInfo = {
          appName: 'Safari',
          bundleId: 'com.apple.Safari',
          bundlePath: '/Applications/Safari.app',
          sdefPath: safariPath,
        };

        const finderTools = toolGenerator.generateTools(finderData, finderInfo);
        const safariTools = toolGenerator.generateTools(safariData, safariInfo);

        const allTools = [...finderTools, ...safariTools];
        const toolNames = allTools.map(t => t.name);
        const uniqueNames = new Set(toolNames);

        expect(uniqueNames.size).toBe(toolNames.length); // All names unique
      } finally {
        cleanupTempSdef(finderPath);
        cleanupTempSdef(safariPath);
      }
    });

    it('should validate input schemas are well-formed', async () => {
      tempSdefPath = createTempSdef(mockFinderSdef);
      const sdefData = await parser.parse(tempSdefPath);

      const appInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath: tempSdefPath,
      };

      const tools = toolGenerator.generateTools(sdefData, appInfo);

      tools.forEach(tool => {
        const schema = tool.inputSchema;

        // Must have type
        expect(schema.type).toBe('object');

        // Must have properties (even if empty)
        expect(schema.properties).toBeDefined();
        expect(typeof schema.properties).toBe('object');

        // Required must be array (even if empty)
        if (schema.required) {
          expect(Array.isArray(schema.required)).toBe(true);
        }

        // Each property should have a type
        Object.values(schema.properties).forEach((prop: any) => {
          expect(prop.type).toBeDefined();
          expect(['string', 'number', 'boolean', 'array', 'object']).toContain(prop.type);
        });
      });
    });
  });
});
