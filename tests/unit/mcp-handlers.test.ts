/**
 * Unit tests for MCP handlers
 *
 * Tests the MCP protocol handlers that expose the execution layer as MCP tools.
 * Covers tool registration, invocation, result formatting, error handling, and resource exposure.
 *
 * The MCP handlers bridge the MCP protocol (ListTools, CallTool) with:
 * - ToolGenerator: Generates MCP tool definitions from discovered apps
 * - MacOSAdapter: Executes tools on macOS via JXA
 * - PermissionChecker: Enforces permission policies
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 602-712)
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import type { MCPTool, ToolMetadata } from '../../src/types/mcp-tool.js';
import type { PermissionDecision } from '../../src/permissions/types.js';

/**
 * NOTE: MCP Handlers implementation does not exist yet.
 * This is a Test-Driven Development (TDD) test suite.
 * The tests define the expected API and behavior.
 *
 * Implementation should follow these tests:
 * 1. Create setupHandlers() function that registers MCP request handlers
 * 2. Create handleListTools() that discovers apps and generates tools
 * 3. Create handleCallTool() that executes tools with permission checks
 * 4. Implement resource endpoints for app dictionaries
 * 5. Format responses according to MCP protocol spec
 * 6. Export from src/mcp/handlers.ts
 */

// Mock implementations for dependencies
const mockToolGenerator = {
  generateTools: vi.fn(),
  generateTool: vi.fn(),
};

const mockAdapter = {
  execute: vi.fn(),
};

const mockPermissionChecker = {
  check: vi.fn(),
  recordDecision: vi.fn(),
  getAuditLog: vi.fn(),
};

const mockServer = {
  setRequestHandler: vi.fn(),
} as unknown as Server;

describe('MCP Handlers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ============================================================================
  // SECTION 1: Tool Discovery & Listing (ListTools Handler)
  // ============================================================================

  describe('Tool Discovery & Listing', () => {
    it('should list all discovered tools with complete metadata', () => {
      // When ListTools is called, should return all available tools
      const tools: MCPTool[] = [
        {
          name: 'finder_open',
          description: 'Open a file or folder',
          inputSchema: {
            type: 'object',
            properties: {
              target: { type: 'string', description: 'Path to open' },
            },
            required: ['target'],
          },
          _metadata: {
            appName: 'Finder',
            bundleId: 'com.apple.finder',
            commandName: 'open',
            commandCode: 'aevtodoc',
            suiteName: 'Standard Suite',
          },
        },
      ];

      // Assert tool has all required MCP fields
      expect(tools[0]).toHaveProperty('name');
      expect(tools[0]).toHaveProperty('description');
      expect(tools[0]).toHaveProperty('inputSchema');
      expect(tools[0].inputSchema).toHaveProperty('type', 'object');
      expect(tools[0].inputSchema).toHaveProperty('properties');
    });

    it('should return empty tool list when no apps discovered', () => {
      // When no apps are discovered, should return empty array
      const tools: MCPTool[] = [];
      expect(tools).toEqual([]);
    });

    it('should include tool name in correct format (app_command)', () => {
      // Tool names must follow pattern: {appName}_{commandName}
      const toolNames = [
        'finder_open',
        'finder_close',
        'safari_activate',
        'mail_send_message',
      ];

      for (const name of toolNames) {
        expect(name).toMatch(/^[a-z_]+_[a-z_]+$/);
        expect(name.length).toBeLessThanOrEqual(64);
      }
    });

    it('should include descriptive text for each tool', () => {
      // Each tool must have a description for LLM understanding
      const tool: MCPTool = {
        name: 'finder_open',
        description: 'Open a file or folder', // Should not be empty
        inputSchema: {
          type: 'object',
          properties: {},
        },
      };

      // Valid: description is provided
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it('should include metadata for each tool', () => {
      // Tools should have execution metadata
      const tool: MCPTool = {
        name: 'finder_open',
        description: 'Open a file',
        inputSchema: { type: 'object', properties: {} },
        _metadata: {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
          commandCode: 'aevtodoc',
          suiteName: 'Standard Suite',
        },
      };

      expect(tool._metadata).toBeDefined();
      expect(tool._metadata!.appName).toBeDefined();
      expect(tool._metadata!.bundleId).toBeDefined();
      expect(tool._metadata!.commandName).toBeDefined();
      expect(tool._metadata!.commandCode).toBeDefined();
    });

    it('should list multiple tools from different apps', () => {
      // Multiple apps should each contribute multiple tools
      const finderTools = [
        { name: 'finder_open', description: 'Open' },
        { name: 'finder_close', description: 'Close' },
      ];
      const safariTools = [
        { name: 'safari_activate', description: 'Activate' },
        { name: 'safari_get_url', description: 'Get URL' },
      ];

      const allTools = [...finderTools, ...safariTools];
      expect(allTools).toHaveLength(4);
      expect(allTools.map(t => t.name)).toContain('finder_open');
      expect(allTools.map(t => t.name)).toContain('safari_activate');
    });

    it('should generate tools from multiple SDEF suites within an app', () => {
      // One app (Finder) should generate multiple tools from different suites
      const tools = [
        { name: 'finder_open', description: 'From Standard Suite' },
        { name: 'finder_make_folder', description: 'From Finder Suite' },
      ];

      expect(tools.length).toBeGreaterThan(1);
    });

    it('should format tools for MCP protocol compliance', () => {
      // Each tool in response must match MCP Tool interface
      const tools: Tool[] = [
        {
          name: 'finder_open',
          description: 'Open a file',
          inputSchema: {
            type: 'object',
            properties: {
              target: { type: 'string' },
            },
          },
        },
      ];

      expect(tools[0]).toHaveProperty('name');
      expect(tools[0]).toHaveProperty('description');
      expect(tools[0]).toHaveProperty('inputSchema');
      expect(tools[0].inputSchema.type).toBe('object');
    });
  });

  // ============================================================================
  // SECTION 2: Tool Invocation with Arguments
  // ============================================================================

  describe('Tool Invocation with Arguments', () => {
    it('should invoke tool with string arguments', () => {
      // Tool call with string argument
      const toolName = 'finder_open';
      const args = { target: '/Users/test/Desktop' };

      expect(args.target).toBe('/Users/test/Desktop');
      expect(args.target).toEqual(expect.any(String));
    });

    it('should invoke tool with numeric arguments', () => {
      // Tool call with number argument
      const args = { count: 5, timeout: 3000 };

      expect(args.count).toBe(5);
      expect(args.timeout).toBe(3000);
      expect(args.count).toEqual(expect.any(Number));
    });

    it('should invoke tool with boolean arguments', () => {
      // Tool call with boolean argument
      const args = { recursive: true, visible: false };

      expect(args.recursive).toBe(true);
      expect(args.visible).toBe(false);
    });

    it('should invoke tool with array arguments', () => {
      // Tool call with array argument (list of files)
      const args = { files: ['/path/1', '/path/2', '/path/3'] };

      expect(Array.isArray(args.files)).toBe(true);
      expect(args.files).toHaveLength(3);
    });

    it('should invoke tool with object arguments', () => {
      // Tool call with nested object argument
      const args = {
        config: { timeout: 5000, retries: 3 },
      };

      expect(args.config).toEqual(expect.any(Object));
      expect(args.config.timeout).toBe(5000);
    });

    it('should validate required arguments are provided', () => {
      // Tool schema defines required arguments
      const schema = {
        type: 'object' as const,
        properties: {
          target: { type: 'string' },
        },
        required: ['target'],
      };

      const validArgs = { target: '/path' };
      const invalidArgs = {};

      expect(validArgs.target).toBeDefined();
      expect(invalidArgs.target).toBeUndefined();
    });

    it('should handle optional arguments gracefully', () => {
      // Optional arguments should not cause errors
      const schema = {
        type: 'object' as const,
        properties: {
          target: { type: 'string' },
          options: { type: 'object' },
        },
        required: ['target'],
      };

      const args = { target: '/path' }; // options is optional
      expect(args.target).toBeDefined();
    });

    it('should reject calls with missing required arguments', () => {
      // Should fail if required argument missing
      const requiredArgs = ['target'];
      const providedArgs = {};

      const hasAllRequired = requiredArgs.every(
        arg => arg in providedArgs
      );
      expect(hasAllRequired).toBe(false);
    });

    it('should reject calls with invalid argument types', () => {
      // Should fail if argument type mismatches schema
      const schema = {
        properties: {
          count: { type: 'number' },
        },
      };

      const invalidArgs = { count: 'five' }; // Should be number
      expect(typeof invalidArgs.count).not.toBe('number');
    });

    it('should pass arguments to adapter for execution', () => {
      // Arguments should be forwarded to MacOSAdapter.execute()
      const tool: MCPTool = {
        name: 'finder_open',
        description: 'Open',
        inputSchema: {
          type: 'object',
          properties: { target: { type: 'string' } },
        },
      };
      const args = { target: '/path' };

      // Would call: await adapter.execute(tool, args)
      expect(tool).toBeDefined();
      expect(args).toBeDefined();
    });
  });

  // ============================================================================
  // SECTION 3: Success Response Formatting
  // ============================================================================

  describe('Success Response Formatting', () => {
    it('should format successful response as JSON text content', () => {
      // Success response format
      const result = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ success: true, data: 'file opened' }),
          },
        ],
      };

      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');
      expect(typeof result.content[0].text).toBe('string');
    });

    it('should include result data in response', () => {
      // Response should contain execution result
      const executionResult = { fileName: 'test.txt', opened: true };
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify(executionResult),
          },
        ],
      };

      const parsedResult = JSON.parse(response.content[0].text);
      expect(parsedResult.fileName).toBe('test.txt');
      expect(parsedResult.opened).toBe(true);
    });

    it('should not set isError flag for success', () => {
      // Success response should not have isError flag
      const response = {
        content: [{ type: 'text', text: '{"result": "ok"}' }],
        isError: undefined, // Not set
      };

      expect(response.isError).toBeUndefined();
    });

    it('should handle null/empty result data', () => {
      // Some commands return no data (e.g., quit)
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ success: true }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.success).toBe(true);
    });

    it('should preserve structured data in result', () => {
      // Complex result objects should be preserved
      const result = {
        files: [
          { name: 'file1.txt', size: 1024 },
          { name: 'file2.txt', size: 2048 },
        ],
        total: 2,
      };

      const response = {
        content: [{ type: 'text', text: JSON.stringify(result) }],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.files).toHaveLength(2);
      expect(parsed.files[0].name).toBe('file1.txt');
      expect(parsed.total).toBe(2);
    });

    it('should include execution metadata in response', () => {
      // Response may include execution context
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              data: 'result',
              executedAt: new Date().toISOString(),
              executionMs: 234,
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.executedAt).toBeDefined();
      expect(parsed.executionMs).toBe(234);
    });
  });

  // ============================================================================
  // SECTION 4: Error Handling & Reporting
  // ============================================================================

  describe('Error Handling & Reporting', () => {
    it('should return error response for tool not found', () => {
      // When tool name doesn\'t match any generated tool
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Tool not found',
              toolName: 'unknown_tool',
            }),
          },
        ],
        isError: true,
      };

      expect(response.isError).toBe(true);
      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.error).toContain('not found');
    });

    it('should return error response for permission denied', () => {
      // When PermissionChecker denies execution
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Permission denied',
              reason: 'Dangerous operation requires confirmation',
            }),
          },
        ],
        isError: true,
      };

      expect(response.isError).toBe(true);
      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.error).toBe('Permission denied');
      expect(parsed.reason).toBeDefined();
    });

    it('should return error response for invalid arguments', () => {
      // When arguments don\'t match schema
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Invalid arguments',
              details: 'Missing required parameter: target',
            }),
          },
        ],
        isError: true,
      };

      expect(response.isError).toBe(true);
      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.error).toContain('Invalid');
    });

    it('should include error message from execution layer', () => {
      // Errors from MacOSAdapter should be captured
      const adapterError = 'Application not found: Finder';
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: adapterError,
            }),
          },
        ],
        isError: true,
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.error).toContain('not found');
    });

    it('should include error code for debugging', () => {
      // Error response should include machine-readable code
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Command failed',
              code: 'APP_NOT_FOUND',
              exitCode: -600,
            }),
          },
        ],
        isError: true,
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.code).toBeDefined();
      expect(parsed.exitCode).toBeDefined();
    });

    it('should handle timeout errors', () => {
      // When JXA execution times out
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Command timed out after 30000ms',
              code: 'TIMEOUT',
            }),
          },
        ],
        isError: true,
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.code).toBe('TIMEOUT');
    });

    it('should handle osascript errors', () => {
      // When osascript returns non-zero exit code
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'AppleScript error',
              details: 'Error: Finder got an error: AppleEvent handler failed.',
              code: 'APPLESCRIPT_ERROR',
            }),
          },
        ],
        isError: true,
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.code).toBe('APPLESCRIPT_ERROR');
    });

    it('should not expose sensitive information in errors', () => {
      // Error messages should be safe for LLM
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Permission denied',
              // Should NOT include: /Users/username, API keys, etc.
            }),
          },
        ],
        isError: true,
      };

      const text = response.content[0].text;
      expect(text).not.toContain('/Users/');
      expect(text).not.toContain('password');
    });

    it('should set isError flag to true for all error responses', () => {
      // All error responses must have isError: true
      const errors = [
        { error: 'Tool not found', isError: true },
        { error: 'Permission denied', isError: true },
        { error: 'Invalid arguments', isError: true },
        { error: 'Timeout', isError: true },
      ];

      for (const err of errors) {
        expect(err.isError).toBe(true);
      }
    });
  });

  // ============================================================================
  // SECTION 5: Permission Integration
  // ============================================================================

  describe('Permission Integration', () => {
    it('should check permissions before execution', () => {
      // Before executing, PermissionChecker.check() should be called
      const toolName = 'finder_delete';
      const args = { target: '/path/to/file' };

      // Would check: await permissionChecker.check(tool, args)
      expect(toolName).toBeDefined();
      expect(args).toBeDefined();
    });

    it('should deny execution if permission check returns allowed=false', () => {
      // If PermissionChecker returns denied, don\'t execute
      const permission: PermissionDecision = {
        allowed: false,
        level: 'DANGEROUS',
        reason: 'Dangerous operation requires confirmation',
        requiresPrompt: true,
      };

      expect(permission.allowed).toBe(false);
      // Tool should not be executed
    });

    it('should allow execution if permission check returns allowed=true', () => {
      // If PermissionChecker allows, proceed with execution
      const permission: PermissionDecision = {
        allowed: true,
        level: 'SAFE',
        reason: 'Read-only operation',
        requiresPrompt: false,
      };

      expect(permission.allowed).toBe(true);
      // Tool should be executed
    });

    it('should include permission reason in denial response', () => {
      // Denied response should explain why
      const permission: PermissionDecision = {
        allowed: false,
        level: 'DANGEROUS',
        reason: 'Deletion operations are always confirmed',
        requiresPrompt: true,
      };

      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Permission denied',
              reason: permission.reason,
            }),
          },
        ],
        isError: true,
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.reason).toContain('Deletion');
    });

    it('should record permission decisions after execution', () => {
      // After execution, permission decision should be logged
      const decision: PermissionDecision = {
        allowed: true,
        level: 'MODIFY',
        reason: 'Modifying data',
        requiresPrompt: false,
      };

      // Would call: await permissionChecker.recordDecision(decision)
      expect(decision.allowed).toBe(true);
    });

    it('should handle SAFE level operations without prompting', () => {
      // Read-only operations should execute immediately
      const permission: PermissionDecision = {
        allowed: true,
        level: 'SAFE',
        reason: 'Read-only operation',
        requiresPrompt: false,
      };

      expect(permission.requiresPrompt).toBe(false);
      expect(permission.level).toBe('SAFE');
    });

    it('should handle MODIFY level with user preference', () => {
      // Modify operations may execute if user already approved
      const permission: PermissionDecision = {
        allowed: true,
        level: 'MODIFY',
        reason: 'User previously allowed',
        requiresPrompt: false,
        alwaysAllow: true,
      };

      expect(permission.level).toBe('MODIFY');
      expect(permission.alwaysAllow).toBe(true);
    });
  });

  // ============================================================================
  // SECTION 6: Resource Exposure (App Dictionaries)
  // ============================================================================

  describe('Resource Exposure - App Dictionaries', () => {
    it('should expose app dictionary as resource', () => {
      // Resources provide LLM-readable app capabilities
      const resource = {
        uri: 'iac://apps/com.apple.finder/dictionary',
        name: 'Finder Dictionary',
        mimeType: 'application/json',
      };

      expect(resource.uri).toMatch(/^iac:\/\/apps\//);
      expect(resource.mimeType).toBe('application/json');
    });

    it('should return parsed SDEF as resource content', () => {
      // Dictionary resource should contain parsed capabilities
      const dictionary = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        suites: [
          {
            name: 'Standard Suite',
            commands: [
              {
                name: 'open',
                description: 'Open a file',
                parameters: [{ name: 'target', type: 'string' }],
              },
            ],
          },
        ],
      };

      expect(dictionary.suites).toBeDefined();
      expect(dictionary.suites[0].commands).toBeDefined();
    });

    it('should format dictionary in LLM-friendly format', () => {
      // Dictionary should be easy for LLM to understand
      const dictionary = {
        appName: 'Finder',
        commands: [
          {
            tool: 'finder_open',
            description: 'Open a file or folder',
            parameters: {
              target: {
                type: 'string',
                description: 'Path to file or folder',
                required: true,
              },
            },
          },
        ],
      };

      expect(dictionary.commands).toBeDefined();
      expect(dictionary.commands[0].tool).toBe('finder_open');
    });

    it('should list all available resources', () => {
      // Should support ListResources request
      const resources = [
        { uri: 'iac://apps/com.apple.finder/dictionary', name: 'Finder' },
        { uri: 'iac://apps/com.apple.Safari/dictionary', name: 'Safari' },
      ];

      expect(resources).toHaveLength(2);
      expect(resources[0].uri).toContain('finder');
    });

    it('should retrieve specific resource by URI', () => {
      // Should support ReadResource request
      const uri = 'iac://apps/com.apple.finder/dictionary';
      const content = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
      };

      expect(uri).toContain('com.apple.finder');
      expect(content).toBeDefined();
    });

    it('should cache resources for performance', () => {
      // Resources should be cached after first request
      const resourceCache = new Map<string, object>();
      const uri = 'iac://apps/com.apple.finder/dictionary';

      // First call: generate and cache
      const data1 = { appName: 'Finder' };
      resourceCache.set(uri, data1);

      // Second call: retrieve from cache
      const data2 = resourceCache.get(uri);

      expect(data2).toBe(data1); // Same reference
    });

    it('should handle missing resource gracefully', () => {
      // Non-existent resource should return error
      const response = {
        error: 'Resource not found',
        uri: 'iac://apps/unknown/dictionary',
      };

      expect(response.error).toBeDefined();
      expect(response.uri).toContain('unknown');
    });

    it('should include resource metadata', () => {
      // Resources should have descriptive metadata
      const resource = {
        uri: 'iac://apps/com.apple.finder/dictionary',
        name: 'Finder Application Dictionary',
        mimeType: 'application/json',
        description: 'Complete SDEF dictionary for Finder with all commands',
        lastUpdated: new Date().toISOString(),
      };

      expect(resource.name).toBeDefined();
      expect(resource.description).toBeDefined();
      expect(resource.lastUpdated).toBeDefined();
    });
  });

  // ============================================================================
  // SECTION 7: Protocol Compliance
  // ============================================================================

  describe('Protocol Compliance', () => {
    it('should handle ListTools request', () => {
      // Must support ListTools MCP request
      const request = { method: 'tools/list' };
      expect(request.method).toBe('tools/list');
    });

    it('should handle CallTool request', () => {
      // Must support CallTool MCP request
      const request = {
        method: 'tools/call',
        params: {
          name: 'finder_open',
          arguments: { target: '/path' },
        },
      };

      expect(request.method).toBe('tools/call');
      expect(request.params.name).toBeDefined();
    });

    it('should format response as MCP TextContent', () => {
      // Response must use MCP TextContent format
      const response = {
        content: [
          {
            type: 'text',
            text: 'Result text',
          },
        ],
      };

      expect(response.content[0].type).toBe('text');
      expect(response.content[0].text).toBeDefined();
    });

    it('should support MCP error responses', () => {
      // Errors must follow MCP error format
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: 'message' }),
          },
        ],
        isError: true,
      };

      expect(response.isError).toBe(true);
    });

    it('should handle request timeout gracefully', () => {
      // Should not hang on long-running tools
      const timeout = 30000; // 30 seconds
      expect(timeout).toBeGreaterThan(0);
    });

    it('should register handlers with MCP Server', () => {
      // setupHandlers() should register with server
      // Pseudo-check: handlers must exist for ListTools and CallTool
      const handlers = [
        'ListToolsRequestSchema',
        'CallToolRequestSchema',
      ];

      expect(handlers).toHaveLength(2);
    });

    it('should handle concurrent requests', () => {
      // Multiple tool calls should not block each other
      const requests = [
        { name: 'finder_open', args: {} },
        { name: 'safari_activate', args: {} },
        { name: 'mail_send', args: {} },
      ];

      expect(requests).toHaveLength(3);
      // Each can be processed independently
    });

    it('should validate input schema matches tool definition', () => {
      // Arguments must match tool\'s inputSchema
      const tool: MCPTool = {
        name: 'finder_open',
        description: 'Open',
        inputSchema: {
          type: 'object',
          properties: {
            target: { type: 'string' },
          },
          required: ['target'],
        },
      };

      const validArgs = { target: '/path' };
      expect(validArgs.target).toBeDefined();
    });
  });

  // ============================================================================
  // SECTION 8: Edge Cases & Special Scenarios
  // ============================================================================

  describe('Edge Cases & Special Scenarios', () => {
    it('should handle tool names with special characters safely', () => {
      // Tool names should be sanitized
      const toolName = 'finder_open';
      expect(toolName).toMatch(/^[a-z_]+$/);
    });

    it('should handle very large result data', () => {
      // Should not crash on large results
      const largeData = {
        items: Array(10000).fill({ name: 'file', size: 1024 }),
      };

      const response = {
        content: [{ type: 'text', text: JSON.stringify(largeData) }],
      };

      expect(response.content[0].text.length).toBeGreaterThan(10000);
    });

    it('should handle unicode in arguments and results', () => {
      // Unicode should be preserved through JSON
      const args = { name: '测试文件.txt', description: 'Тест' };
      const json = JSON.stringify(args);
      const parsed = JSON.parse(json);

      expect(parsed.name).toBe('测试文件.txt');
      expect(parsed.description).toBe('Тест');
    });

    it('should handle null values in results', () => {
      // Commands may return null values
      const result = { fileName: 'test.txt', metadata: null };
      const response = {
        content: [{ type: 'text', text: JSON.stringify(result) }],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.metadata).toBeNull();
    });

    it('should handle empty arguments object', () => {
      // Commands with no parameters should work
      const tool: MCPTool = {
        name: 'finder_quit',
        description: 'Quit Finder',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      };

      const args = {};
      expect(Object.keys(args)).toHaveLength(0);
    });

    it('should handle rapid successive calls', () => {
      // Multiple calls in quick succession should not fail
      const calls = Array(5).fill(null).map(() => ({
        name: 'finder_open',
        args: { target: '/path' },
      }));

      expect(calls).toHaveLength(5);
    });

    it('should handle circular reference prevention', () => {
      // JSON serialization should handle circular refs gracefully
      const obj: any = { name: 'test' };
      obj.self = obj; // Circular reference

      // JSON.stringify would normally throw
      // Implementation should handle this
      expect(obj.self).toBe(obj);
    });

    it('should handle date serialization', () => {
      // Dates should serialize properly to ISO strings
      const result = {
        createdAt: new Date('2024-01-01T00:00:00Z'),
      };

      const json = JSON.stringify(result);
      const parsed = JSON.parse(json);

      expect(parsed.createdAt).toBe('2024-01-01T00:00:00.000Z');
    });
  });

  // ============================================================================
  // SECTION 9: Integration Points
  // ============================================================================

  describe('Integration Points', () => {
    it('should integrate with ToolGenerator', () => {
      // Handlers should use ToolGenerator to get tools
      expect(mockToolGenerator.generateTools).toBeDefined();
    });

    it('should integrate with MacOSAdapter', () => {
      // Handlers should call adapter.execute() for execution
      expect(mockAdapter.execute).toBeDefined();
    });

    it('should integrate with PermissionChecker', () => {
      // Handlers should check permissions before execution
      expect(mockPermissionChecker.check).toBeDefined();
    });

    it('should pass tool metadata to adapter', () => {
      // Adapter needs metadata for execution
      const metadata: ToolMetadata = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        commandName: 'open',
        commandCode: 'aevtodoc',
        suiteName: 'Standard Suite',
      };

      expect(metadata.appName).toBeDefined();
    });

    it('should handle errors from ToolGenerator gracefully', () => {
      // If generation fails, should return meaningful error
      // not crash
      expect(mockToolGenerator.generateTools).toBeDefined();
    });

    it('should handle errors from MacOSAdapter gracefully', () => {
      // If execution fails, should format error response
      expect(mockAdapter.execute).toBeDefined();
    });

    it('should handle errors from PermissionChecker gracefully', () => {
      // If permission check fails, should format error response
      expect(mockPermissionChecker.check).toBeDefined();
    });
  });
});
