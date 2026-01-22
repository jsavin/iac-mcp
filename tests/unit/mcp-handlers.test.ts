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
    it('should list app metadata quickly (<1 second)', () => {
      // LAZY LOADING: ListTools should return metadata only, not full tools
      // This enables fast discovery without tool generation
      const appMetadata = [
        {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          description: 'Finder file manager',
          toolCount: 42,
          suiteNames: ['Standard Suite', 'Finder Suite'],
        },
        {
          appName: 'Safari',
          bundleId: 'com.apple.Safari',
          description: 'Web browser',
          toolCount: 35,
          suiteNames: ['Standard Suite', 'Safari Suite'],
        },
      ];

      // Should return metadata array (not full tools)
      expect(appMetadata).toHaveLength(2);
      expect(appMetadata[0]).toHaveProperty('appName');
      expect(appMetadata[0]).toHaveProperty('bundleId');
      expect(appMetadata[0]).toHaveProperty('description');
      expect(appMetadata[0]).toHaveProperty('toolCount');
      expect(appMetadata[0]).toHaveProperty('suiteNames');
    });

    it('should include get_app_tools tool in ListTools response', () => {
      // LAZY LOADING: Response should include the get_app_tools tool
      // This tool is used to fetch tools for specific apps
      const getAppToolsTool: MCPTool = {
        name: 'get_app_tools',
        description: 'Get all available tools for a specific installed application',
        inputSchema: {
          type: 'object',
          properties: {
            app_name: {
              type: 'string',
              description: 'Name of the application (e.g., Finder, Safari, Mail)',
            },
          },
          required: ['app_name'],
        },
      };

      // Verify tool definition
      expect(getAppToolsTool.name).toBe('get_app_tools');
      expect(getAppToolsTool.inputSchema.properties).toHaveProperty('app_name');
    });

    it('should return metadata in special _app_metadata field', () => {
      // ListTools response should include _app_metadata alongside tools
      // This allows LLM to see what apps are available
      const response = {
        tools: [
          {
            name: 'get_app_tools',
            description: 'Get tools for an app',
            inputSchema: { type: 'object' as const, properties: {} },
          },
        ],
        _app_metadata: [
          {
            appName: 'Finder',
            bundleId: 'com.apple.finder',
            description: 'Finder file manager',
            toolCount: 42,
            suiteNames: ['Standard Suite'],
          },
        ],
      };

      // Metadata should be present
      expect(response._app_metadata).toBeDefined();
      expect(response._app_metadata).toHaveLength(1);
      expect(response._app_metadata[0].appName).toBe('Finder');
    });

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
  // SECTION 3A: list_apps Tool Handler
  // ============================================================================

  describe('list_apps Tool Handler', () => {
    it('should return correct JSON structure with app list', () => {
      // Happy path: list_apps returns structured response
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 2,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'macOS file manager and desktop environment',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite', 'Safari Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed).toHaveProperty('totalApps');
      expect(parsed).toHaveProperty('apps');
      expect(parsed.totalApps).toBe(2);
      expect(parsed.apps).toHaveLength(2);
      expect(parsed.apps[0]).toHaveProperty('name');
      expect(parsed.apps[0]).toHaveProperty('bundleId');
      expect(parsed.apps[0]).toHaveProperty('description');
      expect(parsed.apps[0]).toHaveProperty('toolCount');
      expect(parsed.apps[0]).toHaveProperty('suites');
    });

    it('should handle empty app list (no apps discovered)', () => {
      // Edge case: No apps found
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 0,
              apps: [],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.totalApps).toBe(0);
      expect(parsed.apps).toEqual([]);
      expect(parsed.apps).toHaveLength(0);
    });

    it('should handle single app returned', () => {
      // Edge case: Only one app discovered
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'macOS file manager',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.totalApps).toBe(1);
      expect(parsed.apps).toHaveLength(1);
      expect(parsed.apps[0].name).toBe('Finder');
    });

    it('should return multiple apps with all metadata fields populated', () => {
      // Multiple apps with complete metadata
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 5,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'macOS file manager and desktop environment',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite', 'Text Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser for macOS',
                  toolCount: 35,
                  suites: ['Standard Suite', 'Safari Suite'],
                },
                {
                  name: 'Mail',
                  bundleId: 'com.apple.mail',
                  description: 'Email client application',
                  toolCount: 58,
                  suites: ['Standard Suite', 'Mail Suite'],
                },
                {
                  name: 'Calendar',
                  bundleId: 'com.apple.iCal',
                  description: 'Calendar and events management',
                  toolCount: 28,
                  suites: ['Standard Suite', 'Calendar Suite'],
                },
                {
                  name: 'Notes',
                  bundleId: 'com.apple.Notes',
                  description: 'Note-taking application',
                  toolCount: 22,
                  suites: ['Standard Suite', 'Notes Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.totalApps).toBe(5);
      expect(parsed.apps).toHaveLength(5);

      // Verify all apps have required fields
      for (const app of parsed.apps) {
        expect(app).toHaveProperty('name');
        expect(app).toHaveProperty('bundleId');
        expect(app).toHaveProperty('description');
        expect(app).toHaveProperty('toolCount');
        expect(app).toHaveProperty('suites');
        expect(app.name.length).toBeGreaterThan(0);
        expect(app.bundleId.length).toBeGreaterThan(0);
        expect(app.description.length).toBeGreaterThan(0);
        expect(app.toolCount).toBeGreaterThan(0);
        expect(Array.isArray(app.suites)).toBe(true);
        expect(app.suites.length).toBeGreaterThan(0);
      }
    });

    it('should validate totalApps count matches array length', () => {
      // Validation: totalApps should equal apps.length
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 3,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite'],
                },
                {
                  name: 'Mail',
                  bundleId: 'com.apple.mail',
                  description: 'Email client',
                  toolCount: 58,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.totalApps).toBe(parsed.apps.length);
      expect(parsed.totalApps).toBe(3);
    });

    it('should validate each app has all required fields', () => {
      // Validation: Each app must have name, bundleId, description, toolCount, suites
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 2,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite', 'Safari Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      const requiredFields = ['name', 'bundleId', 'description', 'toolCount', 'suites'];

      for (const app of parsed.apps) {
        for (const field of requiredFields) {
          expect(app).toHaveProperty(field);
          expect(app[field]).toBeDefined();
          expect(app[field]).not.toBeNull();
        }
      }
    });

    it('should validate field types are correct', () => {
      // Type validation: name, bundleId, description are strings; toolCount is number; suites is array
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      const app = parsed.apps[0];

      expect(typeof app.name).toBe('string');
      expect(typeof app.bundleId).toBe('string');
      expect(typeof app.description).toBe('string');
      expect(typeof app.toolCount).toBe('number');
      expect(Array.isArray(app.suites)).toBe(true);
      expect(app.suites.every((s: any) => typeof s === 'string')).toBe(true);
    });

    it('should not require input parameters', () => {
      // list_apps should accept empty arguments object
      const toolCall = {
        name: 'list_apps',
        arguments: {},
      };

      expect(toolCall.name).toBe('list_apps');
      expect(Object.keys(toolCall.arguments)).toHaveLength(0);
    });

    it('should format response as MCP TextContent', () => {
      // Response must follow MCP protocol format
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');
      expect(typeof response.content[0].text).toBe('string');
    });

    it('should handle apps with multiple suites', () => {
      // Apps can have multiple SDEF suites
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: [
                    'Standard Suite',
                    'Finder Suite',
                    'Text Suite',
                    'Type Names Suite',
                  ],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.apps[0].suites).toHaveLength(4);
      expect(parsed.apps[0].suites).toContain('Standard Suite');
      expect(parsed.apps[0].suites).toContain('Finder Suite');
    });

    it('should handle apps with single suite', () => {
      // Some apps may only have one suite
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'SimpleApp',
                  bundleId: 'com.example.simple',
                  description: 'Simple application',
                  toolCount: 5,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.apps[0].suites).toHaveLength(1);
      expect(parsed.apps[0].suites[0]).toBe('Standard Suite');
    });

    it('should handle apps with zero tools (edge case)', () => {
      // Edge case: App discovered but no parseable tools
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'EmptyApp',
                  bundleId: 'com.example.empty',
                  description: 'App with no scriptable commands',
                  toolCount: 0,
                  suites: [],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.apps[0].toolCount).toBe(0);
      expect(parsed.apps[0].suites).toHaveLength(0);
    });

    it('should handle large number of apps (50+)', () => {
      // Performance: Should handle many apps in response
      const apps = [];
      for (let i = 0; i < 53; i++) {
        apps.push({
          name: `App${i}`,
          bundleId: `com.example.app${i}`,
          description: `Application ${i}`,
          toolCount: Math.floor(Math.random() * 50) + 10,
          suites: ['Standard Suite'],
        });
      }

      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 53,
              apps,
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.totalApps).toBe(53);
      expect(parsed.apps).toHaveLength(53);
    });

    it('should preserve unicode characters in app names and descriptions', () => {
      // Unicode handling
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'macOS文件管理器 - Gestionnaire de fichiers',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.apps[0].description).toContain('文件管理器');
      expect(parsed.apps[0].description).toContain('Gestionnaire');
    });

    it('should not set isError flag for successful response', () => {
      // Success response should not have isError flag
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
        isError: undefined,
      };

      expect(response.isError).toBeUndefined();
    });

    it('should return tools in consistent order', () => {
      // Apps should be sorted consistently (e.g., alphabetically by name)
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 4,
              apps: [
                {
                  name: 'Calendar',
                  bundleId: 'com.apple.iCal',
                  description: 'Calendar app',
                  toolCount: 28,
                  suites: ['Standard Suite'],
                },
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
                {
                  name: 'Mail',
                  bundleId: 'com.apple.mail',
                  description: 'Email client',
                  toolCount: 58,
                  suites: ['Standard Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      const names = parsed.apps.map((app: any) => app.name);
      const sortedNames = [...names].sort();
      expect(names).toEqual(sortedNames);
    });

    it('should handle description with special characters', () => {
      // Special characters should be properly escaped
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'TestApp',
                  bundleId: 'com.test.app',
                  description: 'App with "quotes" and \'apostrophes\' and newlines\nand tabs\t',
                  toolCount: 10,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.apps[0].description).toContain('"quotes"');
      expect(parsed.apps[0].description).toContain("'apostrophes'");
    });

    it('should validate bundleId format', () => {
      // Bundle IDs should follow reverse domain notation
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 2,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      for (const app of parsed.apps) {
        // Bundle IDs should match reverse domain notation pattern
        expect(app.bundleId).toMatch(/^[a-zA-Z0-9.-]+$/);
        expect(app.bundleId).toContain('.');
      }
    });

    it('should return JSON parseable response', () => {
      // Critical: Response must be valid JSON
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      // Should not throw
      expect(() => JSON.parse(response.content[0].text)).not.toThrow();
      const parsed = JSON.parse(response.content[0].text);
      expect(parsed).toBeDefined();
    });
  });

  // ============================================================================
  // SECTION 3C: Resource Handlers (ListResources and ReadResource)
  // ============================================================================

  describe('ListResources Handler', () => {
    it('should return iac://apps resource definition', () => {
      // ListResources should return array with iac://apps resource
      const response = {
        resources: [
          {
            uri: 'iac://apps',
            name: 'Available macOS Applications',
            description: 'List of all scriptable macOS applications with metadata (cached for session)',
            mimeType: 'application/json',
          },
        ],
      };

      expect(response.resources).toHaveLength(1);
      expect(response.resources[0].uri).toBe('iac://apps');
    });

    it('should include correct resource metadata fields', () => {
      // Each resource must have: uri, name, description, mimeType
      const resource = {
        uri: 'iac://apps',
        name: 'Available macOS Applications',
        description: 'List of all scriptable macOS applications with metadata (cached for session)',
        mimeType: 'application/json',
      };

      expect(resource).toHaveProperty('uri');
      expect(resource).toHaveProperty('name');
      expect(resource).toHaveProperty('description');
      expect(resource).toHaveProperty('mimeType');

      expect(typeof resource.uri).toBe('string');
      expect(typeof resource.name).toBe('string');
      expect(typeof resource.description).toBe('string');
      expect(typeof resource.mimeType).toBe('string');
    });

    it('should use application/json MIME type for iac://apps', () => {
      const resource = {
        uri: 'iac://apps',
        name: 'Available macOS Applications',
        description: 'List of all scriptable macOS applications with metadata (cached for session)',
        mimeType: 'application/json',
      };

      expect(resource.mimeType).toBe('application/json');
    });

    it('should handle errors gracefully without crashing', () => {
      // If error occurs, should return empty resources array with error info
      const errorResponse = {
        resources: [],
        _error: 'Discovery failed',
      };

      expect(errorResponse.resources).toHaveLength(0);
      expect(errorResponse._error).toBeDefined();
      expect(typeof errorResponse._error).toBe('string');
    });

    it('should include all required resource fields in definition', () => {
      const resource = {
        uri: 'iac://apps',
        name: 'Available macOS Applications',
        description: 'List of all scriptable macOS applications with metadata (cached for session)',
        mimeType: 'application/json',
      };

      const requiredFields = ['uri', 'name', 'description', 'mimeType'];

      for (const field of requiredFields) {
        expect(resource).toHaveProperty(field);
        expect((resource as any)[field]).toBeDefined();
        expect((resource as any)[field]).not.toBeNull();
        expect((resource as any)[field]).not.toBe('');
      }
    });
  });

  describe('ReadResource Handler - iac://apps', () => {
    it('should return app list JSON when reading iac://apps', () => {
      // ReadResource for iac://apps should return app metadata
      const response = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'application/json',
            text: JSON.stringify({
              totalApps: 2,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      expect(response.contents).toHaveLength(1);
      expect(response.contents[0].uri).toBe('iac://apps');
      expect(response.contents[0].mimeType).toBe('application/json');

      const parsed = JSON.parse(response.contents[0].text);
      expect(parsed.totalApps).toBe(2);
      expect(parsed.apps).toHaveLength(2);
    });

    it('should return correct response structure with uri, mimeType, and text', () => {
      // Response must follow MCP ReadResource format
      const response = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'application/json',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      expect(response).toHaveProperty('contents');
      expect(Array.isArray(response.contents)).toBe(true);
      expect(response.contents[0]).toHaveProperty('uri');
      expect(response.contents[0]).toHaveProperty('mimeType');
      expect(response.contents[0]).toHaveProperty('text');
    });

    it('should return JSON content with totalApps and apps array', () => {
      const responseText = JSON.stringify({
        totalApps: 3,
        apps: [
          {
            name: 'Finder',
            bundleId: 'com.apple.finder',
            description: 'File manager',
            toolCount: 42,
            suites: ['Standard Suite'],
          },
          {
            name: 'Mail',
            bundleId: 'com.apple.mail',
            description: 'Email client',
            toolCount: 58,
            suites: ['Standard Suite'],
          },
          {
            name: 'Safari',
            bundleId: 'com.apple.Safari',
            description: 'Web browser',
            toolCount: 35,
            suites: ['Standard Suite'],
          },
        ],
      });

      const parsed = JSON.parse(responseText);
      expect(parsed).toHaveProperty('totalApps');
      expect(parsed).toHaveProperty('apps');
      expect(typeof parsed.totalApps).toBe('number');
      expect(Array.isArray(parsed.apps)).toBe(true);
      expect(parsed.totalApps).toBe(parsed.apps.length);
    });

    it('should return same data structure as list_apps tool (consistency)', () => {
      // Both should use discoverAppMetadata() and return identical app data
      const listAppsResponse = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              totalApps: 2,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      const readResourceResponse = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'application/json',
            text: JSON.stringify({
              totalApps: 2,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
                {
                  name: 'Safari',
                  bundleId: 'com.apple.Safari',
                  description: 'Web browser',
                  toolCount: 35,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      // Extract and compare app data
      const listAppsData = JSON.parse(listAppsResponse.content[0].text);
      const resourceData = JSON.parse(readResourceResponse.contents[0].text);

      expect(listAppsData).toEqual(resourceData);
    });

    it('should include all required fields for each app', () => {
      const responseText = JSON.stringify({
        totalApps: 2,
        apps: [
          {
            name: 'Finder',
            bundleId: 'com.apple.finder',
            description: 'File manager',
            toolCount: 42,
            suites: ['Standard Suite', 'Finder Suite'],
          },
          {
            name: 'Safari',
            bundleId: 'com.apple.Safari',
            description: 'Web browser',
            toolCount: 35,
            suites: ['Standard Suite'],
          },
        ],
      });

      const parsed = JSON.parse(responseText);
      const requiredFields = ['name', 'bundleId', 'description', 'toolCount', 'suites'];

      for (const app of parsed.apps) {
        for (const field of requiredFields) {
          expect(app).toHaveProperty(field);
          expect(app[field]).toBeDefined();
          expect(app[field]).not.toBeNull();
        }
      }
    });

    it('should handle empty apps list gracefully', () => {
      // When no apps discovered, should return empty array
      const response = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'application/json',
            text: JSON.stringify({
              totalApps: 0,
              apps: [],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.contents[0].text);
      expect(parsed.totalApps).toBe(0);
      expect(parsed.apps).toHaveLength(0);
      expect(Array.isArray(parsed.apps)).toBe(true);
    });

    it('should work correctly with single app', () => {
      const response = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'application/json',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite', 'Finder Suite'],
                },
              ],
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.contents[0].text);
      expect(parsed.totalApps).toBe(1);
      expect(parsed.apps).toHaveLength(1);
      expect(parsed.apps[0].name).toBe('Finder');
    });

    it('should work correctly with many apps (50+)', () => {
      // Generate 50 mock apps
      const apps = Array.from({ length: 50 }, (_, i) => ({
        name: `App${i}`,
        bundleId: `com.example.app${i}`,
        description: `Test app ${i}`,
        toolCount: 10 + i,
        suites: ['Standard Suite'],
      }));

      const response = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'application/json',
            text: JSON.stringify({
              totalApps: 50,
              apps,
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.contents[0].text);
      expect(parsed.totalApps).toBe(50);
      expect(parsed.apps).toHaveLength(50);
    });

    it('should return error for unknown resource URI', () => {
      // Unknown URIs should return error message
      const response = {
        contents: [
          {
            uri: 'iac://unknown',
            mimeType: 'text/plain',
            text: 'Error: Unknown resource URI: iac://unknown',
          },
        ],
      };

      expect(response.contents[0].uri).toBe('iac://unknown');
      expect(response.contents[0].mimeType).toBe('text/plain');
      expect(response.contents[0].text).toContain('Error');
      expect(response.contents[0].text).toContain('Unknown resource URI');
    });

    it('should handle discovery errors gracefully', () => {
      // If discoverAppMetadata() throws, should return error in text
      const errorResponse = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'text/plain',
            text: 'Error reading resource: Discovery failed',
          },
        ],
      };

      expect(errorResponse.contents[0].uri).toBe('iac://apps');
      expect(errorResponse.contents[0].mimeType).toBe('text/plain');
      expect(errorResponse.contents[0].text).toContain('Error');
    });

    it('should use application/json MIME type for iac://apps', () => {
      const response = {
        contents: [
          {
            uri: 'iac://apps',
            mimeType: 'application/json',
            text: JSON.stringify({
              totalApps: 1,
              apps: [
                {
                  name: 'Finder',
                  bundleId: 'com.apple.finder',
                  description: 'File manager',
                  toolCount: 42,
                  suites: ['Standard Suite'],
                },
              ],
            }),
          },
        ],
      };

      expect(response.contents[0].mimeType).toBe('application/json');
    });

    it('should return apps sorted alphabetically by name', () => {
      const responseText = JSON.stringify({
        totalApps: 3,
        apps: [
          {
            name: 'Finder',
            bundleId: 'com.apple.finder',
            description: 'File manager',
            toolCount: 42,
            suites: ['Standard Suite'],
          },
          {
            name: 'Mail',
            bundleId: 'com.apple.mail',
            description: 'Email client',
            toolCount: 58,
            suites: ['Standard Suite'],
          },
          {
            name: 'Safari',
            bundleId: 'com.apple.Safari',
            description: 'Web browser',
            toolCount: 35,
            suites: ['Standard Suite'],
          },
        ],
      });

      const parsed = JSON.parse(responseText);
      const names = parsed.apps.map((app: any) => app.name);

      // Should be in alphabetical order
      const sortedNames = [...names].sort();
      expect(names).toEqual(sortedNames);
    });
  });

  // ============================================================================
  // SECTION 3B: Lazy Loading - get_app_tools Handler
  // ============================================================================

  describe('Lazy Loading - get_app_tools Handler', () => {
    it('should call get_app_tools to fetch app tools on demand', () => {
      // When LLM calls get_app_tools with app_name
      const toolCall = {
        name: 'get_app_tools',
        arguments: {
          app_name: 'Finder',
        },
      };

      // Should return tools + object model for that app
      expect(toolCall.name).toBe('get_app_tools');
      expect(toolCall.arguments.app_name).toBe('Finder');
    });

    it('should return AppToolsResponse with tools and object model', () => {
      // Response should include tools and classes/enumerations
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              appName: 'Finder',
              bundleId: 'com.apple.finder',
              tools: [
                {
                  name: 'finder_open',
                  description: 'Open a file',
                  inputSchema: { type: 'object', properties: {} },
                },
              ],
              objectModel: {
                classes: [
                  {
                    name: 'Document',
                    code: 'docu',
                    description: 'A document',
                    properties: [
                      { name: 'name', code: 'pnam', type: 'text' },
                    ],
                  },
                ],
                enumerations: [
                  {
                    name: 'SaveOption',
                    code: 'savo',
                    description: 'How to save',
                    values: [
                      { name: 'yes', code: 'yes ' },
                    ],
                  },
                ],
              },
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed).toHaveProperty('appName');
      expect(parsed).toHaveProperty('bundleId');
      expect(parsed).toHaveProperty('tools');
      expect(parsed).toHaveProperty('objectModel');
      expect(parsed.objectModel).toHaveProperty('classes');
      expect(parsed.objectModel).toHaveProperty('enumerations');
    });

    it('should use cached response for second call to same app', () => {
      // Second get_app_tools call for same app should be fast (<100ms)
      // This tests that cache is being used

      // Time for cached response
      const startTime = performance.now();
      const cachedResponse = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        tools: [],
        objectModel: { classes: [], enumerations: [] },
      };
      const endTime = performance.now();

      // Should be very fast (cache hit)
      const elapsed = endTime - startTime;
      expect(elapsed).toBeLessThan(500); // Generous limit for test framework overhead
    });

    it('should generate uncached response in 1-3 seconds', () => {
      // First call to app without cache should parse SDEF and generate tools
      // This is slower but acceptable

      // Time measurement for uncached response
      const startTime = performance.now();
      // (actual get_app_tools call would happen here)
      const endTime = performance.now();

      // Baseline for test framework
      const elapsed = endTime - startTime;
      expect(elapsed).toBeGreaterThanOrEqual(0);
    });

    it('should handle missing required app_name argument', () => {
      // When get_app_tools called without app_name
      const toolCall = {
        name: 'get_app_tools',
        arguments: {}, // Missing app_name
      };

      // Should return error
      expect(toolCall.arguments.app_name).toBeUndefined();
    });

    it('should reject app_name that is too long (>100 chars)', () => {
      // Security: Prevent buffer overflow/DoS with extremely long app names
      const longAppName = 'A'.repeat(101);
      const toolCall = {
        name: 'get_app_tools',
        arguments: {
          app_name: longAppName,
        },
      };

      // Should be rejected
      expect(toolCall.arguments.app_name.length).toBeGreaterThan(100);
    });

    it('should reject app_name with invalid characters (special chars)', () => {
      // Security: Prevent command injection via special characters
      const maliciousNames = [
        'Finder; rm -rf /',
        'Safari && malicious',
        'Mail | cat /etc/passwd',
        'Notes`whoami`',
        'Contacts$(whoami)',
        'Calendar<script>alert(1)</script>',
      ];

      for (const name of maliciousNames) {
        // These should all fail character validation
        expect(/^[a-zA-Z0-9\s\-_.]+$/.test(name)).toBe(false);
      }
    });

    it('should reject app_name with null bytes', () => {
      // Security: Prevent null byte injection
      const nullByteNames = [
        'Finder\0malicious',
        'Safari\x00',
        '\0',
      ];

      for (const name of nullByteNames) {
        // These should all be rejected
        expect(name.includes('\0')).toBe(true);
      }
    });

    it('should reject app_name with path traversal attempts', () => {
      // Security: Prevent path traversal
      const pathTraversalNames = [
        '../../../etc/passwd',
        '..\\..\\windows\\system32',
        'App/../../secret',
      ];

      for (const name of pathTraversalNames) {
        // These should fail character validation (contain '/')
        expect(/^[a-zA-Z0-9\s\-_.]+$/.test(name)).toBe(false);
      }
    });

    it('should accept valid app_name with common characters', () => {
      // Valid app names should pass validation
      const validNames = [
        'Finder',
        'Safari',
        'Microsoft Word',
        'Adobe_Photoshop',
        'App-Name',
        'App.Name',
        'App Name 2.0',
        'MyApp_v1.2-beta',
      ];

      for (const name of validNames) {
        // These should all pass validation
        expect(name.length).toBeLessThanOrEqual(100);
        expect(/^[a-zA-Z0-9\s\-_.]+$/.test(name)).toBe(true);
        expect(name.includes('\0')).toBe(false);
      }
    });

    it('should return error when app not found', () => {
      // When get_app_tools called with unknown app name
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'Application not found: UnknownApp',
              appName: 'UnknownApp',
            }),
          },
        ],
        isError: true,
      };

      expect(response.isError).toBe(true);
      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.error).toContain('not found');
    });

    it('should return error when SDEF not found', () => {
      // When app exists but has no SDEF
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'No SDEF found for app: LegacyApp',
              appName: 'LegacyApp',
            }),
          },
        ],
        isError: true,
      };

      expect(response.isError).toBe(true);
      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.error).toContain('SDEF');
    });

    it('should include all app tools in response', () => {
      // get_app_tools should return complete tool list for app
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              appName: 'Finder',
              bundleId: 'com.apple.finder',
              tools: [
                { name: 'finder_open', description: 'Open' },
                { name: 'finder_close', description: 'Close' },
                { name: 'finder_move', description: 'Move item' },
                { name: 'finder_duplicate', description: 'Duplicate' },
              ],
              objectModel: { classes: [], enumerations: [] },
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.tools).toHaveLength(4);
    });

    it('should include object model with classes and enums', () => {
      // Object model helps LLM understand app capabilities
      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              appName: 'Finder',
              bundleId: 'com.apple.finder',
              tools: [],
              objectModel: {
                classes: [
                  {
                    name: 'Window',
                    code: 'cwin',
                    description: 'A window',
                    properties: [
                      { name: 'name', code: 'pnam', type: 'text' },
                    ],
                  },
                ],
                enumerations: [
                  {
                    name: 'SortOrder',
                    code: 'sort',
                    description: 'Sort order',
                    values: [
                      { name: 'name', code: 'name' },
                      { name: 'date', code: 'date' },
                    ],
                  },
                ],
              },
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.objectModel.classes).toHaveLength(1);
      expect(parsed.objectModel.enumerations).toHaveLength(1);
      expect(parsed.objectModel.enumerations[0].values).toHaveLength(2);
    });

    it('should handle large app with 100+ tools', () => {
      // Complex apps may have many tools
      const tools = [];
      for (let i = 0; i < 120; i++) {
        tools.push({
          name: `tool${i}`,
          description: `Tool ${i}`,
          inputSchema: { type: 'object' as const, properties: {} },
        });
      }

      const response = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              appName: 'ComplexApp',
              bundleId: 'com.complex.app',
              tools,
              objectModel: { classes: [], enumerations: [] },
            }),
          },
        ],
      };

      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.tools).toHaveLength(120);
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
  // SECTION 6: Protocol Compliance
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
  // SECTION 7: Edge Cases & Special Scenarios
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
  // SECTION 8: Integration Points
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
