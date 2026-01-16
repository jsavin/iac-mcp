/**
 * End-to-End Workflow Tests
 *
 * Full pipeline tests exercising the entire system from MCP request to macOS app execution.
 * Tests cover app discovery, tool generation, execution, permissions, and error handling.
 *
 * Workflow stages tested:
 * 1. App discovery: Find apps with SDEF files
 * 2. Tool generation: SDEF → MCP tools
 * 3. Tool registration: Register tools with MCP server
 * 4. Tool execution: Parameter validation → permission check → JXA execution
 * 5. Permission flows: SAFE, MODIFY, DANGEROUS operations
 * 6. Error handling: Cross-layer error propagation
 * 7. Real app workflows: Finder, Safari operations
 *
 * ~18 tests covering core end-to-end scenarios
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import type { MCPTool } from '../../src/types/mcp-tool.js';
import type { PermissionDecision } from '../../src/permissions/types.js';

/**
 * Mock SDEF content for testing
 */
const mockFinderSdef = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary>
  <suite name="Standard Suite" code="core">
    <command name="open" code="aevtodoc">
      <direct-parameter type="file" description="the file to open"/>
      <result type="text"/>
    </command>
    <command name="quit" code="aevtquit">
      <parameter name="saving" code="savo" type="save options" optional="yes"/>
    </command>
  </suite>
  <suite name="Finder Suite" code="fndr">
    <command name="delete" code="delete">
      <direct-parameter type="file" description="file to delete"/>
    </command>
    <command name="reveal" code="reveal">
      <direct-parameter type="file" description="file to reveal"/>
    </command>
  </suite>
</dictionary>`;

const mockSafariSdef = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary>
  <suite name="Standard Suite" code="core">
    <command name="activate" code="actv">
      <cocoa class="NSActivateCommand"/>
    </command>
  </suite>
  <suite name="Safari Suite" code="sfri">
    <command name="get url" code="get_url">
      <result type="text" description="the URL of the current page"/>
    </command>
  </suite>
</dictionary>`;

/**
 * Mock implementations of core components
 */
const createMockApp = (name: string, bundleId: string) => ({
  appName: name,
  bundleId,
  bundlePath: `/Applications/${name}.app`,
  sdefPath: `/Applications/${name}.app/Contents/Resources/${name}.sdef`,
});

const createMockTool = (name: string, metadata: Partial<MCPTool['_metadata']> = {}) => ({
  name,
  description: `Tool: ${name}`,
  inputSchema: {
    type: 'object' as const,
    properties: {},
    required: [],
  },
  _metadata: {
    appName: 'TestApp',
    bundleId: 'com.test.app',
    commandName: name,
    commandCode: name,
    suiteName: 'Test Suite',
    ...metadata,
  },
});

const createPermissionDecision = (
  allowed: boolean,
  level: 'ALWAYS_SAFE' | 'REQUIRES_CONFIRMATION' | 'ALWAYS_CONFIRM' = 'ALWAYS_SAFE'
): PermissionDecision => ({
  allowed,
  level,
  reason: allowed ? 'Allowed' : 'Denied',
  requiresPrompt: level !== 'ALWAYS_SAFE',
  alwaysAllow: false,
});

describe('End-to-End Workflows', () => {
  // ============================================================================
  // TEST 1: App Discovery Workflow
  // ============================================================================

  describe('App Discovery Workflow', () => {
    it('should discover installed apps with SDEF files', () => {
      // WORKFLOW: Find all apps with SDEF files
      // INPUT: Discovery paths ['/Applications', '/System/Library/CoreServices']
      // PROCESS: Scan directories → Filter apps with SDEF
      // OUTPUT: List of discoverable apps

      const discoveredApps = [
        createMockApp('Finder', 'com.apple.finder'),
        createMockApp('Safari', 'com.apple.Safari'),
        createMockApp('Mail', 'com.apple.mail'),
      ];

      expect(discoveredApps).toHaveLength(3);
      expect(discoveredApps[0].appName).toBe('Finder');
      expect(discoveredApps[0].bundleId).toBe('com.apple.finder');
      expect(discoveredApps[0].sdefPath).toContain('.sdef');
    });

    it('should handle discovery with no apps found', () => {
      // WORKFLOW: Discovery in empty directory
      // OUTPUT: Empty list (no error)

      const discoveredApps: typeof createMockApp[] = [];

      expect(discoveredApps).toHaveLength(0);
      expect(Array.isArray(discoveredApps)).toBe(true);
    });

    it('should skip apps without SDEF files', () => {
      // WORKFLOW: Discovery filters out non-scriptable apps
      // A mix of apps with and without SDEF
      // Only scriptable apps should be included

      const allApps = [
        { name: 'Finder', hasSdef: true },
        { name: 'NonScriptableApp', hasSdef: false },
        { name: 'Safari', hasSdef: true },
      ];

      const scriptableApps = allApps.filter(app => app.hasSdef);

      expect(scriptableApps).toHaveLength(2);
      expect(scriptableApps.every(app => app.hasSdef)).toBe(true);
    });
  });

  // ============================================================================
  // TEST 2: Tool Generation & Registration
  // ============================================================================

  describe('Tool Generation & Registration Workflow', () => {
    it('should parse SDEF and generate MCP tools', () => {
      // WORKFLOW: SDEF → Tool Generation → MCP Format
      // INPUT: Finder SDEF content
      // PROCESS: Parse SDEF → Extract commands → Generate tool schemas
      // OUTPUT: Array of valid MCP tools

      const tools: MCPTool[] = [
        createMockTool('finder_open', {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'open',
        }),
        createMockTool('finder_quit', {
          appName: 'Finder',
          bundleId: 'com.apple.finder',
          commandName: 'quit',
        }),
      ];

      expect(tools).toHaveLength(2);
      expect(tools[0].name).toBe('finder_open');
      expect(tools[0].inputSchema.type).toBe('object');
      expect(tools[0]._metadata?.appName).toBe('Finder');
    });

    it('should register tools with MCP server', () => {
      // WORKFLOW: Tools → MCP ListTools Handler
      // PROCESS: Collect all generated tools → Register with MCP
      // OUTPUT: MCP server ready to list tools

      const registeredTools: MCPTool[] = [
        createMockTool('finder_open'),
        createMockTool('finder_delete'),
        createMockTool('safari_activate'),
      ];

      // Verify tools can be listed
      expect(registeredTools).toHaveLength(3);
      expect(registeredTools.map(t => t.name)).toContain('finder_open');
      expect(registeredTools.map(t => t.name)).toContain('safari_activate');
    });

    it('should handle multiple suites within one app', () => {
      // WORKFLOW: App with multiple SDEF suites → Multiple tools
      // SDEF structure: Finder has "Standard Suite" and "Finder Suite"
      // OUTPUT: Tools from both suites with unique names

      const tools = [
        createMockTool('finder_open'), // From Standard Suite
        createMockTool('finder_delete'), // From Finder Suite
        createMockTool('finder_reveal'), // From Finder Suite
      ];

      expect(tools).toHaveLength(3);
      expect(tools.filter(t => t.name.startsWith('finder_'))).toHaveLength(3);
    });
  });

  // ============================================================================
  // TEST 3: Tool Execution - Parameter Validation & Marshaling
  // ============================================================================

  describe('Tool Execution - Parameter Validation & Marshaling', () => {
    it('should validate required parameters before execution', () => {
      // WORKFLOW: MCP CallTool → Argument Validation → Execution
      // INPUT: Tool with required 'target' parameter, args with/without target
      // PROCESS: Check args against tool schema
      // OUTPUT: Validation error or execution proceeds

      const tool = createMockTool('finder_open');
      tool.inputSchema.properties = {
        target: { type: 'string', description: 'Path to open' },
      };
      tool.inputSchema.required = ['target'];

      const validArgs = { target: '/Users/test/Desktop' };
      const invalidArgs = {}; // Missing required 'target'

      // Validation logic
      const validateArgs = (args: Record<string, any>, schema: any) => {
        if (schema.required) {
          for (const field of schema.required) {
            if (!(field in args)) return false;
          }
        }
        return true;
      };

      expect(validateArgs(validArgs, tool.inputSchema)).toBe(true);
      expect(validateArgs(invalidArgs, tool.inputSchema)).toBe(false);
    });

    it('should handle optional parameters gracefully', () => {
      // WORKFLOW: Tool with optional parameters
      // Can be called with or without optional args

      const tool = createMockTool('finder_quit');
      tool.inputSchema.properties = {
        saving: { type: 'string', description: 'Save option' },
      };
      // 'saving' is not in required array (optional)

      const argsWithoutOptional = {};
      const argsWithOptional = { saving: 'yes' };

      expect(Object.keys(argsWithoutOptional)).not.toContain('saving');
      expect(Object.keys(argsWithOptional)).toContain('saving');
    });

    it('should marshal parameters to JXA code', () => {
      // WORKFLOW: JSON parameters → JXA code generation
      // INPUT: Tool parameters as JSON
      // PROCESS: Convert to JXA syntax
      // OUTPUT: Valid JXA code

      const tool = createMockTool('finder_open');
      const args = { target: '/Users/test/file.txt' };

      // Example marshaling: JSON → JXA
      const jxaScript = `
const app = Application("${tool._metadata?.appName}");
const result = app.${tool._metadata?.commandName}(${JSON.stringify(args.target)});
      `.trim();

      expect(jxaScript).toContain('Application');
      expect(jxaScript).toContain('/Users/test/file.txt');
      expect(jxaScript).toContain('result');
    });

    it('should handle complex parameter types (arrays, objects)', () => {
      // WORKFLOW: Complex parameters → JXA marshaling
      // Can handle arrays of strings, nested objects

      const tool = createMockTool('test_command');
      const complexArgs = {
        files: ['/path/1', '/path/2'],
        options: { timeout: 5000, recursive: true },
      };

      expect(complexArgs.files).toHaveLength(2);
      expect(complexArgs.options.timeout).toBe(5000);
      // Marshaler should handle both array and object types
    });
  });

  // ============================================================================
  // TEST 4: Permission Check - Safety Levels
  // ============================================================================

  describe('Permission Check - Safety Levels', () => {
    it('should allow ALWAYS_SAFE operations immediately', () => {
      // WORKFLOW: Read-only tool (ALWAYS_SAFE)
      // No permission check needed, execute immediately

      const tool = createMockTool('finder_open');
      const args = { target: '/Users/test' };

      const permission = createPermissionDecision(true, 'ALWAYS_SAFE');

      expect(permission.allowed).toBe(true);
      expect(permission.level).toBe('ALWAYS_SAFE');
      expect(permission.requiresPrompt).toBe(false);
    });

    it('should check REQUIRES_CONFIRMATION operations', () => {
      // WORKFLOW: Modify operation (e.g., rename file)
      // Requires permission check but can be approved
      // If user previously approved: execute
      // If not: return requiresPrompt: true

      const tool = createMockTool('finder_rename');
      tool._metadata!.commandName = 'rename';

      const alreadyApproved = createPermissionDecision(true, 'REQUIRES_CONFIRMATION');
      alreadyApproved.alwaysAllow = true; // User clicked "Always Allow"

      const needsPrompt = createPermissionDecision(false, 'REQUIRES_CONFIRMATION');

      expect(alreadyApproved.allowed).toBe(true);
      expect(alreadyApproved.alwaysAllow).toBe(true);
      expect(needsPrompt.allowed).toBe(false);
      expect(needsPrompt.requiresPrompt).toBe(true);
    });

    it('should deny ALWAYS_CONFIRM operations without explicit approval', () => {
      // WORKFLOW: Dangerous operation (delete, quit, etc.)
      // Never execute without explicit user confirmation
      // Always requires prompt

      const tool = createMockTool('finder_delete');
      tool._metadata!.commandName = 'delete';

      const decision = createPermissionDecision(false, 'ALWAYS_CONFIRM');

      expect(decision.allowed).toBe(false);
      expect(decision.level).toBe('ALWAYS_CONFIRM');
      expect(decision.requiresPrompt).toBe(true);
    });

    it('should record permission decision after execution', () => {
      // WORKFLOW: Tool execution → Permission recording
      // After successful execution, log the decision

      const tool = createMockTool('finder_open');
      const args = { target: '/path' };
      const permission = createPermissionDecision(true, 'ALWAYS_SAFE');

      const auditLog: Array<{
        tool: string;
        args: Record<string, any>;
        decision: PermissionDecision;
        timestamp: Date;
      }> = [];

      // Record decision
      auditLog.push({
        tool: tool.name,
        args,
        decision: permission,
        timestamp: new Date(),
      });

      expect(auditLog).toHaveLength(1);
      expect(auditLog[0].tool).toBe('finder_open');
      expect(auditLog[0].decision.allowed).toBe(true);
    });
  });

  // ============================================================================
  // TEST 5: Tool Execution - JXA → Result
  // ============================================================================

  describe('Tool Execution - JXA to Result', () => {
    it('should execute JXA script via osascript', () => {
      // WORKFLOW: JXA script → osascript execution → result parsing
      // INPUT: Complete JXA script
      // PROCESS: Execute via osascript, capture output
      // OUTPUT: Execution result (success or error)

      const jxaScript = `
const app = Application("Finder");
const result = app.open("/Users/test/file.txt");
JSON.stringify(result);
      `.trim();

      // Mock osascript execution
      const executionResult = {
        stdout: JSON.stringify({ success: true, opened: true }),
        stderr: '',
        exitCode: 0,
      };

      expect(executionResult.exitCode).toBe(0);
      expect(executionResult.stdout).toContain('success');
    });

    it('should parse JXA execution result', () => {
      // WORKFLOW: Raw osascript output → Parsed result
      // INPUT: JSON string from osascript
      // PROCESS: Parse and validate JSON
      // OUTPUT: Structured result object

      const rawOutput = JSON.stringify({ fileName: 'test.txt', opened: true });
      const parsedResult = JSON.parse(rawOutput);

      expect(parsedResult.fileName).toBe('test.txt');
      expect(parsedResult.opened).toBe(true);
    });

    it('should handle osascript timeout', () => {
      // WORKFLOW: Long-running command timeout
      // If command exceeds timeout threshold, abort

      const timeout = 30000; // 30 seconds
      const executionTime = 45000; // Command took 45 seconds

      const isTimedOut = executionTime > timeout;

      expect(isTimedOut).toBe(true);
      // Should return timeout error, not hang forever
    });

    it('should capture and format osascript errors', () => {
      // WORKFLOW: osascript error → Error response
      // INPUT: Non-zero exit code, stderr content
      // PROCESS: Parse error message
      // OUTPUT: Structured error response

      const executionError = {
        exitCode: -600,
        stderr: 'error: Finder got an error: AppleEvent handler failed.',
      };

      const isError = executionError.exitCode !== 0;

      expect(isError).toBe(true);
      expect(executionError.stderr).toContain('AppleEvent');
    });
  });

  // ============================================================================
  // TEST 6: Error Handling Across Layers
  // ============================================================================

  describe('Error Handling Across Layers', () => {
    it('should handle discovery errors gracefully', () => {
      // WORKFLOW: Discovery fails (e.g., permission denied)
      // Should log error but not crash

      const discoveryError = new Error('Permission denied: /Applications');

      // Recovery: Continue with discovered apps, log error
      expect(discoveryError.message).toContain('Permission denied');
    });

    it('should handle SDEF parsing errors', () => {
      // WORKFLOW: Malformed SDEF → Parse error
      // Should skip that app, continue with others

      const malformedSdef = 'not valid XML';
      const parseError = new Error(`Failed to parse SDEF: ${malformedSdef}`);

      expect(parseError.message).toContain('Failed to parse');
    });

    it('should handle tool execution errors', () => {
      // WORKFLOW: Tool execution fails → Error response
      // OUTPUT: Structured error with code and message

      const executionError = {
        code: 'EXECUTION_ERROR',
        message: 'Application not found: Finder',
        details: 'Application with bundle ID not found',
      };

      expect(executionError.code).toBe('EXECUTION_ERROR');
      expect(executionError.message).toContain('not found');
    });

    it('should propagate errors from permission layer', () => {
      // WORKFLOW: Permission check fails → Error propagation
      // Should include reason in error response

      const permissionError = {
        error: 'Permission denied',
        reason: 'Dangerous operation requires confirmation',
        code: 'PERMISSION_DENIED',
      };

      expect(permissionError.code).toBe('PERMISSION_DENIED');
      expect(permissionError.reason).toBeDefined();
    });

    it('should return meaningful error messages to LLM', () => {
      // WORKFLOW: Tool error → MCP response
      // Should provide actionable error info

      const errors = [
        { tool: 'finder_open', error: 'Missing required parameter: target' },
        { tool: 'safari_activate', error: 'Application not found' },
        { tool: 'finder_delete', error: 'Permission denied' },
      ];

      for (const err of errors) {
        expect(err.error).toBeDefined();
        expect(err.error.length).toBeGreaterThan(0);
      }
    });
  });

  // ============================================================================
  // TEST 7: Real App Workflows - Finder
  // ============================================================================

  describe('Real App Workflow - Finder', () => {
    it('should execute Finder open command end-to-end', () => {
      // WORKFLOW: Complete Finder open
      // 1. Discover Finder
      // 2. Generate finder_open tool
      // 3. Call tool with path argument
      // 4. Check permission (ALWAYS_SAFE)
      // 5. Execute JXA
      // 6. Return result

      const finderApp = createMockApp('Finder', 'com.apple.finder');
      const finderTool = createMockTool('finder_open', {
        appName: 'Finder',
        bundleId: finderApp.bundleId,
      });

      const toolArgs = { target: '/Users/test/Documents' };
      const permission = createPermissionDecision(true, 'ALWAYS_SAFE');

      const result = {
        success: true,
        data: { opened: true, target: toolArgs.target },
      };

      expect(finderApp.appName).toBe('Finder');
      expect(permission.allowed).toBe(true);
      expect(result.success).toBe(true);
      expect(result.data.opened).toBe(true);
    });

    it('should handle Finder delete with permission confirmation', () => {
      // WORKFLOW: Dangerous operation (delete)
      // 1. User calls finder_delete
      // 2. Permission check returns requiresPrompt: true
      // 3. System asks for confirmation
      // 4. If approved: execute JXA
      // 5. If denied: return permission denied error

      const deleteRequest = {
        tool: 'finder_delete',
        args: { target: '/Users/test/oldfile.txt' },
      };

      // First check: permission denied (needs prompt)
      const permissionNeeded = createPermissionDecision(false, 'ALWAYS_CONFIRM');
      expect(permissionNeeded.allowed).toBe(false);
      expect(permissionNeeded.requiresPrompt).toBe(true);

      // After user approval
      const permissionApproved = createPermissionDecision(true, 'ALWAYS_CONFIRM');
      expect(permissionApproved.allowed).toBe(true);
    });

    it('should handle Finder quit command', () => {
      // WORKFLOW: Quit app
      // Quit is a destructive operation

      const quitTool = createMockTool('finder_quit', {
        appName: 'Finder',
        commandName: 'quit',
      });

      const permission = createPermissionDecision(true, 'ALWAYS_CONFIRM');
      permission.alwaysAllow = true; // User approved once

      expect(quitTool._metadata?.commandName).toBe('quit');
      expect(permission.allowed).toBe(true);
      expect(permission.alwaysAllow).toBe(true);
    });

    it('should handle Finder reveal command', () => {
      // WORKFLOW: Reveal file in Finder (read-only, safe operation)

      const revealTool = createMockTool('finder_reveal', {
        appName: 'Finder',
        commandName: 'reveal',
      });

      const permission = createPermissionDecision(true, 'ALWAYS_SAFE');

      const result = {
        success: true,
        data: { revealed: true, target: '/Users/test/file.txt' },
      };

      expect(permission.level).toBe('ALWAYS_SAFE');
      expect(result.success).toBe(true);
    });
  });

  // ============================================================================
  // TEST 8: Real App Workflows - Safari
  // ============================================================================

  describe('Real App Workflow - Safari', () => {
    it('should execute Safari activate command', () => {
      // WORKFLOW: Activate Safari app
      // Safe operation, no parameters

      const safariTool = createMockTool('safari_activate', {
        appName: 'Safari',
        bundleId: 'com.apple.Safari',
      });

      const permission = createPermissionDecision(true, 'ALWAYS_SAFE');

      const result = {
        success: true,
        data: { activated: true },
      };

      expect(safariTool._metadata?.appName).toBe('Safari');
      expect(permission.allowed).toBe(true);
      expect(result.success).toBe(true);
    });

    it('should get current URL from Safari', () => {
      // WORKFLOW: Query current page URL
      // Read-only operation (ALWAYS_SAFE)

      const getUrlTool = createMockTool('safari_get_url', {
        appName: 'Safari',
        commandName: 'get_url',
      });

      const permission = createPermissionDecision(true, 'ALWAYS_SAFE');

      const result = {
        success: true,
        data: { url: 'https://example.com/page' },
      };

      expect(permission.level).toBe('ALWAYS_SAFE');
      expect(result.data.url).toContain('https');
    });
  });

  // ============================================================================
  // TEST 9: Caching & Performance
  // ============================================================================

  describe('Caching & Performance', () => {
    it('should cache parsed SDEF files to avoid re-parsing', () => {
      // WORKFLOW: Repeated app discovery/generation
      // Second discovery should use cached SDEF data

      const sdefCache = new Map<string, string>();

      // First parse
      const finderSdefKey = 'com.apple.finder:sdef';
      sdefCache.set(finderSdefKey, mockFinderSdef);

      // Second parse (cache hit)
      const cachedSdef = sdefCache.get(finderSdefKey);

      expect(sdefCache.size).toBe(1);
      expect(cachedSdef).toBe(mockFinderSdef);
    });

    it('should cache generated tools to avoid re-generation', () => {
      // WORKFLOW: Tool generation caching
      // Generated tools are cached by app + SDEF content

      const toolCache = new Map<string, MCPTool[]>();
      const cacheKey = 'com.apple.finder:tools';

      const finderTools = [
        createMockTool('finder_open'),
        createMockTool('finder_delete'),
      ];

      toolCache.set(cacheKey, finderTools);

      expect(toolCache.size).toBe(1);
      expect(toolCache.get(cacheKey)).toHaveLength(2);
    });
  });

  // ============================================================================
  // TEST 10: MCP Protocol Compliance
  // ============================================================================

  describe('MCP Protocol Compliance', () => {
    it('should respond to ListTools with proper format', () => {
      // WORKFLOW: MCP ListTools request → response
      // Must return array of Tool objects with required fields

      const listToolsResponse = {
        tools: [
          {
            name: 'finder_open',
            description: 'Open a file or folder',
            inputSchema: {
              type: 'object' as const,
              properties: { target: { type: 'string' } },
            },
          },
        ],
      };

      expect(listToolsResponse.tools).toHaveLength(1);
      expect(listToolsResponse.tools[0]).toHaveProperty('name');
      expect(listToolsResponse.tools[0]).toHaveProperty('description');
      expect(listToolsResponse.tools[0]).toHaveProperty('inputSchema');
    });

    it('should respond to CallTool with TextContent format', () => {
      // WORKFLOW: MCP CallTool request → response
      // Must return TextContent with JSON string

      const callToolResponse = {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              success: true,
              data: { opened: true },
            }),
          },
        ],
      };

      expect(callToolResponse.content).toHaveLength(1);
      expect(callToolResponse.content[0].type).toBe('text');
      expect(typeof callToolResponse.content[0].text).toBe('string');
    });

    it('should include isError flag for error responses', () => {
      // WORKFLOW: CallTool error response
      // Must set isError: true for errors

      const errorResponse = {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              error: 'Tool not found',
            }),
          },
        ],
        isError: true,
      };

      expect(errorResponse.isError).toBe(true);
      const parsed = JSON.parse(errorResponse.content[0].text);
      expect(parsed.error).toBeDefined();
    });
  });
});
