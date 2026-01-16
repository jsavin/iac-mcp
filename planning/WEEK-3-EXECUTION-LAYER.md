# Week 3: Tool Execution Layer - TDD Implementation Plan

## Executive Summary

**Goal:** Implement the execution layer that takes generated MCP tools from Week 2 and executes them on macOS via JXA (JavaScript for Automation).

**Timeline:** 5-7 days (25-35 hours @ 5 hours/day)

**What We're Building:**
- JXA execution engine (osascript integration)
- Parameter marshaling (JSON → JXA/AppleScript types)
- Result parsing (JXA output → JSON)
- Error handling (app not found, permission denied, timeouts)
- Basic permission system (read-only, modify, dangerous classification)
- MCP server integration (ListTools, CallTool handlers)

**Success Criteria:**
- Can execute Finder commands via JXA
- Can execute Safari commands via JXA
- Can execute Mail commands via JXA
- Handles errors gracefully (no crashes)
- Returns structured JSON results
- Works with Claude Desktop end-to-end
- 80%+ test coverage across all modules

---

## Architecture Overview

### Components to Build

```
src/
├── adapters/                    # Platform adapters (Week 3 focus)
│   └── macos/
│       ├── index.ts            # Main MacOSAdapter class
│       ├── jxa-executor.ts     # JXA script execution
│       ├── parameter-marshaler.ts  # JSON → JXA conversion
│       ├── result-parser.ts    # JXA → JSON conversion
│       └── error-handler.ts    # Error classification & messages
│
├── permissions/                 # Permission system
│   ├── index.ts                # Main PermissionChecker class
│   ├── classifier.ts           # Classify operations as safe/modify/dangerous
│   ├── rules.ts                # Permission rules engine
│   └── types.ts                # Permission types
│
├── mcp/                         # MCP server implementation
│   ├── server.ts               # MCP server setup & handlers
│   ├── handlers.ts             # ListTools, CallTool implementations
│   └── types.ts                # MCP-specific types
│
└── types/
    └── execution.ts            # Execution layer types

tests/
├── unit/
│   ├── jxa-executor.test.ts
│   ├── parameter-marshaler.test.ts
│   ├── result-parser.test.ts
│   ├── error-handler.test.ts
│   ├── permission-classifier.test.ts
│   └── mcp-handlers.test.ts
│
└── integration/
    ├── finder-execution.test.ts
    ├── safari-execution.test.ts
    ├── mail-execution.test.ts
    └── end-to-end.test.ts
```

### Data Flow

```
1. Claude Desktop → MCP CallTool request
   └─ { name: "finder_open", arguments: { target: "/path/to/file" } }

2. MCP Server → Permission Check
   └─ PermissionChecker.check("finder_open", { target: "/path/to/file" })
   └─ Returns: ALLOW / DENY / PROMPT

3. MCP Server → MacOSAdapter.execute()
   └─ Receives: tool metadata + arguments

4. ParameterMarshaler → Convert JSON to JXA
   └─ { target: "/path/to/file" } → `Path("/path/to/file")`

5. JXAExecutor → Build & run script
   └─ Generates: `Application("Finder").open(Path("/path/to/file"))`
   └─ Executes: `osascript -l JavaScript -e "script"`

6. ResultParser → Parse JXA output
   └─ Parses stdout/stderr
   └─ Converts to JSON

7. MCP Server → Return result to Claude
   └─ { content: [{ type: "text", text: JSON.stringify(result) }] }
```

---

## Module Specifications

### Module 1: JXA Executor

**File:** `src/adapters/macos/jxa-executor.ts`

**Responsibility:** Execute JXA scripts via osascript and handle low-level execution

**API:**
```typescript
export class JXAExecutor {
  /**
   * Execute JXA script via osascript
   * @param script - JXA script code
   * @param options - Execution options (timeout, etc.)
   * @returns Execution result with stdout/stderr
   */
  execute(script: string, options?: ExecutionOptions): Promise<ExecutionResult>;

  /**
   * Check if osascript is available
   */
  isAvailable(): Promise<boolean>;

  /**
   * Get osascript version
   */
  getVersion(): Promise<string>;
}

interface ExecutionOptions {
  timeoutMs?: number;        // Default: 30000 (30 seconds)
  captureStderr?: boolean;   // Default: true
}

interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}
```

**Implementation Notes:**
- Use Node.js `child_process.spawn` or `execFile`
- Set timeout using AbortController (Node 15+) or setTimeout + kill
- Capture both stdout and stderr
- Handle process exit codes
- Use `-l JavaScript` flag for JXA
- Use `-e` flag for inline scripts

**Error Scenarios:**
- osascript not found (should never happen on macOS, but check)
- Script timeout
- Script syntax error
- App not running/not found
- Permission denied

---

### Module 2: Parameter Marshaler

**File:** `src/adapters/macos/parameter-marshaler.ts`

**Responsibility:** Convert JSON parameters to JXA-compatible code

**API:**
```typescript
export class ParameterMarshaler {
  /**
   * Marshal JSON parameters to JXA code
   * @param params - JSON parameters from MCP tool call
   * @param schema - JSON Schema for validation
   * @param metadata - Tool metadata (for type hints)
   * @returns JXA code representing the parameters
   */
  marshal(
    params: Record<string, any>,
    schema: JSONSchema,
    metadata: ToolMetadata
  ): string;

  /**
   * Marshal a single value based on JSON Schema type
   * @param value - Value to marshal
   * @param schema - Schema for this value
   * @returns JXA code string
   */
  marshalValue(value: any, schema: JSONSchemaProperty): string;
}
```

**Type Mapping Table:**

| JSON Type | JSON Value | JXA Code | Notes |
|-----------|------------|----------|-------|
| `string` (path) | `"/path/file"` | `Path("/path/file")` | If schema has `format: "path"` |
| `string` (regular) | `"hello"` | `"hello"` | Regular string |
| `number` | `42` | `42` | Direct number |
| `boolean` | `true` | `true` | Direct boolean |
| `array` | `[1, 2, 3]` | `[1, 2, 3]` | Array literal |
| `object` | `{a: 1}` | `{a: 1}` | Object literal |
| `enum` | `"value"` | `"value"` | Validated against enum |
| `null` | `null` | `null` | Null value |

**Special Cases:**
- **File paths:** Detect if parameter name is `target`, `to`, `from`, `path`, or schema has `format: "path"`
  - Wrap in `Path()` constructor: `Path("/Users/...")`
- **Enumerations:** Validate against enum values from schema
  - Some SDEF enums need mapping (e.g., `yes` → `true`)
- **Lists:** Recursively marshal array items
- **Records:** Recursively marshal object properties

**Implementation Notes:**
- Escape strings properly (quotes, backslashes)
- Handle undefined/null values gracefully
- Validate against schema before marshaling
- Preserve type information from SDEF metadata

---

### Module 3: Result Parser

**File:** `src/adapters/macos/result-parser.ts`

**Responsibility:** Parse JXA execution output and convert to JSON

**API:**
```typescript
export class ResultParser {
  /**
   * Parse JXA execution result
   * @param result - Raw execution result from JXAExecutor
   * @param metadata - Tool metadata (for type hints)
   * @returns Parsed JSON result
   */
  parse(result: ExecutionResult, metadata: ToolMetadata): ParsedResult;

  /**
   * Parse JXA error from stderr
   * @param stderr - Error output
   * @returns Classified error
   */
  parseError(stderr: string): JXAError;
}

interface ParsedResult {
  success: boolean;
  data?: any;
  error?: JXAError;
}

interface JXAError {
  type: 'APP_NOT_FOUND' | 'PERMISSION_DENIED' | 'INVALID_PARAM' | 'EXECUTION_ERROR' | 'TIMEOUT';
  message: string;
  originalError?: string;
}
```

**Implementation Notes:**
- JXA returns results as strings to stdout
- Simple values: `"hello"`, `42`, `true` (parse as JSON)
- Complex values: `{"key": "value"}` (parse as JSON)
- File references: `Path("/path/to/file")` (convert to path string)
- Arrays: `[item1, item2]` (parse as JSON)
- Null/undefined: Handle gracefully

**Error Patterns to Detect:**
- App not found: `Error: Application can't be found.`
- Permission denied: `Error: Not authorized to send Apple events`
- Invalid parameter: `Error: Can't get object`
- Timeout: Process killed by timeout
- Syntax error: `Error: Syntax Error`

**Edge Cases:**
- Empty result (void commands)
- Large results (truncate?)
- Binary data (encode as base64?)
- Special characters in strings

---

### Module 4: Error Handler

**File:** `src/adapters/macos/error-handler.ts`

**Responsibility:** Classify errors and generate user-friendly messages

**API:**
```typescript
export class ErrorHandler {
  /**
   * Handle execution error and generate user-friendly message
   * @param error - Raw error from execution
   * @param context - Context for better error messages
   * @returns Classified error with user-friendly message
   */
  handle(error: Error | ExecutionResult, context: ExecutionContext): HandledError;

  /**
   * Check if error is retryable
   * @param error - Error to check
   * @returns True if user should retry
   */
  isRetryable(error: HandledError): boolean;
}

interface ExecutionContext {
  appName: string;
  commandName: string;
  parameters: Record<string, any>;
}

interface HandledError {
  type: ErrorType;
  message: string;            // User-friendly message
  suggestion?: string;        // What user should do
  retryable: boolean;
  originalError: string;      // Technical details
}

type ErrorType =
  | 'APP_NOT_FOUND'
  | 'APP_NOT_RUNNING'
  | 'PERMISSION_DENIED'
  | 'INVALID_PARAMETER'
  | 'EXECUTION_ERROR'
  | 'TIMEOUT'
  | 'UNKNOWN';
```

**User-Friendly Error Messages:**

| Error Type | User Message | Suggestion |
|------------|--------------|------------|
| `APP_NOT_FOUND` | "The application '{appName}' could not be found." | "Please ensure {appName} is installed." |
| `APP_NOT_RUNNING` | "{appName} needs to be running to execute this command." | "Please launch {appName} and try again." |
| `PERMISSION_DENIED` | "Permission denied to control {appName}." | "Grant automation permission in System Settings → Privacy & Security → Automation." |
| `INVALID_PARAMETER` | "Invalid parameter: {details}" | "Check the parameter format and try again." |
| `TIMEOUT` | "The command timed out after {seconds} seconds." | "Try again or check if {appName} is responding." |
| `EXECUTION_ERROR` | "Error executing command: {details}" | "Check the command parameters and {appName} state." |

---

### Module 5: MacOS Adapter (Main)

**File:** `src/adapters/macos/index.ts`

**Responsibility:** Main adapter that orchestrates execution

**API:**
```typescript
export class MacOSAdapter {
  constructor(options?: AdapterOptions);

  /**
   * Execute an MCP tool on macOS
   * @param tool - Complete MCP tool definition
   * @param args - Arguments from MCP CallTool request
   * @returns Execution result
   */
  async execute(tool: MCPTool, args: Record<string, any>): Promise<ExecutionResult>;

  /**
   * Test if app is available
   * @param bundleId - App bundle identifier
   * @returns True if app is installed and scriptable
   */
  async testApp(bundleId: string): Promise<boolean>;

  /**
   * Build JXA script for a tool
   * @param tool - MCP tool definition
   * @param args - Marshaled arguments
   * @returns JXA script code
   */
  buildJXAScript(tool: MCPTool, args: Record<string, any>): string;
}

interface AdapterOptions {
  timeoutMs?: number;
  enableLogging?: boolean;
}
```

**JXA Script Template:**
```javascript
// Basic structure for generated scripts
(() => {
  const app = Application("{appName}");
  app.includeStandardAdditions = true;

  // Marshal parameters
  const params = {marshaledParams};

  // Execute command
  const result = app.{commandName}(params);

  // Return result (will be stringified)
  return result;
})()
```

**Implementation Flow:**
1. Validate tool metadata exists
2. Marshal parameters using ParameterMarshaler
3. Build JXA script
4. Execute script using JXAExecutor
5. Parse result using ResultParser
6. Handle errors using ErrorHandler
7. Return formatted result

---

### Module 6: Permission Classifier

**File:** `src/permissions/classifier.ts`

**Responsibility:** Classify commands as safe, modify, or dangerous

**API:**
```typescript
export class PermissionClassifier {
  /**
   * Classify a command's permission level
   * @param tool - MCP tool definition
   * @param args - Command arguments
   * @returns Permission level
   */
  classify(tool: MCPTool, args: Record<string, any>): PermissionLevel;

  /**
   * Register custom classification rule
   * @param rule - Custom rule
   */
  registerRule(rule: ClassificationRule): void;
}

type PermissionLevel = 'SAFE' | 'MODIFY' | 'DANGEROUS';

interface ClassificationRule {
  // Match condition
  matcher: (tool: MCPTool, args: Record<string, any>) => boolean;
  // Classification result
  level: PermissionLevel;
  // Reason for classification
  reason: string;
}
```

**Classification Rules (MVP):**

**SAFE (Always Allow):**
- Read-only operations
  - Commands like: `list`, `get`, `find`, `search`, `count`
  - Examples: `finder_list_folder`, `safari_get_url`, `mail_count_messages`
- No side effects on system or data

**MODIFY (Prompt First Time, Allow "Always Allow"):**
- Modify data but not destructive
  - Commands like: `set`, `make`, `move`, `copy`, `duplicate`, `save`
  - Examples: `finder_move`, `mail_send_message`, `notes_make_note`
- Can be undone or recovered

**DANGEROUS (Always Prompt):**
- Destructive or system-affecting operations
  - Commands like: `delete`, `remove`, `quit`, `restart`, `shutdown`, `trash`
  - Examples: `finder_delete`, `system_quit_application`
- Cannot be easily undone
- Affects system stability

**Implementation Strategy:**
- Start with keyword-based classification
- Build safelist for known safe commands
- Build blocklist for known dangerous commands
- Default to MODIFY for unknown commands
- Allow override via config file (future)

---

### Module 7: Permission Checker

**File:** `src/permissions/index.ts`

**Responsibility:** Check permissions and enforce rules

**API:**
```typescript
export class PermissionChecker {
  constructor(options?: PermissionOptions);

  /**
   * Check if command should be allowed
   * @param tool - MCP tool definition
   * @param args - Command arguments
   * @returns Permission decision
   */
  async check(tool: MCPTool, args: Record<string, any>): Promise<PermissionDecision>;

  /**
   * Record user decision for future reference
   * @param decision - Permission decision with user choice
   */
  async recordDecision(decision: PermissionDecision): Promise<void>;

  /**
   * Get audit log
   * @returns Recent permission decisions and executions
   */
  getAuditLog(): PermissionAuditEntry[];
}

interface PermissionDecision {
  allowed: boolean;
  level: PermissionLevel;
  reason: string;
  requiresPrompt: boolean;
  alwaysAllow?: boolean;      // User chose "always allow"
}

interface PermissionAuditEntry {
  timestamp: Date;
  tool: string;
  args: Record<string, any>;
  decision: PermissionDecision;
  executed: boolean;
  result?: any;
}
```

**MVP Implementation:**
- Store permissions in memory (JSON file in future)
- Log all executions to audit log
- No UI prompts yet (return `requiresPrompt: true`, caller handles)
- Simple rule engine (just classification)

---

### Module 8: MCP Server

**File:** `src/mcp/server.ts`

**Responsibility:** MCP protocol server setup and lifecycle

**API:**
```typescript
export class IACMCPServer {
  constructor(options?: ServerOptions);

  /**
   * Initialize the MCP server
   * - Discover apps
   * - Generate tools
   * - Setup handlers
   */
  async initialize(): Promise<void>;

  /**
   * Start the MCP server (stdio transport)
   */
  async start(): Promise<void>;

  /**
   * Stop the MCP server
   */
  async stop(): Promise<void>;

  /**
   * Get server status
   */
  getStatus(): ServerStatus;
}

interface ServerOptions {
  discoveryPaths?: string[];
  enableCache?: boolean;
  cacheDir?: string;
  timeoutMs?: number;
}

interface ServerStatus {
  running: boolean;
  appsDiscovered: number;
  toolsGenerated: number;
  uptime: number;
}
```

**Implementation:**
- Use `@modelcontextprotocol/sdk` Server class
- Use StdioServerTransport
- Register ListTools and CallTool handlers
- Integrate with discovery and generation from Weeks 1-2
- Integrate with execution layer (Week 3)

---

### Module 9: MCP Handlers

**File:** `src/mcp/handlers.ts`

**Responsibility:** Implement MCP protocol handlers

**API:**
```typescript
/**
 * Setup MCP request handlers
 */
export function setupHandlers(
  server: Server,
  toolGenerator: ToolGenerator,
  adapter: MacOSAdapter,
  permissionChecker: PermissionChecker
): void;

/**
 * Handle ListTools request
 */
export async function handleListTools(
  request: ListToolsRequest
): Promise<ListToolsResponse>;

/**
 * Handle CallTool request
 */
export async function handleCallTool(
  request: CallToolRequest
): Promise<CallToolResponse>;
```

**ListTools Handler:**
```typescript
server.setRequestHandler(ListToolsRequestSchema, async () => {
  // Get all discovered apps
  const apps = await discoverer.discover();

  // Generate tools for all apps
  const allTools: MCPTool[] = [];
  for (const app of apps) {
    const dictionary = await parser.parse(app.sdefPath);
    const tools = toolGenerator.generateTools(dictionary, app);
    allTools.push(...tools);
  }

  // Return MCP response
  return {
    tools: allTools.map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    }))
  };
});
```

**CallTool Handler:**
```typescript
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // Find tool by name
  const tool = findToolByName(name);
  if (!tool) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ error: 'Tool not found' })
      }],
      isError: true
    };
  }

  // Check permissions
  const permission = await permissionChecker.check(tool, args);
  if (!permission.allowed) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Permission denied',
          reason: permission.reason
        })
      }],
      isError: true
    };
  }

  // Execute tool
  try {
    const result = await adapter.execute(tool, args);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: error.message
        })
      }],
      isError: true
    };
  }
});
```

---

## Test Strategy

### TDD Approach

**Golden Rule:** Write tests first, then implementation.

**Test Pyramid:**
- 70% Unit tests (fast, isolated)
- 20% Integration tests (real apps, slower)
- 10% End-to-end tests (full stack)

**Coverage Target:** 80%+ across all modules

---

### Unit Tests

#### 1. JXA Executor Tests
**File:** `tests/unit/jxa-executor.test.ts`

**Test Cases:**
```typescript
describe('JXAExecutor', () => {
  describe('execute()', () => {
    it('should execute simple JXA script successfully');
    it('should capture stdout from script');
    it('should capture stderr from script');
    it('should return exit code 0 for successful execution');
    it('should return non-zero exit code for failed execution');
    it('should timeout long-running scripts');
    it('should set timedOut flag when timeout occurs');
    it('should handle script syntax errors');
    it('should handle osascript not found (mock)');
    it('should kill process on timeout');
  });

  describe('isAvailable()', () => {
    it('should return true on macOS with osascript');
    it('should return false if osascript missing (mock)');
  });

  describe('getVersion()', () => {
    it('should return osascript version string');
  });
});
```

**Mocking Strategy:**
- Mock `child_process.spawn` for controlled testing
- Test real osascript for one integration test
- Mock timeout scenarios

---

#### 2. Parameter Marshaler Tests
**File:** `tests/unit/parameter-marshaler.test.ts`

**Test Cases:**
```typescript
describe('ParameterMarshaler', () => {
  describe('marshal() - basic types', () => {
    it('should marshal string parameter');
    it('should marshal number parameter');
    it('should marshal boolean parameter');
    it('should marshal null parameter');
    it('should marshal undefined as null');
  });

  describe('marshal() - complex types', () => {
    it('should marshal array of strings');
    it('should marshal array of numbers');
    it('should marshal nested arrays');
    it('should marshal object with properties');
    it('should marshal nested objects');
  });

  describe('marshal() - special types', () => {
    it('should marshal file path as Path() constructor');
    it('should detect path from parameter name (target, path, file)');
    it('should detect path from schema format hint');
    it('should marshal enum value after validation');
    it('should throw error for invalid enum value');
  });

  describe('marshal() - edge cases', () => {
    it('should escape quotes in strings');
    it('should escape backslashes in strings');
    it('should handle empty strings');
    it('should handle empty arrays');
    it('should handle empty objects');
    it('should handle very long strings');
  });

  describe('marshalValue()', () => {
    it('should marshal string value');
    it('should marshal number value');
    it('should marshal boolean value');
    it('should marshal array value');
    it('should marshal object value');
    it('should throw error for unsupported type');
  });
});
```

**Test Data:**
```typescript
const testCases = [
  { input: 'hello', expected: '"hello"' },
  { input: 42, expected: '42' },
  { input: true, expected: 'true' },
  { input: [1, 2, 3], expected: '[1,2,3]' },
  { input: { a: 1 }, expected: '{a:1}' },
  { input: '/path/to/file', schema: { format: 'path' }, expected: 'Path("/path/to/file")' },
];
```

---

#### 3. Result Parser Tests
**File:** `tests/unit/result-parser.test.ts`

**Test Cases:**
```typescript
describe('ResultParser', () => {
  describe('parse() - success cases', () => {
    it('should parse string result');
    it('should parse number result');
    it('should parse boolean result');
    it('should parse null result');
    it('should parse array result');
    it('should parse object result');
    it('should parse empty result (void command)');
    it('should parse file path result');
    it('should parse large result');
  });

  describe('parse() - error cases', () => {
    it('should detect APP_NOT_FOUND error');
    it('should detect PERMISSION_DENIED error');
    it('should detect INVALID_PARAM error');
    it('should detect EXECUTION_ERROR');
    it('should detect TIMEOUT error');
    it('should handle unknown error format');
  });

  describe('parseError()', () => {
    it('should classify app not found error');
    it('should classify permission denied error');
    it('should classify invalid parameter error');
    it('should classify timeout error');
    it('should extract error message from stderr');
    it('should preserve original error');
  });

  describe('parse() - edge cases', () => {
    it('should handle malformed JSON');
    it('should handle very long output');
    it('should handle binary data (base64)');
    it('should handle special characters');
    it('should handle non-UTF8 output');
  });
});
```

**Test Data:**
```typescript
const errorPatterns = [
  {
    stderr: 'Error: Application can\'t be found.',
    expected: { type: 'APP_NOT_FOUND' }
  },
  {
    stderr: 'Error: Not authorized to send Apple events',
    expected: { type: 'PERMISSION_DENIED' }
  },
  {
    stderr: 'Error: Can\'t get object',
    expected: { type: 'INVALID_PARAM' }
  }
];
```

---

#### 4. Error Handler Tests
**File:** `tests/unit/error-handler.test.ts`

**Test Cases:**
```typescript
describe('ErrorHandler', () => {
  describe('handle()', () => {
    it('should generate user-friendly message for APP_NOT_FOUND');
    it('should generate user-friendly message for PERMISSION_DENIED');
    it('should generate user-friendly message for TIMEOUT');
    it('should generate user-friendly message for INVALID_PARAMETER');
    it('should generate user-friendly message for EXECUTION_ERROR');
    it('should include suggestion for each error type');
    it('should preserve original error for debugging');
    it('should include app name in context');
    it('should include command name in context');
  });

  describe('isRetryable()', () => {
    it('should return true for timeout errors');
    it('should return true for app not running errors');
    it('should return false for permission denied errors');
    it('should return false for invalid parameter errors');
    it('should return false for app not found errors');
  });
});
```

---

#### 5. Permission Classifier Tests
**File:** `tests/unit/permission-classifier.test.ts`

**Test Cases:**
```typescript
describe('PermissionClassifier', () => {
  describe('classify() - SAFE operations', () => {
    it('should classify list commands as SAFE');
    it('should classify get commands as SAFE');
    it('should classify find commands as SAFE');
    it('should classify count commands as SAFE');
    it('should classify search commands as SAFE');
  });

  describe('classify() - MODIFY operations', () => {
    it('should classify set commands as MODIFY');
    it('should classify make commands as MODIFY');
    it('should classify move commands as MODIFY');
    it('should classify copy commands as MODIFY');
    it('should classify duplicate commands as MODIFY');
    it('should classify save commands as MODIFY');
  });

  describe('classify() - DANGEROUS operations', () => {
    it('should classify delete commands as DANGEROUS');
    it('should classify remove commands as DANGEROUS');
    it('should classify quit commands as DANGEROUS');
    it('should classify trash commands as DANGEROUS');
    it('should classify shutdown commands as DANGEROUS');
  });

  describe('classify() - custom rules', () => {
    it('should allow registering custom rule');
    it('should apply custom rule when matched');
    it('should prioritize custom rules over default');
  });

  describe('classify() - edge cases', () => {
    it('should default to MODIFY for unknown commands');
    it('should handle command name variations (case)');
    it('should handle compound command names');
  });
});
```

---

#### 6. MCP Handlers Tests
**File:** `tests/unit/mcp-handlers.test.ts`

**Test Cases:**
```typescript
describe('MCP Handlers', () => {
  describe('handleListTools()', () => {
    it('should return all discovered tools');
    it('should include name, description, inputSchema');
    it('should handle empty tool list');
    it('should handle discovery errors gracefully');
  });

  describe('handleCallTool()', () => {
    it('should execute tool with valid arguments');
    it('should return result as text content');
    it('should return error if tool not found');
    it('should return error if permission denied');
    it('should return error if execution fails');
    it('should set isError flag for errors');
    it('should validate arguments against schema');
    it('should handle missing required parameters');
  });
});
```

---

### Integration Tests

#### 1. Finder Execution Tests
**File:** `tests/integration/finder-execution.test.ts`

**Test Cases:**
```typescript
describe('Finder Integration', () => {
  it('should list desktop items', async () => {
    // Setup
    const tool = findTool('finder_list_folder');
    const args = { path: '~/Desktop' };

    // Execute
    const result = await adapter.execute(tool, args);

    // Assert
    expect(result.success).toBe(true);
    expect(Array.isArray(result.data)).toBe(true);
  });

  it('should get file info', async () => {
    // Test getting info for a known file
  });

  it('should count items in folder', async () => {
    // Test counting items
  });

  it('should handle non-existent path gracefully', async () => {
    // Test error handling
  });
});
```

**Prerequisites:**
- Finder must be available (always is on macOS)
- Test files setup in temp directory
- Cleanup after tests

---

#### 2. Safari Execution Tests
**File:** `tests/integration/safari-execution.test.ts`

**Test Cases:**
```typescript
describe('Safari Integration', () => {
  it('should get current URL', async () => {
    // Requires Safari to be running with a tab
  });

  it('should get page title', async () => {
    // Requires Safari to be running
  });

  it('should count tabs', async () => {
    // Requires Safari to be running
  });

  it('should handle Safari not running', async () => {
    // Test error handling when Safari isn't open
  });
});
```

**Prerequisites:**
- Safari must be running for some tests
- Skip tests if Safari not available
- Use `test.skipIf()` for conditional skipping

---

#### 3. Mail Execution Tests
**File:** `tests/integration/mail-execution.test.ts`

**Test Cases:**
```typescript
describe('Mail Integration', () => {
  it('should count inbox messages', async () => {
    // Requires Mail app
  });

  it('should get mailbox names', async () => {
    // Requires Mail app
  });

  it('should handle Mail not configured', async () => {
    // Test when Mail has no accounts
  });
});
```

**Prerequisites:**
- Mail.app may not be configured on CI
- Skip tests gracefully if Mail not available
- Don't send actual emails in tests

---

#### 4. End-to-End Tests
**File:** `tests/integration/end-to-end.test.ts`

**Test Cases:**
```typescript
describe('End-to-End MCP Flow', () => {
  let server: IACMCPServer;

  beforeAll(async () => {
    server = new IACMCPServer();
    await server.initialize();
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('should complete full ListTools flow', async () => {
    // Simulate MCP ListTools request
    // Verify response contains tools
  });

  it('should complete full CallTool flow', async () => {
    // Simulate MCP CallTool request
    // Verify execution and response
  });

  it('should handle permission check in flow', async () => {
    // Test permission checking integration
  });

  it('should handle execution error in flow', async () => {
    // Test error handling end-to-end
  });
});
```

---

## Implementation Order

### Day 1: JXA Execution Foundation (5 hours)

**Goal:** Get basic JXA execution working

**Tasks:**
1. Write tests for JXAExecutor (1 hour)
   - Test basic execution
   - Test timeout handling
   - Test error capture

2. Implement JXAExecutor (2 hours)
   - Use child_process.spawn
   - Implement timeout with AbortController
   - Capture stdout/stderr

3. Write tests for ResultParser (1 hour)
   - Test parsing simple results
   - Test parsing errors

4. Implement ResultParser (1 hour)
   - Parse stdout as JSON
   - Classify errors from stderr

**Validation:**
```bash
npm test tests/unit/jxa-executor.test.ts
npm test tests/unit/result-parser.test.ts
```

**Deliverable:** Can execute JXA scripts and parse results

---

### Day 2: Parameter Marshaling (5 hours)

**Goal:** Convert JSON to JXA-compatible code

**Tasks:**
1. Write tests for ParameterMarshaler (2 hours)
   - Test all basic types
   - Test file path detection
   - Test enum validation
   - Test edge cases (escaping, etc.)

2. Implement ParameterMarshaler (2.5 hours)
   - Basic type marshaling
   - Path detection and wrapping
   - String escaping
   - Enum validation

3. Integration test with JXAExecutor (0.5 hours)
   - Marshal params → Execute → Parse result
   - Test full round-trip

**Validation:**
```bash
npm test tests/unit/parameter-marshaler.test.ts
```

**Deliverable:** Can convert JSON params to JXA code

---

### Day 3: MacOS Adapter Integration (5 hours)

**Goal:** Tie together execution components

**Tasks:**
1. Write tests for MacOSAdapter (1 hour)
   - Test buildJXAScript()
   - Test execute() with mocked components
   - Test error handling

2. Implement MacOSAdapter (2 hours)
   - Build JXA script from tool + args
   - Integrate executor, marshaler, parser
   - Error handling

3. Write integration tests (1 hour)
   - Finder list desktop
   - Finder get file info
   - Safari get URL (if running)

4. Run integration tests (1 hour)
   - Debug issues
   - Fix bugs
   - Verify all pass

**Validation:**
```bash
npm test tests/unit/macos-adapter.test.ts
npm test tests/integration/finder-execution.test.ts
```

**Deliverable:** Can execute Finder commands end-to-end

---

### Day 4: Permission System (5 hours)

**Goal:** Classify and check permissions

**Tasks:**
1. Write tests for PermissionClassifier (1.5 hours)
   - Test SAFE classification
   - Test MODIFY classification
   - Test DANGEROUS classification
   - Test custom rules

2. Implement PermissionClassifier (1.5 hours)
   - Keyword-based classification
   - Rule registry
   - Default behavior

3. Write tests for PermissionChecker (1 hour)
   - Test check() with different levels
   - Test audit log
   - Test decision recording

4. Implement PermissionChecker (1 hour)
   - Use classifier
   - In-memory permission store
   - Audit log

**Validation:**
```bash
npm test tests/unit/permission-classifier.test.ts
npm test tests/unit/permission-checker.test.ts
```

**Deliverable:** Can classify and check permissions

---

### Day 5: Error Handling (4 hours)

**Goal:** User-friendly error messages

**Tasks:**
1. Write tests for ErrorHandler (1 hour)
   - Test each error type
   - Test user-friendly messages
   - Test suggestions
   - Test retryable detection

2. Implement ErrorHandler (1.5 hours)
   - Error classification
   - Message templates
   - Context interpolation

3. Integrate with MacOSAdapter (1 hour)
   - Use ErrorHandler for all errors
   - Update integration tests

4. Manual testing (0.5 hours)
   - Test each error scenario
   - Verify messages are clear

**Validation:**
```bash
npm test tests/unit/error-handler.test.ts
```

**Deliverable:** Clear, actionable error messages

---

### Day 6: MCP Server Integration (6 hours)

**Goal:** Wire everything into MCP server

**Tasks:**
1. Write tests for MCP handlers (1.5 hours)
   - Test handleListTools()
   - Test handleCallTool()
   - Test error responses

2. Implement MCP handlers (2 hours)
   - ListTools integration
   - CallTool integration
   - Error formatting

3. Implement IACMCPServer class (1.5 hours)
   - Initialize discovery and generation
   - Setup handlers
   - Start/stop server

4. Write end-to-end test (1 hour)
   - Full MCP flow test
   - Verify ListTools returns tools
   - Verify CallTool executes

**Validation:**
```bash
npm test tests/unit/mcp-handlers.test.ts
npm test tests/integration/end-to-end.test.ts
```

**Deliverable:** MCP server working with stdio transport

---

### Day 7: Testing with Claude Desktop (3 hours)

**Goal:** Validate with real MCP client

**Tasks:**
1. Build and package (0.5 hours)
   ```bash
   npm run build
   ```

2. Configure Claude Desktop (0.5 hours)
   - Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Add iac-mcp server configuration
   - Restart Claude Desktop

3. Manual testing (1.5 hours)
   - Ask Claude: "What apps can you control?"
   - Try: "List files on my desktop"
   - Try: "Get current Safari URL"
   - Try dangerous command: "Delete file X" (should handle gracefully)
   - Test error scenarios

4. Bug fixes and polish (0.5 hours)
   - Fix any issues found
   - Improve error messages
   - Add logging

**Validation Checklist:**
- [ ] Claude can see available tools
- [ ] Claude can list desktop files successfully
- [ ] Claude can get Safari URL (if Safari running)
- [ ] Errors are clear and actionable
- [ ] Permission system works correctly
- [ ] No crashes or hangs

**Deliverable:** Working with Claude Desktop

---

## Integration with Weeks 1-2

### Dependencies from Week 1 (SDEF Parser)

**What We Need:**
- `SDEFDictionary` type
- `SDEFCommand` type
- `SDEFParameter` type
- `AppDiscoverer` class
- `SDEFParser` class

**How We Use It:**
```typescript
// Discover apps
const discoverer = new AppDiscoverer();
const apps = await discoverer.discover();

// Parse SDEF
const parser = new SDEFParser();
const dictionary = await parser.parse(app.sdefPath);
```

### Dependencies from Week 2 (Tool Generator)

**What We Need:**
- `MCPTool` type
- `ToolMetadata` type
- `JSONSchema` type
- `ToolGenerator` class

**How We Use It:**
```typescript
// Generate tools
const generator = new ToolGenerator();
const tools = generator.generateTools(dictionary, appInfo);

// Access metadata for execution
const { bundleId, commandCode, directParameterName } = tool._metadata;
```

### What Week 3 Adds

**New Capabilities:**
- Execute generated tools on macOS
- Marshal JSON parameters to JXA
- Parse JXA results back to JSON
- Classify and check permissions
- Handle errors gracefully
- MCP server that ties it all together

**Data Flow:**
```
Week 1: SDEF File → Parsed Dictionary
Week 2: Parsed Dictionary → MCP Tools
Week 3: MCP Tools + Args → Executed Results
```

---

## Error Scenarios to Test

### 1. App Not Found
**Scenario:** Try to control app that's not installed
**Expected:** Clear error message with suggestion to install

### 2. App Not Running
**Scenario:** Some commands require app to be running
**Expected:** Error message asking user to launch app

### 3. Permission Denied
**Scenario:** macOS blocks automation
**Expected:** Clear instructions to grant permission in System Settings

### 4. Invalid Parameter
**Scenario:** Pass wrong type or invalid value
**Expected:** Validation error with what's wrong

### 5. Timeout
**Scenario:** Command takes too long
**Expected:** Timeout error with suggestion to retry

### 6. File Not Found
**Scenario:** Try to operate on non-existent file
**Expected:** Clear error about file not existing

### 7. Dangerous Command
**Scenario:** Try to delete or quit
**Expected:** Permission system blocks or prompts

---

## Success Criteria

### Technical Criteria

**Must Have:**
- [ ] JXA execution works reliably
- [ ] Can execute Finder commands (list, get, count)
- [ ] Can execute Safari commands (get URL, title)
- [ ] Can execute Mail commands (count messages)
- [ ] Parameter marshaling handles all basic types
- [ ] Result parsing handles all basic types
- [ ] Error messages are clear and actionable
- [ ] Permission classification works
- [ ] MCP server responds to ListTools
- [ ] MCP server responds to CallTool
- [ ] No crashes on error conditions
- [ ] 80%+ test coverage

**Should Have:**
- [ ] Timeout handling works correctly
- [ ] Audit log tracks executions
- [ ] Can handle large results
- [ ] Can handle special characters

**Nice to Have:**
- [ ] Performance logging
- [ ] Debug mode with verbose output
- [ ] Dry-run mode (don't actually execute)

### User Experience Criteria

**Must Have:**
- [ ] Works with Claude Desktop
- [ ] Claude can discover available tools
- [ ] Claude can execute tools successfully
- [ ] Errors don't crash Claude Desktop
- [ ] Error messages help user fix issues

**Should Have:**
- [ ] Fast response (< 5 seconds for simple commands)
- [ ] Progress indication for long operations
- [ ] Consistent behavior across apps

### Testing Criteria

**Must Have:**
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] No skipped tests without good reason
- [ ] Tests run in < 30 seconds (unit)
- [ ] Tests run in < 2 minutes (integration)

---

## Risk Mitigation

### Technical Risks

**Risk: JXA is unreliable**
- **Mitigation:** Extensive timeout and error handling
- **Fallback:** Can switch to AppleScript if needed (harder to parse)

**Risk: osascript has version differences**
- **Mitigation:** Test on multiple macOS versions if possible
- **Fallback:** Document minimum macOS version

**Risk: Apps behave differently**
- **Mitigation:** Test with 3-5 different apps
- **Fallback:** App-specific overrides for edge cases

**Risk: Parameter marshaling edge cases**
- **Mitigation:** Comprehensive unit tests
- **Fallback:** Whitelist known-good patterns, block unknown

### Integration Risks

**Risk: Week 1/2 code needs changes**
- **Mitigation:** Review interfaces early
- **Fallback:** Use adapter pattern for compatibility

**Risk: MCP SDK breaking changes**
- **Mitigation:** Pin SDK version in package.json
- **Fallback:** Can implement MCP protocol manually if needed

### Timeline Risks

**Risk: Tasks take longer than estimated**
- **Mitigation:** Prioritize critical features (execution works)
- **Fallback:** Can punt permission UI, polish to Week 4

**Risk: Integration issues at end**
- **Mitigation:** Integration test early (Day 3)
- **Fallback:** Can ship with reduced app support

---

## Deliverables

### Code Deliverables

**Source Files:**
- `src/adapters/macos/jxa-executor.ts`
- `src/adapters/macos/parameter-marshaler.ts`
- `src/adapters/macos/result-parser.ts`
- `src/adapters/macos/error-handler.ts`
- `src/adapters/macos/index.ts` (MacOSAdapter)
- `src/permissions/classifier.ts`
- `src/permissions/index.ts` (PermissionChecker)
- `src/mcp/server.ts` (IACMCPServer)
- `src/mcp/handlers.ts`
- `src/types/execution.ts`

**Test Files:**
- `tests/unit/jxa-executor.test.ts`
- `tests/unit/parameter-marshaler.test.ts`
- `tests/unit/result-parser.test.ts`
- `tests/unit/error-handler.test.ts`
- `tests/unit/permission-classifier.test.ts`
- `tests/unit/mcp-handlers.test.ts`
- `tests/integration/finder-execution.test.ts`
- `tests/integration/safari-execution.test.ts`
- `tests/integration/mail-execution.test.ts`
- `tests/integration/end-to-end.test.ts`

### Documentation Deliverables

**Updated Files:**
- `README.md` - Add execution layer overview
- `CLAUDE.md` - Document execution patterns
- `planning/ROADMAP.md` - Mark Week 3 complete

**New Files:**
- `docs/EXECUTION.md` - Execution layer architecture
- `docs/PERMISSIONS.md` - Permission system guide
- `docs/ERRORS.md` - Error handling guide

### Validation Deliverables

**Testing:**
- All unit tests pass
- All integration tests pass
- Coverage report showing 80%+

**Manual Validation:**
- Works with Claude Desktop
- Can execute 10+ different commands
- Handles errors gracefully
- Permission system works

**Artifacts:**
- Test coverage report
- Manual testing checklist (completed)
- Screenshots of Claude Desktop working

---

## Example: Finder "list folder" Complete Flow

**1. Claude Desktop sends MCP request:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "finder_list_folder",
    "arguments": {
      "target": "/Users/jake/Desktop"
    }
  }
}
```

**2. MCP Handler receives request:**
```typescript
const tool = findToolByName("finder_list_folder");
const args = { target: "/Users/jake/Desktop" };
```

**3. Permission check:**
```typescript
const permission = await permissionChecker.check(tool, args);
// Result: { allowed: true, level: 'SAFE', reason: 'Read-only operation' }
```

**4. Parameter marshaling:**
```typescript
const marshaled = marshaler.marshal(args, tool.inputSchema, tool._metadata);
// Result: `{ target: Path("/Users/jake/Desktop") }`
```

**5. Build JXA script:**
```javascript
(() => {
  const app = Application("Finder");
  app.includeStandardAdditions = true;

  const folder = app.folders.byName("Desktop");
  const items = folder.items();

  return items.name(); // Array of file names
})()
```

**6. Execute JXA:**
```typescript
const result = await executor.execute(script, { timeoutMs: 30000 });
// Result: { stdout: '["file1.txt","file2.pdf","folder"]', stderr: '', exitCode: 0 }
```

**7. Parse result:**
```typescript
const parsed = parser.parse(result, tool._metadata);
// Result: { success: true, data: ["file1.txt", "file2.pdf", "folder"] }
```

**8. Return to Claude:**
```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"success\":true,\"data\":[\"file1.txt\",\"file2.pdf\",\"folder\"]}"
    }
  ]
}
```

**9. Claude interprets response:**
```
I found 3 items on your desktop:
- file1.txt
- file2.pdf
- folder
```

---

## Testing Checklist

### Unit Test Coverage

- [ ] JXAExecutor
  - [ ] Basic execution
  - [ ] Timeout handling
  - [ ] Error capture
  - [ ] Process management

- [ ] ParameterMarshaler
  - [ ] All basic types (string, number, boolean, null)
  - [ ] Complex types (array, object)
  - [ ] File paths (auto-detection, wrapping)
  - [ ] Enums (validation, mapping)
  - [ ] Edge cases (escaping, empty values)

- [ ] ResultParser
  - [ ] Parse all result types
  - [ ] Parse all error types
  - [ ] Handle malformed output
  - [ ] Handle empty results

- [ ] ErrorHandler
  - [ ] All error types have messages
  - [ ] All messages are user-friendly
  - [ ] Suggestions are helpful
  - [ ] Retryable classification correct

- [ ] PermissionClassifier
  - [ ] SAFE classification correct
  - [ ] MODIFY classification correct
  - [ ] DANGEROUS classification correct
  - [ ] Custom rules work

- [ ] MCP Handlers
  - [ ] ListTools returns correct format
  - [ ] CallTool executes and returns result
  - [ ] Errors are formatted correctly

### Integration Test Coverage

- [ ] Finder Integration
  - [ ] List folder works
  - [ ] Get file info works
  - [ ] Count items works
  - [ ] Error handling works

- [ ] Safari Integration (if available)
  - [ ] Get URL works
  - [ ] Get title works
  - [ ] Count tabs works
  - [ ] Not running error works

- [ ] Mail Integration (if available)
  - [ ] Count messages works
  - [ ] Get mailboxes works
  - [ ] Not configured error works

- [ ] End-to-End
  - [ ] Full ListTools flow works
  - [ ] Full CallTool flow works
  - [ ] Permission check integrated
  - [ ] Error handling integrated

### Manual Testing Checklist

- [ ] Claude Desktop Integration
  - [ ] Can discover tools
  - [ ] Can execute Finder commands
  - [ ] Can execute Safari commands (if Safari running)
  - [ ] Errors are clear
  - [ ] No crashes
  - [ ] Performance acceptable (< 5s response)

- [ ] Error Scenarios
  - [ ] App not found → clear message
  - [ ] Permission denied → clear instructions
  - [ ] Invalid parameter → validation error
  - [ ] Timeout → timeout error with retry suggestion
  - [ ] Dangerous command → permission check

- [ ] Edge Cases
  - [ ] Empty results handled
  - [ ] Large results handled
  - [ ] Special characters handled
  - [ ] Very long paths handled

---

## Next Steps After Week 3

**Immediate (Week 4):**
- Expand to 10-15 apps (Messages, Photos, Music, etc.)
- Add caching for parsed capabilities
- Improve permission system (persistent storage)
- Add audit log viewer
- Performance optimization

**Short-term (Weeks 5-8):**
- Comprehensive documentation
- Example workflows
- npm package setup
- Testing with more MCP clients

**Medium-term (Weeks 9-12):**
- Public release
- Community feedback
- Bug fixes
- Plan Phase 2 (UI wrapper)

---

## Questions & Clarifications

**Q: Do we need to handle prompting the user for permissions in Week 3?**
**A:** No. For MVP, permission system just classifies and checks. It returns `requiresPrompt: true` and the caller (Claude) can inform the user. Full prompting UI comes in Phase 2 (native app).

**Q: What if JXA execution is too slow?**
**A:** Optimize in Week 4 if needed. Start with simple approach (spawn process each time). Can add JXA REPL later if performance is an issue.

**Q: Should we support AppleScript in addition to JXA?**
**A:** No. JXA is cleaner and easier to work with from Node.js. If JXA proves problematic, we can add AppleScript later, but JXA should work fine.

**Q: How do we test on different macOS versions?**
**A:** Test on your current macOS version. Document minimum version (macOS 10.10+ has JXA). If community reports issues on specific versions, we can address them.

**Q: What if some apps need special handling?**
**A:** Create app-specific overrides in Week 4+. For Week 3, focus on getting the general case working with Finder, Safari, and Mail. Document any quirks you find.

**Q: Do we need to handle concurrent executions?**
**A:** Not in Week 3. Single request at a time is fine. Can add queuing/concurrency in Week 4 if needed.

---

## Summary

**Week 3 transforms our project from "generates tools" to "executes tools".**

**What we're building:**
- JXA execution engine
- Parameter marshaling (JSON → JXA)
- Result parsing (JXA → JSON)
- Error handling (user-friendly messages)
- Permission system (classify operations)
- MCP server (tie it all together)

**How we're building it:**
- TDD: Write tests first
- Incremental: One module at a time
- Integration-focused: Test with real apps early
- User-centric: Clear error messages

**Success looks like:**
- Claude Desktop can execute Finder commands
- Errors are clear and actionable
- No crashes
- 80%+ test coverage
- Ready to expand to more apps in Week 4

**Let's build the execution layer!**
