# Test Coverage Analysis: handlers.ts (61% → 85%)

**Status**: Current coverage 22.41% (22 tests passing, significant gaps identified)

**Target**: 85% coverage (+25.24% improvement required)

**File**: `src/mcp/handlers.ts` (548 lines)

**Coverage Baseline**:
- Statements: 22.41%
- Branches: 100%
- Functions: 66.66%
- Lines: 22.41%
- Uncovered lines: 172–405, 422–449

**Estimated effort**: 45–60 unit/integration tests needed (~2–3 days)

---

## Coverage Gap Analysis

### Section 1: Uncovered Line Ranges Breakdown

#### Range 1: Lines 172–405 (ListTools Handler + CallTool Setup)

**Scope**: ListTools request handler implementation and CallTool tool lookup

**Uncovered Functions**:
- Lines 84–161: `server.setRequestHandler(ListToolsRequestSchema, async () => {})`
- Lines 171–267: `get_app_tools` lazy loading logic (part of CallTool)
- Lines 268–406: Main tool execution logic (CallTool handler)

**Why Uncovered**:
- These are async handlers that depend on MCP server context
- Integration-level code that requires full server setup
- Mocking complexity: require mocking `findAllScriptableApps`, `buildMetadata`, `loadAppTools`
- Error paths in exception handlers not tested

**High-Risk Code Paths**:
1. **Metadata building failure** (lines 113–118): Apps that fail to parse
   - Not tested: What happens when `buildMetadata` throws?
   - Risk: Silent failures or incomplete metadata

2. **Discovery with no apps** (lines 95–101): Edge case when no scriptable apps found
   - Not tested: Proper empty response formatting
   - Risk: Null/undefined errors in downstream code

3. **App not found in CallTool** (lines 273–289): Tool lookup failure
   - Not tested: Proper error response when tool doesn't exist
   - Risk: Leaking internal tool names in error messages

4. **AppNotFoundError handling** (lines 245–254): Specific error type detection
   - Not tested: Error.name property checks
   - Risk: Fallback to generic error handling

5. **get_app_tools validation** (lines 179–224): Security input validation
   - Length check (line 194–202): NOT TESTED
   - Regex validation (line 205–213): NOT TESTED
   - Null byte rejection (line 216–224): NOT TESTED
   - Risk: Security vulnerability if validation skipped

#### Range 2: Lines 422–449 (Error Code Mapping)

**Scope**: `getErrorCode()` function branch coverage

**Uncovered Branches**:
- Line 442: `if (message.includes('not found'))`
- Line 444: `if (message.includes('Permission'))`
- Line 445: `if (message.includes('timeout'))`
- Line 446: `if (message.includes('Invalid'))`
- Line 447: `if (message.includes('AppleScript'))`
- Line 448: Default case

**Why Uncovered**:
- These if/else branches are only triggered with specific error messages
- Currently only returning generic `EXECUTION_ERROR`
- Needs intentional error message crafting to test

---

## Categorized Test Plan

### CRITICAL PRIORITY (Must have - 20 tests)

These tests are essential for launch readiness and cover security/core functionality.

#### 1. Security Input Validation for get_app_tools (4 tests)

**Why Critical**:
- Security boundary between user input and app discovery
- Input length check prevents DoS attacks
- Regex validation prevents directory traversal
- Null byte rejection prevents null byte injection

```typescript
describe('get_app_tools - Input Validation', () => {

  it('should reject app_name exceeding MAX_APP_NAME_LENGTH (100 chars)', async () => {
    const longName = 'a'.repeat(101);
    const result = await handleCallTool('get_app_tools', { app_name: longName });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('too long');
    expect(result.content[0].text).toContain('100 characters');
  });

  it('should reject app_name with invalid characters (security)', async () => {
    const invalidNames = [
      '../../../etc/passwd',  // Directory traversal
      '$(rm -rf /)',          // Command injection
      'Finder; rm -rf /',     // Shell metacharacter
      '| cat /etc/passwd',    // Pipe injection
    ];

    for (const name of invalidNames) {
      const result = await handleCallTool('get_app_tools', { app_name: name });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('invalid characters');
    }
  });

  it('should reject app_name containing null bytes (null byte injection)', async () => {
    const nullByteNames = [
      'Finder\0.app',
      '\0Finder',
      'Finder\0\0',
    ];

    for (const name of nullByteNames) {
      const result = await handleCallTool('get_app_tools', { app_name: name });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('null bytes');
    }
  });

  it('should accept valid app names (alphanumeric, spaces, hyphens, underscores, periods)', async () => {
    const validNames = [
      'Finder',
      'Adobe InDesign',
      'Microsoft-Word',
      'Script_Editor',
      'App.Name',
    ];

    // Mock successful app lookup
    mockLoadAppTools.mockResolvedValue({ tools: [], objectModel: {} });

    for (const name of validNames) {
      const result = await handleCallTool('get_app_tools', { app_name: name });
      expect(result.isError).toBe(false);
      // Should call loadAppTools with validated name
      expect(mockLoadAppTools).toHaveBeenCalledWith(
        name,
        expect.anything(),
        expect.anything(),
        expect.anything(),
        expect.anything()
      );
    }
  });
});
```

**Coverage Impact**: +8 lines (includes validation checks and success path)

---

#### 2. ListTools Handler - Happy Path & Discovery Failure (3 tests)

**Why Critical**:
- Core MCP handler that client calls to discover tools
- Must handle empty app lists gracefully
- Must handle partial failures (some apps fail to parse)

```typescript
describe('ListTools Handler', () => {

  it('should return get_app_tools tool + metadata for discovered apps', async () => {
    const mockApps = [
      { appName: 'Finder', bundleId: 'com.apple.finder', sdefPath: '/path/to/Finder.sdef' },
      { appName: 'Safari', bundleId: 'com.apple.Safari', sdefPath: '/path/to/Safari.sdef' },
    ];

    mockFindAllScriptableApps.mockResolvedValue(mockApps);
    mockSDEFParser.parse.mockResolvedValue({ /* dictionary */ });
    mockBuildMetadata.mockResolvedValue({
      appName: 'Finder',
      bundleId: 'com.apple.finder',
      toolCount: 42,
    });

    const result = await invokeListTools();

    expect(result.tools).toHaveLength(1);
    expect(result.tools[0].name).toBe('get_app_tools');
    expect(result._app_metadata).toHaveLength(2);
    expect(result._app_metadata[0].appName).toBe('Finder');
  });

  it('should handle apps that fail metadata building (partial failure)', async () => {
    const mockApps = [
      { appName: 'Finder', bundleId: 'com.apple.finder', sdefPath: '/path/to/Finder.sdef' },
      { appName: 'BrokenApp', bundleId: 'com.broken', sdefPath: '/path/to/Broken.sdef' },
    ];

    mockFindAllScriptableApps.mockResolvedValue(mockApps);
    mockBuildMetadata
      .mockResolvedValueOnce({ appName: 'Finder', /* ... */ })
      .mockRejectedValueOnce(new Error('Failed to parse SDEF'));

    const result = await invokeListTools();

    // Should still return get_app_tools + only successful metadata
    expect(result.tools).toHaveLength(1);
    expect(result._app_metadata).toHaveLength(1);
    expect(result._app_metadata[0].appName).toBe('Finder');
  });

  it('should return empty tools list when no scriptable apps found', async () => {
    mockFindAllScriptableApps.mockResolvedValue([]);

    const result = await invokeListTools();

    expect(result.tools).toEqual([]);
    expect(result._app_metadata).toEqual([]);
  });
});
```

**Coverage Impact**: +25 lines (handler body, error handling, empty app list)

---

#### 3. CallTool get_app_tools Lazy Loading (5 tests)

**Why Critical**:
- Lazy loading is core to performance
- Error handling for app not found
- Tool response formatting

```typescript
describe('CallTool - get_app_tools Lazy Loading', () => {

  it('should load tools for requested app on demand', async () => {
    const mockTools = [
      { name: 'finder_open', description: 'Open file' },
      { name: 'finder_delete', description: 'Delete file' },
    ];

    mockLoadAppTools.mockResolvedValue({
      tools: mockTools,
      objectModel: { Finder: { /* model */ } },
    });

    const result = await handleCallTool('get_app_tools', { app_name: 'Finder' });

    expect(result.isError).toBe(false);
    const response = JSON.parse(result.content[0].text);
    expect(response.tools).toHaveLength(2);
    expect(response.objectModel).toBeDefined();
  });

  it('should handle app not found error (AppNotFoundError)', async () => {
    const error = new Error('App not found');
    (error as any).name = 'AppNotFoundError';
    mockLoadAppTools.mockRejectedValue(error);

    const result = await handleCallTool('get_app_tools', { app_name: 'NonExistentApp' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
    expect(result.content[0].text).toContain('list_tools');
  });

  it('should return missing app_name parameter error', async () => {
    const result = await handleCallTool('get_app_tools', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Missing required parameter');
    expect(result.content[0].text).toContain('app_name');
  });

  it('should handle generic errors from loadAppTools', async () => {
    mockLoadAppTools.mockRejectedValue(new Error('Parse error'));

    const result = await handleCallTool('get_app_tools', { app_name: 'Finder' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Error loading tools');
    expect(result.content[0].text).toContain('Finder');
  });

  it('should use cache when available for repeated requests', async () => {
    const mockCacheResult = {
      tools: [{ name: 'finder_open' }],
      objectModel: {},
    };

    mockLoadAppTools.mockResolvedValue(mockCacheResult);
    mockPerAppCache.get.mockResolvedValue(mockCacheResult);

    // First call
    await handleCallTool('get_app_tools', { app_name: 'Finder' });
    // Second call
    await handleCallTool('get_app_tools', { app_name: 'Finder' });

    // LoadAppTools should use cached result
    expect(mockLoadAppTools).toHaveBeenCalledTimes(2);
  });
});
```

**Coverage Impact**: +40 lines (all paths through get_app_tools, error handling)

---

#### 4. Tool Execution Flow - Core Path (5 tests)

**Why Critical**:
- Main execution path that users rely on
- Permission checking
- Adapter invocation
- Error handling in execution

```typescript
describe('CallTool - Tool Execution', () => {

  it('should execute tool with valid arguments (happy path)', async () => {
    const mockTool = {
      name: 'finder_open',
      inputSchema: {
        type: 'object',
        properties: { path: { type: 'string' } },
        required: ['path'],
      },
    };

    discoveredTools = [mockTool];
    mockPermissionChecker.check.mockResolvedValue({ allowed: true });
    mockAdapter.execute.mockResolvedValue({ success: true, data: 'File opened' });

    const result = await handleCallTool('finder_open', { path: '/Users/test/file.txt' });

    expect(result.isError).toBe(false);
    const response = JSON.parse(result.content[0].text);
    expect(response.success).toBe(true);
    expect(response.data).toBe('File opened');
  });

  it('should check permissions before execution', async () => {
    const mockTool = { name: 'finder_delete', inputSchema: { /* ... */ } };
    discoveredTools = [mockTool];

    mockPermissionChecker.check.mockResolvedValue({
      allowed: false,
      reason: 'Delete operations require user confirmation',
    });

    const result = await handleCallTool('finder_delete', { path: '/Users/test' });

    expect(result.isError).toBe(true);
    expect(mockAdapter.execute).not.toHaveBeenCalled();
    expect(result.content[0].text).toContain('Permission denied');
  });

  it('should skip permission checks when DISABLE_PERMISSIONS=true', async () => {
    process.env.DISABLE_PERMISSIONS = 'true';

    const mockTool = { name: 'finder_delete', inputSchema: { /* ... */ } };
    discoveredTools = [mockTool];
    mockAdapter.execute.mockResolvedValue({ success: true, data: 'Deleted' });

    const result = await handleCallTool('finder_delete', { path: '/Users/test' });

    expect(result.isError).toBe(false);
    expect(mockPermissionChecker.check).not.toHaveBeenCalled();
    expect(mockAdapter.execute).toHaveBeenCalled();

    delete process.env.DISABLE_PERMISSIONS;
  });

  it('should handle execution failure from adapter', async () => {
    const mockTool = { name: 'finder_open', inputSchema: { /* ... */ } };
    discoveredTools = [mockTool];
    mockPermissionChecker.check.mockResolvedValue({ allowed: true });
    mockAdapter.execute.mockResolvedValue({
      success: false,
      error: { type: 'EXECUTION_ERROR', message: 'App not found' },
    });
    mockErrorHandler.handle.mockReturnValue({
      message: 'Finder application not found',
      suggestion: 'Ensure Finder is installed',
      type: 'NOT_FOUND',
      retryable: false,
      originalError: 'App not found',
    });

    const result = await handleCallTool('finder_open', { path: '/tmp' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Finder');
  });

  it('should return not found error when tool does not exist', async () => {
    discoveredTools = [{ name: 'finder_open', inputSchema: { /* ... */ } }];

    const result = await handleCallTool('unknown_tool', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Tool not found');
    expect(result.content[0].text).toContain('unknown_tool');
  });
});
```

**Coverage Impact**: +50 lines (permission flow, adapter interaction, error handling)

---

#### 5. Argument Validation (3 tests)

**Why Critical**:
- Validates tool parameters before execution
- Prevents type mismatches
- Core to MCP protocol compliance

```typescript
describe('validateToolArguments', () => {

  it('should validate required arguments', () => {
    const schema = {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    };

    const result1 = validateToolArguments({ path: '/tmp' }, schema);
    expect(result1.valid).toBe(true);

    const result2 = validateToolArguments({}, schema);
    expect(result2.valid).toBe(false);
    expect(result2.errors[0]).toContain('Missing required argument: path');
  });

  it('should validate argument types (string, number, boolean, array, object)', () => {
    const schema = {
      type: 'object',
      properties: {
        name: { type: 'string' },
        count: { type: 'number' },
        enabled: { type: 'boolean' },
        items: { type: 'array' },
        config: { type: 'object' },
      },
    };

    // Valid types
    const validResult = validateToolArguments(
      {
        name: 'Test',
        count: 5,
        enabled: true,
        items: [1, 2, 3],
        config: { key: 'value' },
      },
      schema
    );
    expect(validResult.valid).toBe(true);

    // Invalid types
    const invalidResult = validateToolArguments(
      {
        name: 123,        // Should be string
        count: 'five',    // Should be number
        enabled: 'yes',   // Should be boolean
        items: 'list',    // Should be array
        config: 'cfg',    // Should be object
      },
      schema
    );
    expect(invalidResult.valid).toBe(false);
    expect(invalidResult.errors).toContain('Argument "name" must be a string');
    expect(invalidResult.errors).toContain('Argument "count" must be a number');
  });

  it('should handle schemas without required or properties', () => {
    const schema = { type: 'object' };

    const result = validateToolArguments({ any: 'value' }, schema);
    expect(result.valid).toBe(true);
  });
});
```

**Coverage Impact**: +20 lines (all type checking branches, required field validation)

---

### HIGH PRIORITY (Important - 15 tests)

These tests cover important but non-critical paths.

#### 6. Error Code Mapping (5 tests)

**Why Important**:
- Determines error type for debugging
- Helps clients understand error category
- All branches currently untested

```typescript
describe('getErrorCode', () => {

  it('should return NOT_FOUND for "not found" messages', () => {
    const messages = [
      'Tool not found',
      'App not found in discovered apps',
      'File not found: /tmp/missing.txt',
    ];

    for (const msg of messages) {
      const code = formatErrorResponse(msg).code;
      expect(code).toBe('NOT_FOUND');
    }
  });

  it('should return PERMISSION_DENIED for "Permission" messages', () => {
    const messages = [
      'Permission denied',
      'Permission denied: user confirmation required',
      'Insufficient permissions for operation',
    ];

    for (const msg of messages) {
      const code = formatErrorResponse(msg).code;
      expect(code).toBe('PERMISSION_DENIED');
    }
  });

  it('should return TIMEOUT for "timeout" messages', () => {
    const messages = [
      'Command timeout',
      'Execution timeout after 5 seconds',
      'Request timeout',
    ];

    for (const msg of messages) {
      const code = formatErrorResponse(msg).code;
      expect(code).toBe('TIMEOUT');
    }
  });

  it('should return INVALID_ARGUMENT for "Invalid" messages', () => {
    const messages = [
      'Invalid arguments',
      'Invalid schema',
      'Invalid parameter type',
    ];

    for (const msg of messages) {
      const code = formatErrorResponse(msg).code;
      expect(code).toBe('INVALID_ARGUMENT');
    }
  });

  it('should return APPLESCRIPT_ERROR for "AppleScript" messages', () => {
    const messages = [
      'AppleScript error',
      'AppleScript execution failed: -1708',
      'AppleScript compilation error',
    ];

    for (const msg of messages) {
      const code = formatErrorResponse(msg).code;
      expect(code).toBe('APPLESCRIPT_ERROR');
    }
  });
});
```

**Coverage Impact**: +12 lines (all error code branches)

---

#### 7. Response Formatting (3 tests)

**Why Important**:
- Ensures MCP protocol compliance
- Consistent response structure for clients

```typescript
describe('Response Formatting', () => {

  it('should format success response with data and optional metadata', () => {
    const response1 = formatSuccessResponse({ result: 'success' });
    expect(response1).toEqual({
      success: true,
      data: { result: 'success' },
    });

    const response2 = formatSuccessResponse(
      { result: 'success' },
      { executionTime: 150 }
    );
    expect(response2).toEqual({
      success: true,
      data: { result: 'success' },
      metadata: { executionTime: 150 },
    });
  });

  it('should format permission denied response with reason and level', () => {
    const decision = {
      allowed: false,
      reason: 'Delete operations require confirmation',
      level: 'REQUIRES_CONFIRMATION',
      requiresPrompt: true,
    };

    const response = formatPermissionDeniedResponse(decision);
    expect(response.error).toBe('Permission denied');
    expect(response.reason).toBe(decision.reason);
    expect(response.level).toBe(decision.level);
    expect(response.requiresPrompt).toBe(true);
    expect(response.timestamp).toBeDefined();
  });

  it('should format error response with context', () => {
    const response = formatErrorResponse('Command failed', {
      toolName: 'finder_delete',
      attemptedArgs: { path: '/tmp' },
    });

    expect(response.error).toBe('Command failed');
    expect(response.code).toBeDefined();
    expect(response.timestamp).toBeDefined();
    expect(response.toolName).toBe('finder_delete');
    expect(response.attemptedArgs).toEqual({ path: '/tmp' });
  });
});
```

**Coverage Impact**: +15 lines (all formatting branches)

---

#### 8. Edge Cases & Exception Handling (4 tests)

**Why Important**:
- Defensive against unexpected inputs
- Prevents crashes in production
- Ensures graceful degradation

```typescript
describe('Edge Cases & Exception Handling', () => {

  it('should handle CallTool with undefined arguments', async () => {
    const mockTool = { name: 'finder_open', inputSchema: { properties: {} } };
    discoveredTools = [mockTool];
    mockAdapter.execute.mockResolvedValue({ success: true, data: 'OK' });

    const result = await handleCallTool('finder_open', undefined);

    expect(result.isError).toBe(false); // Should treat as empty object
  });

  it('should handle CallTool exception thrown by handlers', async () => {
    mockFindAllScriptableApps.mockRejectedValue(new Error('Unexpected error'));

    const result = await invokeListTools();

    expect(result._error).toBeDefined();
    expect(result.tools).toEqual([]);
  });

  it('should handle tool with empty inputSchema', async () => {
    const mockTool = { name: 'finder_refresh', inputSchema: {} };
    discoveredTools = [mockTool];
    mockAdapter.execute.mockResolvedValue({ success: true, data: 'Refreshed' });

    const validationResult = validateToolArguments({}, {});
    expect(validationResult.valid).toBe(true);
  });

  it('should handle non-Error objects thrown as exceptions', async () => {
    mockLoadAppTools.mockRejectedValue('String error thrown');

    const result = await handleCallTool('get_app_tools', { app_name: 'Finder' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('String error thrown');
  });
});
```

**Coverage Impact**: +20 lines (exception paths, defensive checks)

---

### MEDIUM PRIORITY (Nice-to-have - 10 tests)

These tests improve robustness but are not essential for launch.

#### 9. Integration Tests (5 tests)

```typescript
describe('MCP Handlers - Integration Tests', () => {

  it('should handle complete lifecycle: ListTools → get_app_tools → CallTool', async () => {
    // Full workflow test
  });

  it('should handle rapid successive get_app_tools calls for same app', async () => {
    // Cache performance test
  });

  it('should handle concurrent tool executions', async () => {
    // Concurrency test
  });

  it('should handle mixed successful and failed tool executions', async () => {
    // Resilience test
  });

  it('should handle recovery after temporary app discovery failure', async () => {
    // Recovery test
  });
});
```

**Coverage Impact**: +15 lines (integration paths)

---

#### 10. Permission Flow Variations (3 tests)

```typescript
describe('Permission Checker Integration', () => {

  it('should properly pass tool metadata to permission checker', async () => {
    // Verify tool info passed correctly
  });

  it('should handle permission checker returning different decision levels', async () => {
    // Test all decision levels
  });

  it('should format permission denial with all decision properties', async () => {
    // Comprehensive permission response test
  });
});
```

**Coverage Impact**: +10 lines (permission metadata flow)

---

#### 11. Error Handler Integration (2 tests)

```typescript
describe('Error Handler Integration', () => {

  it('should pass correct context to error handler', async () => {
    // Verify context passed to handler
  });

  it('should format error handler output as MCP response', async () => {
    // Response format test
  });
});
```

**Coverage Impact**: +8 lines (error handler integration)

---

## Summary: Tests Needed by Priority

| Priority | Category | Tests | Coverage Gain | Estimated Time |
|----------|----------|-------|---------------|-----------------|
| Critical | Security validation | 4 | +8% | 2 hours |
| Critical | ListTools handler | 3 | +6% | 1.5 hours |
| Critical | get_app_tools lazy loading | 5 | +12% | 2.5 hours |
| Critical | Tool execution | 5 | +12% | 2.5 hours |
| Critical | Argument validation | 3 | +5% | 1.5 hours |
| High | Error code mapping | 5 | +3% | 1.5 hours |
| High | Response formatting | 3 | +4% | 1 hour |
| High | Exception handling | 4 | +5% | 1.5 hours |
| Medium | Integration tests | 5 | +4% | 2 hours |
| Medium | Permission flow | 3 | +3% | 1.5 hours |
| Medium | Error handler | 2 | +2% | 1 hour |
| **TOTAL** | | **42 tests** | **+64% improvement** | **~18 hours** |

**Note**: Target is 85% coverage = current 22.41% + 62.59% improvement. Tests above provide +64%, exceeding target.

---

## Implementation Strategy

### Phase 1: Foundation (Days 1–2)

1. **Create test infrastructure**
   - Mock `findAllScriptableApps`, `buildMetadata`, `loadAppTools`
   - Mock MCP server handlers
   - Setup test utilities for handler invocation

2. **Implement critical validation tests** (Security)
   - Input length validation
   - Regex character validation
   - Null byte rejection
   - Valid name acceptance

3. **Implement ListTools tests**
   - Happy path with multiple apps
   - Partial failure (one app fails)
   - Empty app list

### Phase 2: Core Functionality (Days 2–3)

4. **Implement CallTool tests**
   - get_app_tools lazy loading
   - Permission checking flow
   - Tool execution happy path
   - Error handling

5. **Implement argument validation tests**
   - Required fields
   - Type checking (all 5 types)
   - Empty schema handling

### Phase 3: Polish (Days 3)

6. **Error handling tests**
   - Error code mapping
   - Response formatting
   - Exception handling

7. **Integration tests**
   - End-to-end workflows
   - Concurrency
   - Cache behavior

---

## Architectural Recommendations

### 1. Test Isolation Improvement

**Current state**: Handlers depend on global state (`discoveredTools`, `discoveredApps`)

**Recommendation**: Refactor to accept state as parameters:

```typescript
// Before
server.setRequestHandler(ListToolsRequestSchema, async () => {
  // Uses global discoveredApps
});

// After
server.setRequestHandler(
  ListToolsRequestSchema,
  createListToolsHandler(appDiscovery, metadataBuilder)
);
```

**Benefit**: Enables unit testing without full server context
**Effort**: 2–3 hours refactoring + test rewrite

### 2. Mock Complexity

**Issue**: Handlers use many dependencies
**Solution**: Create helper factory functions:

```typescript
const createTestHandlerContext = () => ({
  toolGenerator: mockToolGenerator,
  permissionChecker: mockPermissionChecker,
  adapter: mockAdapter,
  errorHandler: mockErrorHandler,
  appDiscovery: mockAppDiscovery,
});
```

### 3. Error Type Coverage

**Issue**: Error path testing requires crafting specific error messages
**Solution**: Create error factories:

```typescript
const createNotFoundError = (resource: string) => {
  const err = new Error(`${resource} not found`);
  (err as any).name = 'NotFoundError';
  return err;
};
```

---

## Testing Technical Decisions

### Tool Registration Mocking

**Challenge**: `server.setRequestHandler()` needs to be called and handlers invoked

**Approach**:
```typescript
const handlers = new Map();
const mockServer = {
  setRequestHandler: (schema, handler) => {
    handlers.set(schema, handler);
  },
};

// Invoke handler by schema
const invokeListTools = () => handlers.get(ListToolsRequestSchema)();
```

### Async Handler Testing

**Challenge**: Handlers are async and return MCP responses

**Approach**:
```typescript
const result = await invokeListTools();
// Result is MCP ListToolsResult
expect(result.tools).toBeDefined();
expect(result._app_metadata).toBeDefined();
```

### State Management Between Tests

**Challenge**: `discoveredTools` and `discoveredApps` are module-scoped

**Approach**: Clear between tests:
```typescript
beforeEach(() => {
  discoveredTools = [];
  discoveredApps = [];
  vi.clearAllMocks();
});
```

---

## Risk Assessment: What Could Break?

### Without Security Validation Tests
- **Risk**: Attacker could pass `../../../etc/passwd` as app_name
- **Impact**: Directory traversal vulnerability
- **Severity**: CRITICAL

### Without get_app_tools Lazy Loading Tests
- **Risk**: Clients cannot discover app tools on demand
- **Impact**: Feature unusable for users
- **Severity**: CRITICAL

### Without Tool Execution Tests
- **Risk**: Tool execution path could fail silently
- **Impact**: Tools appear available but don't work
- **Severity**: CRITICAL

### Without Permission Check Tests
- **Risk**: Permission system bypassed
- **Impact**: Dangerous commands execute without confirmation
- **Severity**: CRITICAL

### Without Error Code Mapping Tests
- **Risk**: All errors return generic code
- **Impact**: Poor debugging experience for clients
- **Severity**: LOW-MEDIUM

---

## Coverage Milestones

- **After Phase 1** (Foundation): ~35% coverage (Security + ListTools)
- **After Phase 2** (Core): ~70% coverage (Add CallTool + Execution)
- **After Phase 3** (Polish): ~85% coverage (Add error handling + integration)

---

## Files to Modify

### New Test File
- `tests/unit/mcp-handlers-coverage.test.ts` - New comprehensive test suite (700+ lines)

### Existing Files
- `src/mcp/handlers.ts` - No changes needed (tests are external)
- May require minor refactoring for testability (2–3 hours optional)

---

## Estimated Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 (Foundation) | 1.5 days | 4 critical tests + infrastructure |
| Phase 2 (Core) | 1.5 days | 18 additional tests (total 22) |
| Phase 3 (Polish) | 1 day | 20 final tests (total 42) |
| **TOTAL** | **~4 days** | **85%+ coverage achieved** |

---

## Success Criteria

- ✅ All 42 tests passing
- ✅ Coverage report shows `handlers.ts` at 85%+
- ✅ All critical paths tested (security, execution, permissions)
- ✅ Error handling comprehensive
- ✅ Integration tests verify end-to-end flows
- ✅ No test flakiness (all tests deterministic)
- ✅ <100ms average test execution time

---

## Next Steps

1. **Approval**: Confirm this test plan addresses launch requirements
2. **Setup**: Create test infrastructure and mocks
3. **Implementation**: Follow priority order (Critical → High → Medium)
4. **Review**: Check coverage report after each phase
5. **Polish**: Refactor for performance if needed
6. **Launch**: Declare handlers.ts ready for production

