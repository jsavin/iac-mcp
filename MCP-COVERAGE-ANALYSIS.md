# MCP Coverage Investigation - Complete Analysis

## Executive Summary

**Current MCP Coverage Status:**
- handlers.ts: 65.82% (204 uncovered statements)
- server.ts: 56.94% (124 uncovered statements)
- index.ts: 0% (80 uncovered statements)
- **Overall MCP Coverage: 62.93%**

**Goal: 100% coverage per LAUNCH-MCP-COVERAGE.md**

---

## 1. What PR #13 Actually Added

### PR #13 Summary
**Title:** "MCP Launch Coverage: Add 142 integration tests for critical path (70 server + 72 resource handler tests)"

**Changes:**
- Created `tests/integration/mcp-server-coverage.test.ts` (70 tests)
- Created `tests/integration/mcp-resource-handlers.test.ts` (72 tests)
- Added 2 commits from Jan 21-22, 2026
- Claimed to reach 100% coverage

**Result:** Tests were added but...

### Critical Issue: Tests Were Removed in PR #15

**PR #15 (Lazy Loading MCP Server)** - Commit fb3117a (Jan 23):
- REMOVED `tests/integration/mcp-resource-handlers.test.ts` completely (1,266 lines deleted)
- Reason stated: "Resources now handled via get_app_tools ObjectModel"
- This PR refactored MCP handlers to use lazy loading instead of full tool listing

**Consequence:**
- Resource handler tests (72 tests) no longer exist in the codebase
- The 142 tests from PR #13 were reduced to ~70 existing tests
- Coverage goal of 100% was invalidated by subsequent refactoring

---

## 2. Existing Test Coverage

### Test Files Present

| File | Tests | Purpose |
|------|-------|---------|
| `tests/unit/mcp-handlers.test.ts` | 2,889 lines | Unit tests for handler functions (type/behavior definitions) |
| `tests/unit/iac-mcp-server.test.ts` | 969 lines | Unit tests for server class |
| `tests/integration/mcp-integration.test.ts` | 24,735 bytes | Integration tests with real components |
| `tests/integration/mcp-server-coverage.test.ts` | 31,984 bytes | Server lifecycle coverage tests (from PR #13) |

### Current Test Status

**What IS Tested (65-88% coverage in each module):**
- Server initialization and startup
- Tool discovery and lazy loading
- App metadata building
- Server status tracking
- Basic error handling paths

**What is NOT Tested (35% uncovered in handlers, 43% in server):**
- Lazy loading tool execution (get_app_tools handler)
- Resource handlers (ListResources, ReadResource)
- Tool argument validation and permission checking
- Complex error scenarios
- Main function (index.ts)

---

## 3. Detailed Uncovered Line Analysis

### handlers.ts (204 uncovered statements)

**Uncovered Line Ranges:**
- 130, 248-252, 290-291, 294-295, 327-328, 393-398, 457-463, 507-516, 562-569, 582, 585-590, 621, 623-628, 630-639, 645-649, 651-660, 663-665, 667-669, 671-680, 682-685, 691-693, 695-704, 707-718, 720-726, 728-737, 740-744, 746-755, 779-785, 814-822, 865-866, 868-875, 892-902, 912-919

**What's Missing (Analyzed from source code):**

| Code Section | Lines | Reason |
|--------------|-------|--------|
| Security warning classification in WarningAggregator | 119-139 | Branch conditions (isSecurityWarning flag paths) not tested |
| SDEF parsing error handling | 288-295 | Fallback metadata generation for parse failures |
| App discovery and metadata caching | 392-398, 457-463 | Cache miss/expiry logic, parallel promise handling |
| Lazy loading validation (get_app_tools) | 507-569 | Input validation (length, character whitelist, null bytes) |
| Tool lookup and execution pipeline | 621-755 | Complete CallTool handler path (lookup, validation, permissions, execution) |
| Resource handler endpoints | 779-822, 865-875 | ListResources and ReadResource handlers |
| Error formatting functions | 892-919 | formatErrorResponse, formatSuccessResponse, formatPermissionDeniedResponse |

**Core Issue:** Handlers.ts has 2+ handler implementations that are NOT being tested:
1. **CallTool Handler (lines 474-756)** - Execute tools with full pipeline
2. **ListResources Handler (lines 764-786)** - Provide app metadata resources
3. **ReadResource Handler (lines 794-876)** - Return resource content for iac://apps

These are replaced/modified by PR #15 but no integration tests exercise them.

---

### server.ts (124 uncovered statements)

**Uncovered Line Ranges:**
- 217-220, 243-249, 254, 263-267, 285-286, 310-311, 331-332, 352-356, 388-389, 393-394, 396-410, 413-428, 431-434, 436-451, 454, 457-464, 467-478, 480-495, 510-513

**What's Missing (Analyzed from source code):**

| Code Section | Lines | Reason |
|--------------|-------|--------|
| SDEF parsing error handling in initialize() | 216-220 | Try-catch for failed app parsing |
| ListTools override handler | 242-249 | Server's custom ListTools (lazy loading) |
| CallTool override handler | 253-254 | Server's custom CallTool execution pipeline |
| Start conditions and transport setup | 284-286, 309-311 | "Already running" checks, transport creation |
| Stop conditions and cleanup | 330-332, 352-356 | "Not running" checks, resource cleanup |
| handleToolCall method (lines 387-494) | Most of it | Tool execution pipeline implementation |
| Permission enforcement | 431-451 | Permission checker invocation and decision handling |
| Adapter execution and result formatting | 454, 457-478 | Execute call and result/error formatting |
| Error handling throughout | Various | Catch blocks and error logging |

**Core Issue:** `IACMCPServer.handleToolCall()` (lines 387-494) is NOT tested at all:
- This is the actual tool execution pipeline in server class
- It duplicates code that should be in handlers
- **Design problem:** Two different implementations of tool execution

---

### index.ts (0% / 80 uncovered statements)

**What's Missing:**
- **Entire file is uncovered** - Entry point never executed during tests
- 10 imports (never loaded)
- 3 async functions (main, shutdown handler, SIGINT/SIGTERM setup)
- MCP server initialization
- Graceful shutdown

**Why:** Tests use `IACMCPServer` class directly, never invoke the CLI entry point.

**Question:** Is index.ts meant to be CLI-only, or should it be integration tested?

---

## 4. Root Causes of Low Coverage

### Issue 1: Architecture Inconsistency
**Problem:** Tool execution implemented in TWO places:
- `src/mcp/handlers.ts` - setupHandlers() creates lazy loading handlers
- `src/mcp/server.ts` - IACMCPServer.handleToolCall() duplicates execution logic

**Result:** Only one implementation is tested, the other has 0% coverage

**Solution:** Consolidate to single implementation in handlers, remove from server

---

### Issue 2: Lazy Loading Refactor Not Fully Integrated

**Timeline:**
1. PR #13 (Jan 21): Added resource handler tests
2. PR #15 (Jan 23): Refactored to lazy loading, removed resource tests
3. Result: New lazy loading code has no test coverage

**Code Changes in PR #15:**
- `src/mcp/handlers.ts` - Rewrote ListTools to return metadata only
- `src/mcp/handlers.ts` - Added get_app_tools tool for lazy loading
- Removed corresponding tests

**Missing Tests:**
- get_app_tools handler with input validation
- App name validation (length, character whitelist, null bytes)
- Lazy loading cache hits/misses
- list_apps tool execution
- Resource handlers (if still needed)

---

### Issue 3: Resource Handlers Redesign

**Before PR #15:**
- Resource handlers returned full app dictionaries
- 72 integration tests covered this

**After PR #15:**
- Resources still defined (iac://apps endpoint exists)
- But moved to shared discoverAppMetadata() function
- Tests were deleted, assuming coverage elsewhere

**Reality:**
- ListResources handler: ~20 lines untested
- ReadResource handler: ~80 lines untested
- formatAppMetadataResponse: untested

---

### Issue 4: Missing CLI/Entry Point Tests

**Issue:** index.ts (CLI entry point) has 0% coverage

**Why it matters:**
- This is how users/Claude Desktop runs the server
- No tests verify stdout/stderr for MCP transport
- No tests verify signal handling (SIGINT/SIGTERM)

**Decision needed:**
- Should this be tested via integration test that spawns process?
- Or only test via IACMCPServer class that index.ts uses?

---

## 5. Coverage Goals vs Reality

### What LAUNCH-MCP-COVERAGE.md Says

**Required for launch:**
- 100% coverage of critical path:
  - `src/mcp/server.ts` ✅ Mentioned
  - `src/mcp/handlers.ts` ✅ Mentioned
  - `src/index.ts` ⚠️ Implied

- Tests must verify:
  - ✅ Every scriptable app is discovered (ListTools completeness)
  - ✅ Every app's commands become MCP tools
  - ⚠️ Tool execution works end-to-end
  - ✅ Error handling is graceful
  - ⚠️ Server is stable under load
  - ⚠️ Performance is acceptable

### What Tests Actually Cover

| Requirement | Coverage | Status |
|------------|----------|--------|
| App discovery | ✅ 100% | Tested in mcp-server-coverage.test.ts |
| Tool generation | ✅ 100% | Tested in app discovery tests |
| Tool execution (main path) | ⚠️ ~30% | Only basic paths tested |
| Error handling | ⚠️ ~40% | Some error cases untested |
| Permission checking | ⚠️ ~50% | Not fully integrated |
| Resource endpoints | ⚠️ 0% | Tests were removed |
| CLI entry point | ❌ 0% | Never tested |

---

## 6. Why Coverage Report Shows Discrepancy

### "204 uncovered statements in handlers.ts" vs "65.82%"

Uncovered statements include:
1. **Dead code paths** (error handling branches that don't execute in tests)
2. **Features removed but code not deleted** (resource handlers replaced but not removed)
3. **Type guards and validations** (security checks that tests don't trigger)

Example from handlers.ts line 620:
```typescript
// Line 621-639: Tool lookup and validation - UNTESTED
const tool = discoveredTools.find(t => t.name === toolName);
if (!tool) {
  console.error(`[CallTool] Tool not found: ${toolName}`);
  // ... error response
}
```

This entire code path is uncovered because:
- Tests call lazy loading handlers (get_app_tools)
- Don't call the main CallTool path
- discoveredTools array is never used

---

## 7. Test Coverage Mapping

### Handlers.ts

**What IS tested (65.82%):**
- WarningAggregator class (118-197)
- aggregateWarnings function (211-225)
- discoverAppMetadata function (235-310)
- formatAppMetadataResponse function (321-338)
- setupHandlers registration (360-367)
- ListTools handler basic path (381-464)
- get_app_tools basic validation (520-569)

**What is NOT tested (34.18%):**
- get_app_tools complete execution (571-617)
- get_app_tools error cases (592-616)
- CallTool handler (existing path at 619-755)
- Tool validation pipeline (641-660)
- Permission checking (662-685)
- Adapter execution (687-702)
- Error formatting (691-737)
- ListResources handler (764-786)
- ReadResource handler (794-876)
- Error response functions (892-919)

### Server.ts

**What IS tested (56.94%):**
- Constructor (129-168)
- initialize() partial path
- start() partial path
- stop() partial path
- getStatus() (364-371)

**What is NOT tested (43.06%):**
- initialize() error handling
- SDEF parsing loop error paths
- ListTools handler override
- CallTool handler override
- start() pre-conditions
- stop() pre-conditions
- handleToolCall() (entire method 387-494)
  - Tool lookup
  - Validation
  - Permission check
  - Execution
  - Error handling
- Resource cleanup
- Logging conditions (when enableLogging=true)

---

## 8. Recommendations to Reach 100% Coverage

### Phase 1: Fix Architecture (Prerequisite)

**Action:** Consolidate tool execution
- Remove IACMCPServer.handleToolCall() (duplicate)
- Have server.ts call handlers.setupHandlers() instead
- Single source of truth for tool execution

**Benefit:** Reduces code duplication, clarifies architecture

### Phase 2: Add Missing Tests for handlers.ts (34% → 100%)

**Priority 1 - Critical Path (Tool Execution):**
1. Get_app_tools handler with valid app name
2. Get_app_tools handler with invalid app name (validation tests)
3. Get_app_tools handler - app not found
4. Get_app_tools handler - SDEF parsing fails
5. List_apps tool execution
6. CallTool handler (lookup, validate, execute)

**Priority 2 - Error Cases:**
7. Tool not found error
8. Invalid arguments error
9. Permission denied error
10. Execution failure error
11. AppNotFoundError handling

**Priority 3 - Resource Handlers:**
12. ListResources handler returns correct resources
13. ReadResource handler for iac://apps
14. ReadResource handler for unknown URI
15. ReadResource handler with invalid URI
16. ReadResource handler with long URI (DoS protection)

**Priority 4 - Helper Functions:**
17. formatErrorResponse with various error types
18. getErrorCode mapping
19. formatSuccessResponse
20. formatPermissionDeniedResponse
21. validateToolArguments success case
22. validateToolArguments missing required
23. validateToolArguments wrong type

**Estimate:** ~40-50 new tests needed

### Phase 3: Add Missing Tests for server.ts (43% → 100%)

**Priority 1 - Lifecycle Tests:**
1. initialize() with 0 apps discovered
2. initialize() with SDEF parsing failures
3. start() when already running
4. start() when not initialized
5. stop() when not running
6. Repeated initialize/start/stop cycles

**Priority 2 - Handler Override Tests:**
7. ListTools override returns generated tools
8. CallTool override executes handleToolCall
9. Tool execution via server.handleToolCall()

**Priority 3 - Error Conditions:**
10. handleToolCall with tool not found
11. handleToolCall with invalid arguments
12. handleToolCall with permission denied
13. handleToolCall with execution error
14. extractBundleId with various path formats

**Priority 4 - State Management:**
15. getStatus() reflects correct metrics
16. uptime calculation
17. startTime tracking

**Estimate:** ~20-25 new tests needed

### Phase 4: Add CLI Tests for index.ts (0% → 100%)

**Option A: Process-based Integration Test**
- Spawn index.js as subprocess
- Send test data via stdin (MCP protocol)
- Verify stdout responses
- Verify signal handling

**Option B: Mock Transport Test**
- Create mock StdioServerTransport
- Call main() with mock transport
- Verify server lifecycle

**Estimate:** ~5-10 tests, but infrastructure heavy

---

## 9. Key Files to Update with Tests

```
tests/unit/mcp-handlers.test.ts
├── WarningAggregator class tests ✅
├── aggregateWarnings function ✅
├── discoverAppMetadata function ✅
├── formatAppMetadataResponse function ⚠️ Partial
├── setupHandlers function ⚠️ Needs CallTool/ResourceHandlers
│   ├── ListTools handler ✅ Basic
│   ├── CallTool handler ❌ Missing
│   ├── get_app_tools tool ⚠️ Partial
│   ├── list_apps tool ❌ Missing
│   ├── ListResources handler ❌ Missing
│   └── ReadResource handler ❌ Missing
└── Helper functions ⚠️ Partial

tests/unit/iac-mcp-server.test.ts
├── IACMCPServer constructor ✅
├── initialize() ⚠️ Partial
├── start() ⚠️ Partial
├── stop() ⚠️ Partial
├── getStatus() ✅
├── handleToolCall() ❌ Missing
└── extractBundleId() ⚠️ Partial

tests/integration/
├── mcp-server-coverage.test.ts ✅ (Server lifecycle)
├── mcp-integration.test.ts ✅ (Basic integration)
└── mcp-cli.test.ts ❌ Missing (Entry point/CLI)
```

---

## 10. Coverage Metrics Summary

### By Component

| Component | Current | Target | Gap | Tests Needed |
|-----------|---------|--------|-----|--------------|
| handlers.ts | 65.82% | 100% | 34.18% | ~40-50 |
| server.ts | 56.94% | 100% | 43.06% | ~20-25 |
| index.ts | 0% | 100% | 100% | ~5-10 |
| **Overall MCP** | **62.93%** | **100%** | **37.07%** | **~65-85** |

### Test Categories Needed

| Category | Tests | Priority |
|----------|-------|----------|
| Happy path execution | 15 | P0 |
| Error handling | 20 | P0 |
| Input validation | 15 | P0 |
| Edge cases | 15 | P1 |
| Integration/E2E | 10 | P1 |
| CLI entry point | 10 | P2 |
| **Total** | **~85** | |

---

## 11. PR #13 Assessment

**Question:** "Why did PR #13 claim 100% coverage if tests are uncovered?"

**Possible Explanations:**

1. **Tests were written before code** (TDD)
   - PR #13 added comprehensive tests
   - Tests passed but didn't actually cover resource handler code
   - Code paths never exercised during test runs

2. **Test infrastructure issue**
   - Tests mock too much (handlers not actually called)
   - setupHandlers() called but specific handlers not invoked
   - Mock server.setRequestHandler() called but handlers never executed

3. **Coverage tool misconfiguration**
   - Coverage reporter not tracking handler execution properly
   - Handlers executed via jest.fn().mock instead of real calls

4. **Subsequent refactoring (PR #15) broke claims**
   - PR #13: "100% coverage achieved"
   - PR #15: Refactored lazy loading, removed resource tests
   - PR #15 assumed coverage elsewhere (it wasn't)

**Most Likely:** Combination of factors 1 + 4
- PR #13 added tests that validate API contracts
- PR #15 refactored but didn't add corresponding tests
- Result: 65% statement coverage despite 142 tests

---

## 12. Conclusion

### Root Cause
MCP coverage is low (62.93%) because:
1. Tests removed in PR #15 without replacement tests added
2. Architecture has duplicate tool execution (server.ts + handlers.ts)
3. Lazy loading feature added without comprehensive test coverage
4. Resource handlers redesigned but tests not updated
5. CLI entry point (index.ts) never tested

### Path to 100%
1. Add ~65-85 new tests covering gaps identified above
2. Consolidate architecture (single tool execution implementation)
3. Ensure all test files for new code follow existing patterns
4. Add CLI integration tests for index.ts
5. Re-evaluate if resource handlers needed post-lazy-loading

### Effort Estimate
- Writing tests: 3-4 days
- Fixing architecture: 1 day
- Code review/iteration: 1-2 days
- **Total: 5-7 days to 100% coverage**

