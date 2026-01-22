# Launch MCP Coverage Plan

**Objective:** Achieve 100% test coverage on MCP server critical path and launch with confidence that every scriptable Mac app is discoverable and callable via Claude MCP tools.

**Timeline:** 3-4 focused hours (can be split across 1-2 days)

**Owner:** Claude (autonomous execution) | Approver: Jake (decisions only)

---

## Phase A: MCP Server Tests (2 hours)

### Target Files
- `src/mcp/server.ts` (0% → 100%)
- `src/mcp/handlers.ts` (5% → 100%)

### Test Coverage Goals

**File: `src/mcp/server.ts`**
- Server initialization and startup
- MCP protocol compliance (ListTools, CallTool)
- Tool discovery completeness (all apps discovered)
- Tool metadata accuracy (names, descriptions, schemas)
- Error handling (malformed requests, invalid tools)
- Server shutdown and cleanup
- Event handlers (tool execution, errors)

**File: `src/mcp/handlers.ts`**
- ListTools handler returns all apps with SDEF files
- ListTools response format (valid MCP schema)
- CallTool handler execution (valid tool names, parameters)
- CallTool error cases (app not found, execution timeout, JXA error)
- Parameter validation and marshaling
- Result formatting (success, error, partial results)
- Concurrency handling (multiple simultaneous tool calls)

### Test File
Create: `tests/integration/mcp-server-coverage.test.ts`

### Success Criteria
- [ ] 100% statement coverage for `src/mcp/server.ts`
- [ ] 100% statement coverage for `src/mcp/handlers.ts`
- [ ] 100% branch coverage (all error paths tested)
- [ ] All tests pass
- [ ] No new warnings or regressions

---

## Phase B: Entry Point Tests (1 hour)

### Target Files
- `src/index.ts` (0% → 100%)

### Test Coverage Goals
- Module initialization
- Server startup (with and without options)
- Exports are correct (all public APIs exposed)
- Default configuration
- Error handling in initialization

### Test File
Extend: `tests/integration/mcp-server-coverage.test.ts` OR `tests/unit/index.test.ts`

### Success Criteria
- [ ] 100% coverage for `src/index.ts`
- [ ] Module exports verified
- [ ] Initialization tested

---

## Phase C: Verification & Launch (30 min)

### Pre-Launch Checklist
```bash
# Run all tests
npm test
# Expected: 1400+ tests passing, 0 failures

# Check coverage
npm run test:coverage
# Expected: src/mcp/* at 100%, overall >80%

# Build verification
npm run build
# Expected: 0 errors, 0 warnings

# Manual smoke test
npm start
# Expected: Server starts without errors, can list tools
```

### Launch Gate
- [ ] All tests passing
- [ ] 100% MCP coverage achieved
- [ ] No regressions from existing tests
- [ ] Build succeeds
- [ ] Manual smoke test passes

---

## Implementation Notes

### Test Strategy for MCP Server

**Focus Areas:**
1. **Integration tests** (not unit) - test MCP protocol end-to-end
2. **Mock fixtures** - use test SDEF files (already exist)
3. **Real execution** - verify actual app discovery and tool calling works
4. **Error scenarios** - permission denied, app not found, timeout, malformed XML

**Example Test Structure:**
```typescript
describe('MCP Server - Full Integration', () => {
  describe('ListTools', () => {
    it('should discover all apps with SDEF files', async () => {
      // Initialize server
      // Call ListTools
      // Verify response includes Finder, Safari, Mail, etc.
      // Verify tool schema is valid
    });

    it('should handle server initialization failure gracefully', async () => {
      // Try to initialize with invalid config
      // Expect error message
    });
  });

  describe('CallTool', () => {
    it('should execute a valid tool against Finder', async () => {
      // Call a known Finder command
      // Verify result is returned
    });

    it('should handle app not found error', async () => {
      // Try to call a tool from non-existent app
      // Expect proper error response
    });
  });
});
```

### What NOT to Test
- ❌ Type definitions (can't test runtime behavior of pure types)
- ❌ CLI code (not part of launch, library is primary distribution)
- ❌ Example code (not customer-facing)
- ❌ Phase 4 metrics infrastructure (post-launch optimization)

### Coverage Measurement
```bash
npm run test:coverage -- tests/integration/mcp-server-coverage.test.ts
# Verify only src/mcp/* and src/index.ts shown at 100%
```

---

## Execution Plan with Visibility Checkpoints

### Step 1: Analyze Current MCP Code (15 min)
- [ ] Read `src/mcp/server.ts` - understand server setup, handlers, lifecycle
- [ ] Read `src/mcp/handlers.ts` - understand tool execution flow
- [ ] Read `src/index.ts` - understand exports and initialization
- [ ] Identify all code paths (success, error, edge cases)

**📊 CHECKPOINT 1:** Report code structure findings, test strategy approach

---

### Step 2: Create Test File (30 min)
- [ ] Create `tests/integration/mcp-server-coverage.test.ts`
- [ ] Set up test fixtures (mock SDEF parser, real JITD engine)
- [ ] Create MCP server test harness

**📊 CHECKPOINT 2:** Share test file structure, fixture setup, explain test harness design

---

### Step 3: Write ListTools Tests (30 min)
- [ ] Test server initialization
- [ ] Test ListTools handler
- [ ] Verify all apps discovered
- [ ] Verify schema compliance
- [ ] Test error cases

**📊 CHECKPOINT 3:** Show test code samples, report test count for ListTools, coverage % change

---

### Step 4: Write CallTool Tests (30 min)
- [ ] Test tool execution (Finder known command)
- [ ] Test parameter marshaling
- [ ] Test error handling (app not found, execution fails)
- [ ] Test result formatting
- [ ] Test concurrency

**📊 CHECKPOINT 4:** Show test code samples, report test count for CallTool, coverage % change, any unexpected findings

---

### Step 5: Write Entry Point Tests (15 min)
- [ ] Test module initialization
- [ ] Test exports
- [ ] Test with/without options
- [ ] Test default config

**📊 CHECKPOINT 5:** Show test code, report total test count, coverage % on src/index.ts

---

### Step 6: Verify Coverage & Fix Gaps (15 min)
- [ ] Run `npm run test:coverage`
- [ ] Verify 100% on critical path files
- [ ] Identify and fix any gaps
- [ ] Run full test suite (ensure no regressions)

**📊 CHECKPOINT 6:** Share coverage report, confirm 100% on critical path, report total test suite status

---

### Step 7: Commit & Final Report (10 min)
- [ ] Create commit with message explaining coverage
- [ ] Report completion with test counts and coverage %
- [ ] Ask: "Proceed to launch verification?"

**📊 FINAL REPORT:**
- Total new tests written
- Critical path files at 100%
- Overall coverage before/after
- Any regressions detected
- Ready/not-ready assessment

---

## Success Definition

**We are launch-ready when:**
- ✅ `src/mcp/server.ts` = 100% coverage
- ✅ `src/mcp/handlers.ts` = 100% coverage
- ✅ `src/index.ts` = 100% coverage
- ✅ All new tests pass
- ✅ All existing tests still pass
- ✅ No regressions detected
- ✅ MCP protocol compliance verified
- ✅ Manual smoke test confirms server works

**Then:** Ready to launch. Every scriptable Mac app is discoverable and callable via MCP.

---

## Decision Point After Completion

**To User:** "Phase A-C complete. MCP server at 100% coverage. Ready to ship?"

**Options:**
1. **LAUNCH** - Deploy to production immediately
2. **EXTEND** - Add optional features (CLI testing, metrics, etc.)
3. **REFINE** - Based on feedback, make improvements

---

## Notes for Future Maintenance

- This plan prioritizes **launch readiness over 100% codebase coverage**
- CLI, type definitions, examples, and metrics can be added post-launch
- The 57% overall coverage is acceptable for launch because the critical path (MCP) is at 100%
- All future features should follow the same pattern: 100% on critical path, optimize the rest later
