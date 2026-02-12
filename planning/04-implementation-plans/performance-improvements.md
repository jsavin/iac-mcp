# Multi-Phase Plan: MCP Server Performance Improvements

**Created**: 2026-02-10
**Source**: `planning/Performance Improvement Suggestions - 2026-01-10.md`

## Overview

This plan addresses 10 performance improvement recommendations focused on **reducing round-trips** between the LLM and MCP server. The improvements are organized into 4 phases based on dependencies, complexity, and impact.

**Theme**: Every tool call has 2-5 seconds of latency. The current "Unix philosophy" design with small composable primitives creates painful cumulative latency for common tasks.

---

## Phase 1: Low-Hanging Fruit (High Impact, Low Complexity)

These improvements require minimal architectural changes and provide immediate value.

### 1.1 Universal `activate_app` Command

**Problem**: Every session starts with activating an app. Currently requires figuring out if app has its own `activate` command, falling back to System Events if not.

**Solution**: Add top-level `activate_app` tool that handles this logic internally.

**Implementation**:
- File: `src/mcp/handlers.ts`
- Add new tool `activate_app` with single `app_name` parameter
- Logic:
  1. Try app's native `activate` command via `execute_app_command`
  2. If not available, use System Events: `Application("System Events").processes[appName].frontmost = true`
- Return success/failure with clear message

**Effort**: ~1-2 hours

---

### 1.2 Element Type Naming Normalization

**Problem**: `"menu bar"` fails with syntax error but `"menuBar"` works. SDEF reports names with spaces, but JXA needs camelCase.

**Solution**: Accept both formats, normalize internally.

**Implementation**:
- File: `src/execution/query-executor.ts`
- Add `normalizeElementType()` function that converts "menu bar" → "menuBar"
- Apply in `buildElementReference()` before using element type

**Effort**: ~1 hour

---

### 1.3 Clearer Specifier Documentation

**Problem**: LLM struggles with specifier syntax. Tried `{"type": "named", "element": "application"}` instead of `{"type": "application"}`.

**Solution**: Embed concrete examples in tool descriptions.

**Implementation**:
- File: `src/mcp/handlers.ts`
- Update `get_elements`, `get_properties`, `set_property` tool descriptions with examples:
  - `{"type": "application"}` - Reference the app itself
  - `{"type": "element", "element": "window", "index": 0, "container": "application"}` - First window
  - `{"type": "named", "element": "window", "name": "Main", "container": "application"}` - Window by name

**Effort**: ~30 minutes

---

### 1.4 Pre-load App Tools Implicitly

**Problem**: Having to call `get_app_tools` before `execute_app_command` is friction.

**Solution**: Auto-load tools on first `execute_app_command` if not already loaded.

**Implementation**:
- File: `src/mcp/handlers.ts`
- In `execute_app_command` handler, before validation, check if tools are loaded for that app
- If not, call `loadAppTools()` automatically

**Effort**: ~30 minutes

---

## Phase 2: Batch Operations (High Impact, Medium Complexity)

These improvements collapse multiple calls into single operations.

### 2.1 Batch Property Fetching: `get_elements_with_properties`

**Problem**: Getting names of 9 menu bar items requires 9 separate `get_properties` calls.

**Solution**: New tool that returns elements with their key properties in one shot.

**Implementation**:
- File: `src/mcp/handlers.ts` - Add new tool handler
- File: `src/execution/query-executor.ts` - Add `getElementsWithProperties()` method

**Tool Schema**:
```typescript
{
  name: "get_elements_with_properties",
  inputSchema: {
    app_name: string,
    specifier: ObjectSpecifier,  // Parent container
    element_type: string,        // e.g., "menuBarItem"
    properties: string[],        // e.g., ["name", "enabled"]
    limit?: number               // Max elements (default: 100)
  }
}
```

**JXA generates single script** that returns array of `{_index, _ref_id, ...properties}`.

**Effort**: ~4-6 hours

---

### 2.2 Property Type Hints in Responses

**Problem**: When `get_properties` returns values, no type information is included.

**Solution**: Include type hints: `{value: X, type: "string"|"number"|"boolean"|"reference"|...}`.

**Implementation**:
- File: `src/execution/query-executor.ts` - Modify response format
- File: `src/adapters/macos/result-parser.ts` - Add type inference

**Effort**: ~2-3 hours

---

## Phase 3: High-Value Composite Tools (Medium-High Complexity)

These tools collapse common multi-step workflows into single calls.

### 3.1 `describe_ui` / `snapshot` Command

**Problem**: Exploring a window requires dozens of calls: get elements → get properties → get children → repeat.

**Solution**: Single call that returns a shallow tree of UI elements with key properties.

**Tool Schema**:
```typescript
{
  name: "describe_ui",
  inputSchema: {
    app_name: string,
    specifier?: ObjectSpecifier,  // Default: first window
    depth?: number,               // Default: 2
    properties?: string[]         // Default: ["name", "role", "enabled", "value"]
  }
}
```

**Returns**: Nested structure with `{element, name, role, ref_id, children[]}`.

**Effort**: ~6-8 hours

---

### 3.2 `click_menu` Shortcut

**Problem**: Clicking a menu requires 6+ calls.

**Solution**: Single call with menu path like `"View > Go to Today"`.

**Tool Schema**:
```typescript
{
  name: "click_menu",
  inputSchema: {
    app_name: string,
    menu_path: string  // e.g., "File > New > Document"
  }
}
```

**Error handling**: If not found, return available items at that level.

**Effort**: ~3-4 hours

---

### 3.3 `send_keystroke` Shortcut

**Problem**: Sending a keystroke requires multiple calls (activate + build specifier + send).

**Solution**: Single call that handles activation and keystroke.

**Tool Schema**:
```typescript
{
  name: "send_keystroke",
  inputSchema: {
    app_name: string,
    key: string,              // e.g., "t", "return", "escape"
    modifiers?: string[]      // e.g., ["command", "shift"]
  }
}
```

**Effort**: ~2-3 hours

---

## Phase 4: Enhanced Error Handling & Reference Management

### 4.1 Richer Error Messages with Suggestions

**Problem**: Errors are sometimes JXA stack traces rather than actionable guidance.

**Solution**: Parse common errors and provide suggestions.

**Implementation**:
- File: `src/adapters/macos/result-parser.ts` - Add error parsing
- Map common errors to suggestions:
  - "Can't get" → "Element not found. Try get_elements first."
  - "Invalid index" → "Index out of bounds. Check element count."
  - "doesn't understand" → "App doesn't support this. Check get_app_tools."

**Effort**: ~3-4 hours

---

### 4.2 Reference Lifetime Management

**Problem**: References expire after 15 minutes. Need to re-query after restart.

**Solution**: Add `validate_reference` tool and store human-readable paths for recreation.

**Tool Schema**:
```typescript
{
  name: "validate_reference",
  inputSchema: { ref_id: string }
}
// Returns: { valid: boolean, expires_in_seconds?: number, path?: string }
```

**Effort**: ~3-4 hours

---

## Implementation Order & Dependencies

```
Phase 1 (No dependencies - can parallelize all 4):
├── 1.1 activate_app
├── 1.2 Element type normalization
├── 1.3 Specifier documentation
└── 1.4 Pre-load app tools

Phase 2 (Depends on Phase 1.2):
├── 2.1 get_elements_with_properties
└── 2.2 Property type hints

Phase 3 (Depends on Phase 2.1):
├── 3.1 describe_ui
├── 3.2 click_menu
└── 3.3 send_keystroke

Phase 4 (Independent - can start after Phase 1):
├── 4.1 Enhanced error messages
└── 4.2 Reference validation
```

---

## Estimated Effort Summary

| Phase | Items | Estimated Hours | Cumulative Impact |
|-------|-------|-----------------|-------------------|
| 1 | 4 items | 3-4 hours | 40% reduction in common round-trips |
| 2 | 2 items | 6-9 hours | 60% reduction (batch ops) |
| 3 | 3 items | 11-15 hours | 80% reduction (composite tools) |
| 4 | 2 items | 6-8 hours | 85% reduction + better DX |

**Total: ~26-36 hours**

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/mcp/handlers.ts` | Add 7 new tool handlers, update 3 descriptions |
| `src/execution/query-executor.ts` | Add batch methods, element normalization |
| `src/execution/reference-store.ts` | Add validation, path storage |
| `src/adapters/macos/result-parser.ts` | Add type inference, error parsing |
| `tests/integration/` | New test files for each tool |
| `tests/unit/` | Unit tests for new helpers |

---

## Verification

After each phase:
1. Run `npm test` - all tests must pass
2. Run `npm run test:coverage` - maintain 100% coverage
3. Manual testing with Claude Desktop:
   - Phase 1: Verify `activate_app` works, element names with spaces work
   - Phase 2: Verify `get_elements_with_properties` returns batch data
   - Phase 3: Verify `describe_ui`, `click_menu`, `send_keystroke` work end-to-end
   - Phase 4: Verify error messages include suggestions

---

## Success Criteria

- [ ] Common UI exploration: 1-2 calls instead of 20+
- [ ] Menu clicks: 1 call instead of 6+
- [ ] App activation: 1 call always works
- [ ] No more "syntax error" for element names with spaces
- [ ] Clear error messages with actionable suggestions
- [ ] LLM can self-correct without user intervention in most cases
