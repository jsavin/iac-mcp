# Stateful Query System Implementation Plan

**Status:** Planning → Ready for /doit
**Priority:** Critical (blocks core MCP functionality)
**Estimated Effort:** 8-10 days (4 phases)
**Owner:** TBD
**Created:** 2026-01-27

---

## Problem Statement

The iac-mcp server currently exposes **commands (verbs)** from scriptable apps but lacks the ability to **query objects and read their properties**. This prevents Claude from answering questions like "What's my most recent email?" because:

1. ❌ No way to query objects (e.g., "get message 1 of inbox")
2. ❌ No way to read properties (e.g., "subject of message")
3. ❌ No way to enumerate elements (e.g., "all unread messages")
4. ❌ Action tools require object references we can't obtain

**Example failure:**
```
User: "What's my most recent email?"
Claude: "I can see mail_delete and mail_send tools, but I can't query messages."
```

---

## Solution Overview

Implement a **stateful object reference system** with JSON-based object specifiers that allows:

1. ✅ Query objects and get stable references
2. ✅ Read properties from referenced objects
3. ✅ Enumerate elements from containers
4. ✅ Set properties (Phase 3)
5. ✅ Automatic reference cleanup (Phase 4)

**Key Design Decisions:**

- **Stateful references:** Object queries return reference IDs that persist across multiple tool calls (15+ minute TTL)
- **JSON specifiers:** Structured, explicit object paths (not AppleScript strings)
- **Canonical references:** References survive app relaunches/reboots where the underlying OSA system supports it
- **Graceful degradation:** If reference becomes invalid, LLM re-queries automatically

---

## Architecture

### High-Level Flow

```
┌─────────────┐
│   Claude    │
└──────┬──────┘
       │
       │ 1. query_object({ app, specifier })
       ▼
┌─────────────────────┐
│  Query Tools        │
│  (MCP Interface)    │
└──────┬──────────────┘
       │
       │ 2. QueryExecutor.execute()
       ▼
┌─────────────────────┐
│  ReferenceStore     │
│  (State Management) │
└──────┬──────────────┘
       │
       │ 3. Build JXA, execute
       ▼
┌─────────────────────┐
│  JXA Executor       │
│  (OSA Bridge)       │
└──────┬──────────────┘
       │
       │ 4. Return reference ID
       ▼
┌─────────────┐
│   Claude    │ Stores ref_abc123 for future use
└─────────────┘
```

### Component Responsibilities

| Component | Responsibility | Location |
|-----------|----------------|----------|
| **Query Tools** | MCP tool definitions (ListTools) | `src/jitd/tool-generator/query-tools.ts` |
| **QueryExecutor** | Parse specifiers, build JXA, execute | `src/execution/query-executor.ts` |
| **ReferenceStore** | Store/retrieve/cleanup references | `src/execution/reference-store.ts` |
| **JXA Executor** | Execute JXA code, return results | `src/execution/jxa-executor.ts` (existing) |
| **Type Definitions** | ObjectSpecifier, ObjectReference types | `src/types/object-specifier.ts`, `src/types/object-reference.ts` |

---

## Phased Implementation

### Phase 1: Core Stateful Queries (MVP) ⭐

**Goal:** Enable basic object querying and property reading with stateful references.

**Deliverables:**
- ✅ Type definitions for `ObjectSpecifier` and `ObjectReference`
- ✅ `ReferenceStore` with TTL-based cleanup (15 minutes)
- ✅ `QueryExecutor` that builds JXA from JSON specifiers
- ✅ Three MCP tools: `query_object`, `get_properties`, `get_elements`
- ✅ Integration with existing MCP server
- ✅ 100% test coverage (unit + integration)

**Success Criteria:**
- Claude can query "most recent email" and read its properties
- References persist for 15+ minutes
- References work across multiple tool calls
- Error handling for invalid references

**Estimated Effort:** 3-4 days

**Detailed Tasks:** See [Phase 1 Implementation Plan](./stateful-query-phase1.md)

---

### Phase 2: Filtering & Advanced Queries

**Goal:** Enable filtered queries and complex object specifiers.

**Deliverables:**
- ✅ `FilterSpecifier` support in type system
- ✅ Enhanced `get_elements` with `where` clause
- ✅ Complex nested specifiers (e.g., "message 1 of mailbox 'Work'")
- ✅ Common filter operators: `==`, `!=`, `contains`, `<`, `>`, `<=`, `>=`

**Success Criteria:**
- Claude can query "unread emails from John"
- Claude can filter by date ranges
- Nested specifiers work correctly

**Estimated Effort:** 2-3 days

**Detailed Tasks:** See [Phase 2 Implementation Plan](./stateful-query-phase2.md)

---

### Phase 3: Property Setters

**Goal:** Enable property modification with permission checks.

**Deliverables:**
- ✅ `set_property` tool implementation
- ✅ Read-write property validation (from sdef)
- ✅ Permission system integration
- ✅ Atomic updates (set succeeds or fails completely)

**Success Criteria:**
- Claude can mark email as read
- Permission prompts for write operations
- Read-only properties rejected gracefully

**Estimated Effort:** 1-2 days

**Detailed Tasks:** See [Phase 3 Implementation Plan](./stateful-query-phase3.md)

---

### Phase 4: Sophisticated GC & Optimization

**Goal:** Production-ready reference management and performance optimization.

**Deliverables:**
- ✅ LRU eviction strategy (in addition to TTL)
- ✅ Reference validation (check if object still exists in app)
- ✅ Max references per app limits (configurable)
- ✅ `release_reference` tool for manual cleanup
- ✅ Batch property reads (performance)
- ✅ Reference statistics and monitoring

**Success Criteria:**
- Memory usage stable under long sessions
- Old/invalid references cleaned up automatically
- Performance benchmarks met (see below)
- Graceful handling of stale references

**Estimated Effort:** 2-3 days

**Detailed Tasks:** See [Phase 4 Implementation Plan](./stateful-query-phase4.md)

---

## Technical Specifications

### Object Reference Format

```typescript
interface ObjectReference {
  id: string;              // Unique ID (e.g., "ref_abc123")
  app: string;             // App bundle ID
  type: string;            // Object class from sdef
  specifier: ObjectSpecifier;  // How to resolve this object
  createdAt: number;       // Unix timestamp (ms)
  lastAccessedAt: number;  // For LRU (Phase 4)
  metadata?: {
    // Optional app-specific data
    [key: string]: any;
  };
}
```

### JSON Object Specifier Types

```typescript
type ObjectSpecifier =
  | ElementSpecifier      // By index: "message 1"
  | NamedSpecifier        // By name: "mailbox 'Work'"
  | IdSpecifier           // By ID: "message id 'abc'"
  | PropertySpecifier     // Property: "subject of message"
  | FilterSpecifier;      // Filtered: "messages where read = false"

interface ElementSpecifier {
  type: "element";
  element: string;        // e.g., "message"
  index: number;          // 0-based
  container: ObjectSpecifier | "application";
}

interface NamedSpecifier {
  type: "named";
  element: string;
  name: string;
  container: ObjectSpecifier | "application";
}

interface IdSpecifier {
  type: "id";
  element: string;
  id: string;             // App-specific ID
  container: ObjectSpecifier | "application";
}

interface PropertySpecifier {
  type: "property";
  property: string;
  of: ObjectSpecifier | string;  // Object specifier or reference ID
}

interface FilterSpecifier {
  type: "filter";
  element: string;
  container: ObjectSpecifier | "application";
  where: FilterExpression;
  limit?: number;
}

interface FilterExpression {
  property: string;
  op: "==" | "!=" | "<" | ">" | "<=" | ">=" | "contains" | "startsWith" | "endsWith";
  value: any;
}
```

### MCP Tool Schemas

#### Tool 1: query_object

```json
{
  "name": "iac_mcp_query_object",
  "description": "Query an object in an application and return a stable reference. The reference can be used in subsequent calls to get_properties, get_elements, or set_property. References remain valid for at least 15 minutes.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "app": {
        "type": "string",
        "description": "App bundle ID (e.g., 'com.apple.mail')"
      },
      "specifier": {
        "type": "object",
        "description": "JSON object specifier defining how to locate the object",
        "oneOf": [
          "ElementSpecifier",
          "NamedSpecifier",
          "IdSpecifier",
          "PropertySpecifier"
        ]
      }
    },
    "required": ["app", "specifier"]
  }
}
```

**Returns:**
```json
{
  "reference": {
    "id": "ref_abc123",
    "type": "message",
    "app": "com.apple.mail"
  }
}
```

#### Tool 2: get_properties

```json
{
  "name": "iac_mcp_get_properties",
  "description": "Get properties of a referenced object. If properties array is null or omitted, returns all available properties.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "reference": {
        "type": "string",
        "description": "Object reference ID from query_object"
      },
      "properties": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Property names to retrieve (null = all properties)"
      }
    },
    "required": ["reference"]
  }
}
```

**Returns:**
```json
{
  "properties": {
    "subject": "Meeting tomorrow",
    "sender": "john@example.com",
    "date received": "2026-01-27T10:30:00Z",
    "read status": false
  }
}
```

#### Tool 3: get_elements

```json
{
  "name": "iac_mcp_get_elements",
  "description": "Get elements from a container object. Returns references to the elements, which can be used in subsequent calls.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "container": {
        "oneOf": [
          { "type": "string", "description": "Reference ID of container" },
          { "type": "object", "description": "Object specifier for container" }
        ]
      },
      "elementType": {
        "type": "string",
        "description": "Type of elements to retrieve (e.g., 'message', 'file')"
      },
      "limit": {
        "type": "number",
        "description": "Maximum number of elements to return (default: 100)"
      }
    },
    "required": ["container", "elementType"]
  }
}
```

**Returns:**
```json
{
  "elements": [
    { "id": "ref_001", "type": "message", "app": "com.apple.mail" },
    { "id": "ref_002", "type": "message", "app": "com.apple.mail" }
  ],
  "count": 2,
  "totalCount": 127,
  "hasMore": true
}
```

---

## Reference Lifecycle

### Creation
1. Claude calls `query_object` with specifier
2. `QueryExecutor` builds JXA code to resolve specifier
3. JXA executes, returns object reference (or error)
4. `ReferenceStore` creates new reference with:
   - Unique ID (`ref_` + random string)
   - App bundle ID
   - Object type (from sdef)
   - Original specifier (for re-resolution if needed)
   - Timestamps (created, lastAccessed)
5. Reference ID returned to Claude

### Usage
1. Claude calls `get_properties` or `get_elements` with reference ID
2. `ReferenceStore` retrieves reference, updates `lastAccessedAt`
3. `QueryExecutor` resolves reference to JXA object path
4. JXA executes, returns result
5. If reference invalid (OSA error), return clear error
6. Claude re-queries if needed

### Expiration
**Phase 1 (TTL only):**
- References expire after 15 minutes of creation
- Background cleanup runs every 5 minutes
- Expired references removed from store

**Phase 4 (TTL + LRU + Validation):**
- References expire after 15 minutes of creation OR
- LRU eviction if max references exceeded OR
- Validation fails (object no longer exists)
- `release_reference` tool for manual cleanup

### Error Handling
When reference is invalid:
```json
{
  "error": "reference_invalid",
  "reference": "ref_abc123",
  "message": "The referenced object no longer exists or cannot be accessed",
  "suggestion": "Query the object again using query_object"
}
```

LLM behavior: Re-query before failing the user request.

---

## JXA Generation Strategy

### Specifier → JXA Mapping

| Specifier Type | JXA Code |
|----------------|----------|
| `ElementSpecifier` | `container.elementType[index]` |
| `NamedSpecifier` | `container.elementType.byName(name)` |
| `IdSpecifier` | `container.elementType.byId(id)` |
| `PropertySpecifier` | `object.property()` |
| `FilterSpecifier` | `container.elementType.whose(filter)` |

### Example Transformations

**ElementSpecifier:**
```json
{
  "type": "element",
  "element": "message",
  "index": 0,
  "container": {
    "type": "named",
    "element": "mailbox",
    "name": "inbox",
    "container": "application"
  }
}
```

**Generated JXA:**
```javascript
const app = Application("Mail");
const inbox = app.mailboxes.byName("inbox");
const message = inbox.messages[0];
return message;
```

**PropertySpecifier:**
```json
{
  "type": "property",
  "property": "subject",
  "of": "ref_abc123"
}
```

**Generated JXA:**
```javascript
const app = Application("Mail");
// Resolve ref_abc123 to object path
const message = /* resolved path */;
return message.subject();
```

---

## Testing Strategy

### Unit Tests (100% Coverage Required)

**ReferenceStore Tests:**
- ✅ `create()` generates unique IDs
- ✅ `get()` retrieves by ID
- ✅ `touch()` updates lastAccessedAt
- ✅ `cleanup()` removes expired references (TTL)
- ✅ Duplicate IDs handled gracefully
- ✅ Non-existent IDs return undefined

**QueryExecutor Tests:**
- ✅ Parse ElementSpecifier → JXA
- ✅ Parse NamedSpecifier → JXA
- ✅ Parse IdSpecifier → JXA
- ✅ Parse PropertySpecifier → JXA
- ✅ Nested specifiers resolve correctly
- ✅ Reference resolution to object path
- ✅ Error handling for invalid specifiers
- ✅ Type conversions (dates, enums, booleans)

**Tool Generator Tests:**
- ✅ Generate query_object schema
- ✅ Generate get_properties schema
- ✅ Generate get_elements schema
- ✅ Schemas include correct types from sdef

### Integration Tests

**With Real Apps:**

**Mail.app:**
- ✅ Query inbox mailbox
- ✅ Get messages from inbox (with limit)
- ✅ Read message properties (subject, sender, date)
- ✅ Query message by index
- ✅ Reference persists across multiple calls
- ✅ Invalid reference returns clear error

**Finder.app:**
- ✅ Query home folder
- ✅ Get files from folder
- ✅ Read file properties (name, size, modification date)
- ✅ Nested folder navigation

**Calendar.app:**
- ✅ Query calendars
- ✅ Get events from calendar
- ✅ Read event properties (summary, start date, location)

**Reference Lifecycle:**
- ✅ References remain valid for 15+ minutes
- ✅ References survive app relaunch (if OSA supports)
- ✅ Stale references handled gracefully
- ✅ Cleanup removes expired references

### End-to-End Tests

**Scenario 1: "What's my most recent email?"**
1. Claude calls `query_object` for inbox → `ref_inbox`
2. Claude calls `get_elements` on `ref_inbox` (limit 1) → `[ref_msg_001]`
3. Claude calls `get_properties` on `ref_msg_001` → `{subject, sender, date}`
4. Claude responds to user with email details

**Scenario 2: "Mark the first 5 unread emails as read"** (Phase 3)
1. Claude calls `query_object` for inbox → `ref_inbox`
2. Claude calls `get_elements` with filter (unread, limit 5) → `[ref_msg_001, ...]`
3. For each ref: Claude calls `set_property(ref, "read status", true)`
4. Claude confirms completion to user

**Scenario 3: "List files in my Documents folder"**
1. Claude calls `query_object` for Documents folder → `ref_docs`
2. Claude calls `get_elements` on `ref_docs` (elementType: "file") → `[ref_file_001, ...]`
3. Claude calls `get_properties` on each file ref → `{name, size, ...}`
4. Claude formats and displays list to user

---

## Performance Requirements

### Phase 1 (MVP)
- ✅ `query_object`: < 2 seconds (simple queries)
- ✅ `get_properties`: < 1 second
- ✅ `get_elements`: < 3 seconds (up to 100 elements)
- ✅ Reference lookup: < 10ms (in-memory)

### Phase 4 (Optimized)
- ✅ `query_object`: < 1 second (90th percentile)
- ✅ `get_properties`: < 500ms (with batching)
- ✅ `get_elements`: < 2 seconds (up to 100 elements)
- ✅ Cleanup: < 100ms (non-blocking)
- ✅ Memory: < 50MB for 10,000 references

---

## Security & Permissions

### Phase 1: Query Operations
**Risk Level:** Low-Medium (read-only data exposure)

**Permission Strategy:**
- Query operations inherit app-level permissions
- User must have already granted iac-mcp permission to control the app
- No additional prompts for read-only queries (trust OSA sandbox)

**Future Consideration (Phase 4):**
- Option to prompt for "sensitive" data (e.g., email content, contacts)
- Configurable privacy levels

### Phase 3: Property Setters
**Risk Level:** Medium-High (data modification)

**Permission Strategy:**
- Always prompt for write operations (unless "always allow" granted)
- Show property name, old value, new value in prompt
- Group consecutive writes (e.g., "Mark 5 emails as read") with single prompt

---

## Migration & Compatibility

### Backwards Compatibility
- Existing command tools (delete, send, etc.) continue to work unchanged
- New query tools are additive (no breaking changes)
- Object model resources remain available (for LLM to understand structure)

### Deprecations
None. This is purely additive functionality.

---

## Documentation Requirements

### Developer Docs
- ✅ Object specifier JSON schema reference
- ✅ Tool usage examples (query_object, get_properties, get_elements)
- ✅ JXA generation internals (for contributors)
- ✅ Reference lifecycle diagram
- ✅ Testing guide (how to test with real apps)

### User Docs
- ✅ Overview of query capabilities (what's now possible)
- ✅ Common patterns (e.g., "reading email", "listing files")
- ✅ Troubleshooting (e.g., "reference no longer valid")

### CLAUDE.md Updates
- ✅ Add query tools to "What We're Building" section
- ✅ Document agent best practices for using references
- ✅ Add testing patterns for query operations

---

## Success Metrics

### Phase 1 Launch Criteria
- ✅ All Phase 1 tests pass (100% coverage)
- ✅ Claude successfully completes "most recent email" query
- ✅ References work for at least 15 minutes
- ✅ Integration tests pass for Mail, Finder, Calendar
- ✅ No memory leaks or performance regressions
- ✅ Documentation complete

### Phase 4 Launch Criteria
- ✅ All phases implemented and tested
- ✅ Performance benchmarks met
- ✅ LRU + validation GC working
- ✅ No known critical bugs
- ✅ Claude can complete complex multi-step workflows (e.g., "Organize my inbox")

---

## Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **References become invalid** (app quits, object deleted) | High | Medium | Clear error messages, LLM re-queries automatically |
| **Memory leak** (references never cleaned up) | High | Low | TTL cleanup (Phase 1), LRU + validation (Phase 4) |
| **Performance degradation** (many refs) | Medium | Medium | Benchmarking, limits per app (Phase 4) |
| **JXA generation bugs** (invalid code) | High | Low | Comprehensive unit tests, integration tests with real apps |
| **Type conversion errors** (dates, enums) | Medium | Medium | Explicit type mapping, test with diverse properties |
| **Permission issues** (OSA denies access) | Medium | Low | Inherit existing permission system, clear error messages |

---

## Dependencies

### External
- ✅ macOS 10.15+ (JXA support)
- ✅ Node.js 18+ (existing requirement)
- ✅ osascript (system binary)

### Internal
- ✅ Existing MCP server implementation
- ✅ Existing JXA executor (`src/execution/jxa-executor.ts`)
- ✅ Existing sdef parser (for object model metadata)
- ✅ Existing tool generator framework

### Blocking
- None. This work is independent and additive.

### Blocked By This
- Advanced workflow automation (needs query tools)
- Multi-step AI actions (needs stable references)

---

## Open Questions

1. **Should references be persisted to disk?** (Survive iac-mcp restarts)
   - Phase 1: No (in-memory only)
   - Phase 4: Consider for long-running sessions

2. **Should we support reference sharing across MCP clients?**
   - Phase 1: No (single client assumed)
   - Future: Consider if multiple clients connect

3. **How to handle app-specific object ID formats?**
   - Phase 1: Treat as opaque strings
   - Phase 2+: Parse if needed for filtering

4. **Should we cache property values?**
   - Phase 1: No (always fetch fresh)
   - Phase 4: Consider for performance

---

## Next Steps

1. **Review this plan** with user (ensure alignment)
2. **Create detailed Phase 1 implementation plan** (ready for /doit)
3. **Set up feature branch/worktree** (`iac-mcp-stateful-queries`)
4. **Begin Phase 1 implementation** using /doit workflow
5. **Iterate based on testing and feedback**

---

## References

- [Claude's analysis and recommendations](../conversations/stateful-query-discussion.md) (if saved)
- [Code Quality Standards](../../CODE-QUALITY.md)
- [Testing Requirements](../../CODE-QUALITY.md#testing-standards)
- [Worktree Workflow](../../CLAUDE.md#worktree-workflow)
- [/doit Workflow](~/.claude/CLAUDE.md#doit-workflow)

---

**Document Version:** 1.0
**Last Updated:** 2026-01-27
**Status:** Ready for Review → Implementation
