# Phase 1: Core Stateful Queries (MVP) - Implementation Plan

**Parent Plan:** [Stateful Query System](./stateful-query-system.md)
**Status:** Ready for /doit
**Priority:** Critical
**Estimated Effort:** 3-4 days
**Owner:** TBD
**Created:** 2026-01-27

---

## Goal

Enable basic object querying and property reading with stateful references. This unblocks Claude from performing read-only queries like "What's my most recent email?"

---

## Success Criteria

- ✅ Claude can query "most recent email" and read its properties
- ✅ References persist for 15+ minutes without expiring
- ✅ References work across multiple tool calls
- ✅ Error handling for invalid references is clear and actionable
- ✅ 100% test coverage (unit + integration)
- ✅ Integration tests pass for Mail.app, Finder.app, Calendar.app
- ✅ Performance meets requirements (see below)

---

## Deliverables

### 1. Type Definitions

**Files:**
- `src/types/object-specifier.ts` (NEW)
- `src/types/object-reference.ts` (NEW)

**Contents:**
- `ObjectSpecifier` union type (Element, Named, Id, Property)
- `ObjectReference` interface
- `SpecifierContainer` type
- Helper type guards (e.g., `isElementSpecifier()`)

### 2. Reference Store

**File:** `src/execution/reference-store.ts` (NEW)

**Class:** `ReferenceStore`

**Methods:**
- `create(app: string, type: string, specifier: ObjectSpecifier): string`
- `get(id: string): ObjectReference | undefined`
- `touch(id: string): void`
- `cleanup(): void` (TTL-based)
- `getStats(): ReferenceStats` (for monitoring)

**Configuration:**
- Default TTL: 15 minutes (900,000ms)
- Cleanup interval: 5 minutes
- Configurable via environment variables

### 3. Query Executor

**File:** `src/execution/query-executor.ts` (NEW)

**Class:** `QueryExecutor`

**Methods:**
- `queryObject(app: string, specifier: ObjectSpecifier): Promise<ObjectReference>`
- `getProperties(referenceId: string, properties?: string[]): Promise<Record<string, any>>`
- `getElements(container: string | ObjectSpecifier, elementType: string, limit?: number): Promise<ObjectReference[]>`
- `buildJXA(specifier: ObjectSpecifier, action: "resolve" | "getProperties" | "getElements"): string` (private)
- `resolveReference(referenceId: string): ObjectSpecifier` (private)

**Dependencies:**
- `ReferenceStore` (for storing/retrieving references)
- `JXAExecutor` (existing, for executing JXA code)
- `SDEFParser` (existing, for validating types/properties)

### 4. Query Tool Generator

**File:** `src/jitd/tool-generator/query-tools.ts` (NEW)

**Function:** `generateQueryTools(): Tool[]`

**Returns:** Array of 3 MCP tool definitions:
- `iac_mcp_query_object`
- `iac_mcp_get_properties`
- `iac_mcp_get_elements`

**Note:** These are **app-independent** tools (not generated per-app like command tools).

### 5. MCP Server Integration

**File:** `src/mcp/server.ts` (MODIFY)

**Changes:**
- Import and initialize `QueryExecutor`
- Add query tools to `ListToolsResponse`
- Route query tool calls in `CallToolRequestHandler`

**File:** `src/mcp/handlers.ts` (MODIFY)

**New Handlers:**
- `handleQueryObject(params): Promise<ToolResponse>`
- `handleGetProperties(params): Promise<ToolResponse>`
- `handleGetElements(params): Promise<ToolResponse>`

### 6. Tests

**Unit Tests:**
- `tests/unit/types/object-specifier.test.ts` (NEW)
- `tests/unit/types/object-reference.test.ts` (NEW)
- `tests/unit/execution/reference-store.test.ts` (NEW)
- `tests/unit/execution/query-executor.test.ts` (NEW)
- `tests/unit/jitd/tool-generator/query-tools.test.ts` (NEW)

**Integration Tests:**
- `tests/integration/query-mail.test.ts` (NEW)
- `tests/integration/query-finder.test.ts` (NEW)
- `tests/integration/query-calendar.test.ts` (NEW)
- `tests/integration/reference-lifecycle.test.ts` (NEW)

**End-to-End Test:**
- `tests/e2e/most-recent-email.test.ts` (NEW)

---

## Implementation Tasks

### Task 1: Define Type System (Day 1)

**File:** `src/types/object-specifier.ts`

**Types to Define:**
```typescript
// Base specifier types
export type ObjectSpecifier =
  | ElementSpecifier
  | NamedSpecifier
  | IdSpecifier
  | PropertySpecifier;

export type SpecifierContainer = ObjectSpecifier | "application";

export interface ElementSpecifier {
  type: "element";
  element: string;
  index: number;
  container: SpecifierContainer;
}

export interface NamedSpecifier {
  type: "named";
  element: string;
  name: string;
  container: SpecifierContainer;
}

export interface IdSpecifier {
  type: "id";
  element: string;
  id: string;
  container: SpecifierContainer;
}

export interface PropertySpecifier {
  type: "property";
  property: string;
  of: ObjectSpecifier | string;  // Specifier or reference ID
}

// Type guards
export function isElementSpecifier(spec: ObjectSpecifier): spec is ElementSpecifier;
export function isNamedSpecifier(spec: ObjectSpecifier): spec is NamedSpecifier;
export function isIdSpecifier(spec: ObjectSpecifier): spec is IdSpecifier;
export function isPropertySpecifier(spec: ObjectSpecifier): spec is PropertySpecifier;
export function isReferenceId(value: string): boolean;  // Starts with "ref_"
```

**File:** `src/types/object-reference.ts`

**Types to Define:**
```typescript
export interface ObjectReference {
  id: string;              // "ref_" + random string
  app: string;             // Bundle ID
  type: string;            // Object class from sdef
  specifier: ObjectSpecifier;  // How to resolve
  createdAt: number;       // Unix timestamp (ms)
  lastAccessedAt: number;  // For LRU (Phase 4)
  metadata?: Record<string, any>;  // Optional app-specific data
}

export interface ReferenceStats {
  totalReferences: number;
  referencesPerApp: Record<string, number>;
  oldestReference: number;  // Timestamp
  newestReference: number;  // Timestamp
}
```

**Tests:**
- Type guards work correctly
- Invalid specifiers rejected by type system
- Reference ID format validation

**Acceptance Criteria:**
- ✅ All types compile without errors
- ✅ Type guards implemented and tested
- ✅ 100% test coverage for type guards

---

### Task 2: Implement ReferenceStore (Day 1-2)

**File:** `src/execution/reference-store.ts`

**Implementation:**
```typescript
export class ReferenceStore {
  private references = new Map<string, ObjectReference>();
  private ttl: number;  // Default 15 minutes
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(ttl: number = 15 * 60 * 1000) {
    this.ttl = ttl;
    this.startCleanup();
  }

  /**
   * Create a new reference
   * @returns Unique reference ID
   */
  create(app: string, type: string, specifier: ObjectSpecifier): string {
    const id = this.generateId();
    const now = Date.now();
    const ref: ObjectReference = {
      id,
      app,
      type,
      specifier,
      createdAt: now,
      lastAccessedAt: now,
    };
    this.references.set(id, ref);
    return id;
  }

  /**
   * Get reference by ID
   */
  get(id: string): ObjectReference | undefined {
    return this.references.get(id);
  }

  /**
   * Update lastAccessedAt timestamp
   */
  touch(id: string): void {
    const ref = this.references.get(id);
    if (ref) {
      ref.lastAccessedAt = Date.now();
    }
  }

  /**
   * Remove expired references (TTL-based)
   */
  cleanup(): void {
    const now = Date.now();
    const expired: string[] = [];

    for (const [id, ref] of this.references) {
      if (now - ref.createdAt > this.ttl) {
        expired.push(id);
      }
    }

    for (const id of expired) {
      this.references.delete(id);
    }
  }

  /**
   * Get statistics about current references
   */
  getStats(): ReferenceStats {
    const referencesPerApp: Record<string, number> = {};
    let oldest = Date.now();
    let newest = 0;

    for (const ref of this.references.values()) {
      referencesPerApp[ref.app] = (referencesPerApp[ref.app] || 0) + 1;
      oldest = Math.min(oldest, ref.createdAt);
      newest = Math.max(newest, ref.createdAt);
    }

    return {
      totalReferences: this.references.size,
      referencesPerApp,
      oldestReference: oldest,
      newestReference: newest,
    };
  }

  /**
   * Start automatic cleanup timer
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);  // Every 5 minutes
  }

  /**
   * Stop automatic cleanup (for testing)
   */
  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Generate unique reference ID
   */
  private generateId(): string {
    return `ref_${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Clear all references (for testing)
   */
  clear(): void {
    this.references.clear();
  }
}
```

**Tests:** `tests/unit/execution/reference-store.test.ts`

**Test Cases:**
- ✅ `create()` generates unique IDs with "ref_" prefix
- ✅ `get()` retrieves by ID
- ✅ `get()` returns undefined for non-existent ID
- ✅ `touch()` updates lastAccessedAt
- ✅ `touch()` on non-existent ID doesn't throw
- ✅ `cleanup()` removes expired references (mock Date.now)
- ✅ `cleanup()` keeps non-expired references
- ✅ `getStats()` returns correct counts
- ✅ `getStats()` tracks per-app references
- ✅ Cleanup timer runs automatically (integration test)
- ✅ `stopCleanup()` stops timer
- ✅ `clear()` removes all references

**Acceptance Criteria:**
- ✅ 100% test coverage
- ✅ All tests pass
- ✅ No memory leaks (test with many references)

---

### Task 3: Implement Query Executor (Day 2-3)

**File:** `src/execution/query-executor.ts`

**Core Logic:**

```typescript
export class QueryExecutor {
  constructor(
    private referenceStore: ReferenceStore,
    private jxaExecutor: JXAExecutor,
    private sdefParser: SDEFParser  // For validation
  ) {}

  /**
   * Query an object and return a reference
   */
  async queryObject(
    app: string,
    specifier: ObjectSpecifier
  ): Promise<ObjectReference> {
    // 1. Build JXA code to resolve specifier
    const jxaCode = this.buildJXAResolve(app, specifier);

    // 2. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 3. Extract object type from result or specifier
    const objectType = this.extractObjectType(specifier);

    // 4. Create reference
    const refId = this.referenceStore.create(app, objectType, specifier);

    // 5. Return reference
    const ref = this.referenceStore.get(refId)!;
    return ref;
  }

  /**
   * Get properties of a referenced object
   */
  async getProperties(
    referenceId: string,
    properties?: string[]
  ): Promise<Record<string, any>> {
    // 1. Resolve reference
    const ref = this.referenceStore.get(referenceId);
    if (!ref) {
      throw new Error(`Reference not found: ${referenceId}`);
    }

    // 2. Touch reference (update lastAccessedAt)
    this.referenceStore.touch(referenceId);

    // 3. Build JXA code to get properties
    const jxaCode = this.buildJXAGetProperties(ref, properties);

    // 4. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 5. Parse and return properties
    return this.parseProperties(result, properties);
  }

  /**
   * Get elements from a container
   */
  async getElements(
    container: string | ObjectSpecifier,
    elementType: string,
    limit: number = 100
  ): Promise<{ elements: ObjectReference[]; count: number; hasMore: boolean }> {
    // 1. Resolve container (if reference ID)
    let containerSpec: ObjectSpecifier;
    if (typeof container === "string") {
      const ref = this.referenceStore.get(container);
      if (!ref) {
        throw new Error(`Reference not found: ${container}`);
      }
      containerSpec = ref.specifier;
      this.referenceStore.touch(container);
    } else {
      containerSpec = container;
    }

    // 2. Build JXA code to get elements
    const jxaCode = this.buildJXAGetElements(containerSpec, elementType, limit);

    // 3. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 4. Create references for each element
    const elements: ObjectReference[] = [];
    for (let i = 0; i < Math.min(result.elements.length, limit); i++) {
      const elementSpec: ElementSpecifier = {
        type: "element",
        element: elementType,
        index: i,
        container: containerSpec,
      };
      const app = typeof container === "string"
        ? this.referenceStore.get(container)!.app
        : /* extract from containerSpec */;
      const refId = this.referenceStore.create(app, elementType, elementSpec);
      elements.push(this.referenceStore.get(refId)!);
    }

    // 5. Return elements with metadata
    return {
      elements,
      count: elements.length,
      hasMore: result.totalCount > limit,
    };
  }

  /**
   * Build JXA code to resolve a specifier
   */
  private buildJXAResolve(app: string, specifier: ObjectSpecifier): string {
    const appVar = `Application("${this.getBundleId(app)}")`;
    const objectPath = this.buildObjectPath(specifier, appVar);

    return `
      const app = ${appVar};
      try {
        const obj = ${objectPath};
        return { success: true, exists: obj.exists() };
      } catch (error) {
        return { success: false, error: error.message };
      }
    `;
  }

  /**
   * Build JXA code to get properties
   */
  private buildJXAGetProperties(
    ref: ObjectReference,
    properties?: string[]
  ): string {
    const appVar = `Application("${ref.app}")`;
    const objectPath = this.buildObjectPath(ref.specifier, appVar);

    const propsToGet = properties || this.getAllProperties(ref.type);
    const propGetters = propsToGet.map(prop =>
      `"${prop}": obj.${this.camelCase(prop)}()`
    ).join(", ");

    return `
      const app = ${appVar};
      try {
        const obj = ${objectPath};
        return { success: true, properties: { ${propGetters} } };
      } catch (error) {
        return { success: false, error: error.message };
      }
    `;
  }

  /**
   * Build JXA code to get elements
   */
  private buildJXAGetElements(
    container: ObjectSpecifier,
    elementType: string,
    limit: number
  ): string {
    // Similar pattern to buildJXAGetProperties
    // Returns array of element metadata
  }

  /**
   * Build JXA object path from specifier
   */
  private buildObjectPath(specifier: ObjectSpecifier, appVar: string): string {
    if (specifier.type === "element") {
      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      return `${containerPath}.${this.pluralize(specifier.element)}[${specifier.index}]`;
    }

    if (specifier.type === "named") {
      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      return `${containerPath}.${this.pluralize(specifier.element)}.byName("${specifier.name}")`;
    }

    if (specifier.type === "id") {
      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      return `${containerPath}.${this.pluralize(specifier.element)}.byId("${specifier.id}")`;
    }

    if (specifier.type === "property") {
      const ofPath = typeof specifier.of === "string"
        ? this.resolveReference(specifier.of)
        : this.buildObjectPath(specifier.of, appVar);
      return `${ofPath}.${this.camelCase(specifier.property)}()`;
    }

    throw new Error(`Unsupported specifier type: ${(specifier as any).type}`);
  }

  /**
   * Resolve reference ID to object path
   */
  private resolveReference(referenceId: string): string {
    const ref = this.referenceStore.get(referenceId);
    if (!ref) {
      throw new Error(`Reference not found: ${referenceId}`);
    }
    return this.buildObjectPath(ref.specifier, `Application("${ref.app}")`);
  }

  // Helper methods
  private extractObjectType(specifier: ObjectSpecifier): string { /* ... */ }
  private getAllProperties(type: string): string[] { /* from sdef */ }
  private parseProperties(result: any, properties?: string[]): Record<string, any> { /* ... */ }
  private getBundleId(app: string): string { /* ... */ }
  private camelCase(str: string): string { /* ... */ }
  private pluralize(str: string): string { /* ... */ }
}
```

**Tests:** `tests/unit/execution/query-executor.test.ts`

**Test Cases:**
- ✅ `buildObjectPath()` generates correct JXA for ElementSpecifier
- ✅ `buildObjectPath()` generates correct JXA for NamedSpecifier
- ✅ `buildObjectPath()` generates correct JXA for IdSpecifier
- ✅ `buildObjectPath()` generates correct JXA for PropertySpecifier
- ✅ `buildObjectPath()` handles nested specifiers
- ✅ `queryObject()` creates reference and stores in ReferenceStore
- ✅ `queryObject()` throws on invalid specifier
- ✅ `getProperties()` resolves reference and fetches properties
- ✅ `getProperties()` throws on invalid reference ID
- ✅ `getProperties()` touches reference (updates lastAccessedAt)
- ✅ `getElements()` creates references for each element
- ✅ `getElements()` respects limit parameter
- ✅ `getElements()` handles hasMore correctly
- ✅ Type conversions work (dates, booleans, numbers)

**Acceptance Criteria:**
- ✅ 100% test coverage
- ✅ All tests pass
- ✅ JXA generation is correct (validated with integration tests)

---

### Task 4: Generate Query Tools (Day 3)

**File:** `src/jitd/tool-generator/query-tools.ts`

**Implementation:**
```typescript
import { Tool } from "@modelcontextprotocol/sdk/types.js";

export function generateQueryTools(): Tool[] {
  return [
    {
      name: "iac_mcp_query_object",
      description: "Query an object in an application and return a stable reference. The reference can be used in subsequent calls to get_properties, get_elements, or set_property. References remain valid for at least 15 minutes.",
      inputSchema: {
        type: "object",
        properties: {
          app: {
            type: "string",
            description: "App bundle ID (e.g., 'com.apple.mail')",
          },
          specifier: {
            type: "object",
            description: "JSON object specifier defining how to locate the object",
            // Note: Full JSON Schema for oneOf would be verbose,
            // LLM can construct from documentation
          },
        },
        required: ["app", "specifier"],
      },
    },
    {
      name: "iac_mcp_get_properties",
      description: "Get properties of a referenced object. If properties array is null or omitted, returns all available properties.",
      inputSchema: {
        type: "object",
        properties: {
          reference: {
            type: "string",
            description: "Object reference ID from query_object",
          },
          properties: {
            type: "array",
            items: { type: "string" },
            description: "Property names to retrieve (omit or null = all properties)",
          },
        },
        required: ["reference"],
      },
    },
    {
      name: "iac_mcp_get_elements",
      description: "Get elements from a container object. Returns references to the elements, which can be used in subsequent calls.",
      inputSchema: {
        type: "object",
        properties: {
          container: {
            oneOf: [
              { type: "string", description: "Reference ID of container" },
              { type: "object", description: "Object specifier for container" },
            ],
          },
          elementType: {
            type: "string",
            description: "Type of elements to retrieve (e.g., 'message', 'file')",
          },
          limit: {
            type: "number",
            description: "Maximum number of elements to return (default: 100)",
            default: 100,
          },
        },
        required: ["container", "elementType"],
      },
    },
  ];
}
```

**Tests:** `tests/unit/jitd/tool-generator/query-tools.test.ts`

**Test Cases:**
- ✅ `generateQueryTools()` returns 3 tools
- ✅ Each tool has correct name, description, inputSchema
- ✅ Required fields are marked correctly
- ✅ Tool schemas are valid MCP format

**Acceptance Criteria:**
- ✅ 100% test coverage
- ✅ All tests pass
- ✅ Tools are valid MCP format (validated with MCP SDK)

---

### Task 5: Integrate with MCP Server (Day 3-4)

**File:** `src/mcp/server.ts` (MODIFY)

**Changes:**
```typescript
import { QueryExecutor } from "../execution/query-executor.js";
import { ReferenceStore } from "../execution/reference-store.js";
import { generateQueryTools } from "../jitd/tool-generator/query-tools.js";

// In server initialization
const referenceStore = new ReferenceStore();
const queryExecutor = new QueryExecutor(
  referenceStore,
  jxaExecutor,
  sdefParser
);

// In ListToolsRequestHandler
const queryTools = generateQueryTools();
const commandTools = await generateCommandTools(/* ... */);
const allTools = [...queryTools, ...commandTools];

return { tools: allTools };

// In CallToolRequestHandler
if (request.params.name.startsWith("iac_mcp_query_") ||
    request.params.name.startsWith("iac_mcp_get_")) {
  return await handleQueryTool(request.params.name, request.params.arguments);
}
```

**File:** `src/mcp/handlers.ts` (MODIFY)

**New Functions:**
```typescript
export async function handleQueryObject(
  params: { app: string; specifier: ObjectSpecifier }
): Promise<ToolResponse> {
  try {
    const ref = await queryExecutor.queryObject(params.app, params.specifier);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          reference: {
            id: ref.id,
            type: ref.type,
            app: ref.app,
          },
        }),
      }],
    };
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: "query_failed",
          message: error.message,
        }),
      }],
      isError: true,
    };
  }
}

export async function handleGetProperties(
  params: { reference: string; properties?: string[] }
): Promise<ToolResponse> {
  try {
    const properties = await queryExecutor.getProperties(
      params.reference,
      params.properties
    );
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ properties }),
      }],
    };
  } catch (error) {
    if (error.message.includes("Reference not found")) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            error: "reference_invalid",
            reference: params.reference,
            message: "The referenced object no longer exists or cannot be accessed",
            suggestion: "Query the object again using query_object",
          }),
        }],
        isError: true,
      };
    }
    // ... other error handling
  }
}

export async function handleGetElements(
  params: { container: string | ObjectSpecifier; elementType: string; limit?: number }
): Promise<ToolResponse> {
  // Similar pattern to handleGetProperties
}
```

**Tests:**
- Covered by integration tests (see Task 6)

**Acceptance Criteria:**
- ✅ Query tools appear in ListTools response
- ✅ CallTool routes to correct handlers
- ✅ Error responses have correct format
- ✅ Success responses have correct format

---

### Task 6: Integration Testing (Day 4)

**File:** `tests/integration/query-mail.test.ts`

**Test Cases:**
- ✅ Query inbox mailbox (NamedSpecifier)
- ✅ Get first message from inbox (ElementSpecifier)
- ✅ Read message properties (subject, sender, date)
- ✅ Query multiple messages with limit
- ✅ Invalid reference returns error
- ✅ Reference persists across multiple calls

**File:** `tests/integration/query-finder.test.ts`

**Test Cases:**
- ✅ Query home folder
- ✅ Get files from folder
- ✅ Read file properties (name, size, modification date)
- ✅ Nested folder navigation

**File:** `tests/integration/query-calendar.test.ts`

**Test Cases:**
- ✅ Query calendars
- ✅ Get events from calendar
- ✅ Read event properties (summary, start date, location)

**File:** `tests/integration/reference-lifecycle.test.ts`

**Test Cases:**
- ✅ References remain valid for 15+ minutes
- ✅ References expire after TTL
- ✅ Cleanup removes expired references
- ✅ Touch extends reference lifetime (lastAccessedAt updated)

**File:** `tests/e2e/most-recent-email.test.ts`

**End-to-End Scenario:**
```typescript
describe("Most recent email scenario", () => {
  it("should query, retrieve, and read most recent email", async () => {
    // Step 1: Query inbox
    const inboxRef = await queryObject("com.apple.mail", {
      type: "named",
      element: "mailbox",
      name: "inbox",
      container: "application",
    });
    expect(inboxRef.id).toMatch(/^ref_/);

    // Step 2: Get first message
    const { elements } = await getElements(inboxRef.id, "message", 1);
    expect(elements).toHaveLength(1);
    const messageRef = elements[0];

    // Step 3: Read properties
    const props = await getProperties(messageRef.id, ["subject", "sender", "date received"]);
    expect(props.subject).toBeDefined();
    expect(props.sender).toBeDefined();
    expect(props["date received"]).toBeDefined();
  });
});
```

**Acceptance Criteria:**
- ✅ All integration tests pass
- ✅ E2E test passes with real Mail.app data
- ✅ Tests run without user intervention (no permission prompts)
- ✅ 100% coverage maintained

---

## Performance Requirements

- ✅ `query_object`: < 2 seconds (simple queries)
- ✅ `get_properties`: < 1 second
- ✅ `get_elements`: < 3 seconds (up to 100 elements)
- ✅ Reference lookup: < 10ms (in-memory)
- ✅ Cleanup: < 100ms (non-blocking)

**Benchmark Tests:**
- `tests/benchmark/query-performance.test.ts` (optional for Phase 1, required for Phase 4)

---

## Error Handling

### Reference Not Found
```json
{
  "error": "reference_invalid",
  "reference": "ref_abc123",
  "message": "The referenced object no longer exists or cannot be accessed",
  "suggestion": "Query the object again using query_object"
}
```

### Invalid Specifier
```json
{
  "error": "invalid_specifier",
  "message": "Unsupported specifier type: 'unknown'",
  "specifier": { ... }
}
```

### JXA Execution Error
```json
{
  "error": "execution_failed",
  "message": "AppleScript error: Can't get object.",
  "jxaCode": "..."  // Include for debugging (optional)
}
```

---

## Documentation Updates

### Files to Update:
- `CLAUDE.md`: Add section on query tools usage
- `README.md`: Update with query capabilities
- Create: `docs/query-tools-guide.md` (usage examples)

### Documentation Content:
- Overview of query tools
- JSON specifier examples
- Common patterns (email, files, calendar)
- Error handling guide
- Reference lifecycle explanation

---

## Testing Checklist

Before marking Phase 1 complete:

- ✅ All unit tests pass (100% coverage)
- ✅ All integration tests pass (Mail, Finder, Calendar)
- ✅ E2E test passes ("most recent email" scenario)
- ✅ No memory leaks (run cleanup test with 10,000 refs)
- ✅ Performance requirements met
- ✅ Error messages are clear and actionable
- ✅ Documentation updated
- ✅ Code review passed (DRY, no duplication)
- ✅ `npm run lint` passes
- ✅ CI passes

---

## Dependencies

**External:**
- macOS 10.15+ (JXA support)
- Node.js 18+
- osascript

**Internal:**
- `JXAExecutor` (existing)
- `SDEFParser` (existing)
- MCP server framework (existing)

**Blocking:**
None. This work is additive.

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| JXA code generation errors | Comprehensive unit tests for buildObjectPath() |
| Type conversion bugs | Test with diverse property types |
| Memory leaks | Benchmark test with many references |
| OSA permission issues | Integration tests validate permissions |

---

## Next Steps After Phase 1

1. **User Testing:** Test with real Claude Desktop sessions
2. **Gather Feedback:** What queries are difficult? What's missing?
3. **Plan Phase 2:** Filtering and advanced queries
4. **Performance Analysis:** Identify bottlenecks for Phase 4

---

## Questions for Implementation

1. **Should we validate specifiers against sdef before execution?**
   - Pro: Catch errors early
   - Con: Performance overhead
   - **Decision:** Validate in Phase 1, optimize in Phase 4

2. **Should we cache property values?**
   - Phase 1: No (always fetch fresh)
   - Phase 4: Consider for performance

3. **Should we support batch property reads?**
   - Phase 1: No (single object at a time)
   - Phase 4: Yes (performance optimization)

---

**Document Version:** 1.0
**Last Updated:** 2026-01-27
**Status:** Ready for /doit
