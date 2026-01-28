# Object Model Exposure - Technical Design

**Status:** Design Phase
**Version:** 1.0
**Last Updated:** 2026-01-26

---

## Architecture Overview

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ MCP Client (Claude Desktop)                                    │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     │ ListTools / CallTool
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ MCP Server (iac-mcp)                                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Tool Registry                                            │   │
│  │  - Command tools (existing: calendar_create_event)       │   │
│  │  - Query tools (NEW: query_app_objects)                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ JITD Engine                                              │   │
│  │  ┌────────────────┐  ┌────────────────┐                  │   │
│  │  │ Command Parser │  │ Class Parser   │ ← NEW            │   │
│  │  │ (existing)     │  │ (new)          │                  │   │
│  │  └────────┬───────┘  └───────┬────────┘                  │   │
│  │           │                  │                           │   │
│  │           ▼                  ▼                           │   │
│  │  ┌────────────────┐  ┌────────────────┐                  │   │
│  │  │ Tool Generator │  │ Type Generator │ ← NEW            │   │
│  │  └────────────────┘  └────────────────┘                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Type Schema Cache                                        │   │
│  │  {                                                       │   │
│  │    "Calendar": { classes: [...], enums: [...] },        │   │
│  │    "Finder": { classes: [...], enums: [...] }           │   │
│  │  }                                                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Query Executor                                           │   │
│  │  - JXA script generation                                 │   │
│  │  - Filter validation (Phase 3)                           │   │
│  │  - Result formatting                                     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      │ osascript -l JavaScript
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ macOS Application (Calendar.app, Finder.app, etc.)             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Design

### 1. Class Parser (NEW)

**Location:** `src/jitd/class-parser/`

**Responsibilities:**
- Parse `<class>`, `<property>`, `<element>`, `<enumeration>` from SDEF XML
- Resolve inheritance chains
- Normalize property types
- Filter hidden/deprecated elements

**Input:** SDEF XML string

**Output:** Structured class definitions

```typescript
interface ParsedClass {
  name: string;
  code: string;  // 4-character AppleEvent code
  inherits?: string;  // Parent class name
  description?: string;
  properties: ParsedProperty[];
  elements: ParsedElement[];
  hidden?: boolean;
}

interface ParsedProperty {
  name: string;
  code: string;
  type: string | string[];  // Union types = array
  list?: boolean;
  access?: 'r' | 'w' | 'rw';
  description?: string;
  hidden?: boolean;
}

interface ParsedElement {
  type: string;  // Class name
  cocoaKey?: string;  // Runtime property name
}

interface ParsedEnumeration {
  name: string;
  code: string;
  enumerators: {
    name: string;
    code: string;
    description?: string;
  }[];
}
```

**Key functions:**

```typescript
// src/jitd/class-parser/index.ts
export function parseSDEFClasses(sdefXML: string): {
  classes: ParsedClass[];
  enumerations: ParsedEnumeration[];
  classExtensions: ClassExtension[];
} {
  // Parse XML
  // Extract classes, enums, extensions
  // Filter hidden elements
  // Return structured data
}

export function resolveInheritanceChain(
  className: string,
  allClasses: ParsedClass[]
): ParsedClass[] {
  // Walk inheritance tree
  // Return [MostSpecific, ..., MostGeneral]
}

export function mergeClassExtensions(
  baseClass: ParsedClass,
  extensions: ClassExtension[]
): ParsedClass {
  // Merge <class-extension> into base class
}
```

---

### 2. Type Generator (NEW)

**Location:** `src/jitd/type-generator/`

**Responsibilities:**
- Convert ParsedClass → TypeScript interface/enum
- Handle inheritance via `extends`
- Map SDEF types to TypeScript types
- Generate JSDoc comments from descriptions

**Input:** ParsedClass[], ParsedEnumeration[]

**Output:** TypeScript code (string)

**Type Mapping:**

```typescript
// src/jitd/type-generator/type-mapper.ts
export const SDEF_TO_TS_TYPE_MAP: Record<string, string> = {
  'text': 'string',
  'integer': 'number',
  'real': 'number',
  'double integer': 'number',
  'boolean': 'boolean',
  'date': 'Date',
  'file': 'string',  // POSIX path
  'alias': 'string',
  'specifier': 'any',  // Dynamic reference
  'reference': 'any',
  'RGB color': '[number, number, number]',
  'bounding rectangle': '[number, number, number, number]',
  'missing value': 'null',
};

export function mapSDEFTypeToTypeScript(
  sdefType: string | string[],
  list: boolean = false
): string {
  if (Array.isArray(sdefType)) {
    // Union type
    const mapped = sdefType.map(t => SDEF_TO_TS_TYPE_MAP[t] || t);
    const unionType = mapped.join(' | ');
    return list ? `Array<${unionType}>` : unionType;
  }

  const baseType = SDEF_TO_TS_TYPE_MAP[sdefType] || sdefType;
  return list ? `${baseType}[]` : baseType;
}
```

**Key functions:**

```typescript
// src/jitd/type-generator/index.ts
export function generateTypeScriptTypes(
  classes: ParsedClass[],
  enumerations: ParsedEnumeration[]
): string {
  // Generate enums first (classes may reference them)
  const enumCode = enumerations.map(generateEnum).join('\n\n');

  // Generate interfaces (handle inheritance order)
  const interfaceCode = classes.map(generateInterface).join('\n\n');

  return `${enumCode}\n\n${interfaceCode}`;
}

function generateEnum(enumDef: ParsedEnumeration): string {
  // Generate TypeScript enum with JSDoc
}

function generateInterface(classDef: ParsedClass): string {
  // Generate TypeScript interface
  // Handle inheritance via extends
  // Add JSDoc comments
  // Mark readonly for access="r"
}
```

**Example output:**

```typescript
/**
 * The event status.
 */
enum EventStatus {
  /** Event is cancelled */
  Cancelled = "E4ca",
  /** Event is confirmed */
  Confirmed = "E4cn",
  /** No status */
  None = "E4no",
  /** Event is tentative */
  Tentative = "E4te"
}

/**
 * This class represents an attendee.
 */
interface Attendee {
  /** The first and last name of the attendee. */
  readonly displayName?: string;

  /** Email of the attendee. */
  readonly email?: string;

  /** The invitation status for the attendee. */
  readonly participationStatus?: ParticipationStatus;
}
```

---

### 3. Query Tool Generator (NEW)

**Location:** `src/jitd/query-tool-generator/`

**Responsibilities:**
- Generate MCP tool schema for `query_app_objects`
- Include class names and property names in schema
- Validate tool parameters

**Implementation:** Generic query tools (JITD-compliant)

Rather than app-specific tools like `query_calendar_events` (which violate JITD policy),
we implement generic query tools that work with any scriptable application:

- `iac_mcp_query_object` - Query any object by specifier
- `iac_mcp_get_properties` - Get properties of a referenced object
- `iac_mcp_get_elements` - Get child elements from a container

See `src/jitd/tool-generator/query-tools.ts` for the actual implementation.

**Future Enhancement:** JXA filter expressions

```typescript
{
  name: "query_app_objects",
  description: "Query any app's object model using JXA filters",
  inputSchema: {
    type: "object",
    properties: {
      app: {
        type: "string",
        description: "App bundle ID (e.g., 'com.apple.iCal')"
      },
      objectType: {
        type: "string",
        description: "Class name (e.g., 'event', 'calendar')"
        // Dynamically populated from parsed classes
      },
      filter: {
        type: "string",
        description: "JXA filter expression (e.g., 'e => e.startDate > new Date()')"
      },
      properties: {
        type: "array",
        items: { type: "string" },
        description: "Properties to return (optional)"
      }
    },
    required: ["app", "objectType"]
  }
}
```

---

### 4. Query Executor (NEW)

**Location:** `src/jitd/query-executor/`

**Responsibilities:**
- Convert query parameters → JXA script
- Execute via `osascript -l JavaScript`
- Parse and format results
- Handle errors gracefully

**Phase 1 (Predefined queries):**

```typescript
// src/jitd/query-executor/index.ts
export async function executeQuery(params: {
  app: string;
  timeRange: "today" | "this_week" | "this_month" | "all";
  calendarName?: string;
}): Promise<any[]> {
  const jxaScript = generateJXAScript(params);
  const result = await executeJXA(jxaScript);
  return JSON.parse(result);
}

function generateJXAScript(params: {
  app: string;
  timeRange: string;
  calendarName?: string;
}): string {
  // Phase 1: Template-based generation
  const now = new Date();
  const filterDate = getFilterDate(params.timeRange, now);

  return `
    const app = Application("${params.app}");
    const events = app.calendars${params.calendarName ? `["${params.calendarName}"]` : ''}.events();
    const filtered = events.filter(e => {
      const startDate = e.startDate();
      return startDate >= new Date("${filterDate.toISOString()}");
    });
    JSON.stringify(filtered.map(e => ({
      summary: e.summary(),
      startDate: e.startDate().toISOString(),
      endDate: e.endDate().toISOString()
    })));
  `;
}
```

**Phase 2+ (JXA filter expressions):**

```typescript
export async function executeQueryWithFilter(params: {
  app: string;
  objectType: string;
  filter?: string;
  properties?: string[];
}): Promise<any[]> {
  // Validate filter expression (security!)
  validateFilter(params.filter);

  const jxaScript = generateJXAScriptWithFilter(params);
  const result = await executeJXA(jxaScript);
  return JSON.parse(result);
}

function validateFilter(filter?: string): void {
  if (!filter) return;

  // Phase 3: AST-based validation
  // Block: require(), eval(), Function constructor, etc.
  // Allow: property access, comparisons, basic operators

  const FORBIDDEN_PATTERNS = [
    /require\s*\(/,
    /eval\s*\(/,
    /Function\s*\(/,
    /child_process/,
    /fs\./,
    /process\./,
  ];

  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(filter)) {
      throw new Error(`Unsafe filter expression: ${filter}`);
    }
  }
}
```

---

### 5. Type Schema Cache (NEW)

**Location:** `src/jitd/cache/type-schema-cache.ts`

**Responsibilities:**
- Cache parsed class definitions per app
- Invalidate on SDEF changes (check mtime)
- Lazy load (only parse when queried)

```typescript
interface TypeSchemaCache {
  [bundleId: string]: {
    classes: ParsedClass[];
    enumerations: ParsedEnumeration[];
    typescriptCode: string;
    lastParsed: Date;
  };
}

export class TypeSchemaCacheManager {
  private cache: TypeSchemaCache = {};

  async getOrParse(bundleId: string, sdefPath: string): Promise<{
    classes: ParsedClass[];
    enumerations: ParsedEnumeration[];
    typescriptCode: string;
  }> {
    // Check cache
    const cached = this.cache[bundleId];
    if (cached && !this.isStale(sdefPath, cached.lastParsed)) {
      return cached;
    }

    // Parse SDEF
    const sdefXML = await fs.readFile(sdefPath, 'utf-8');
    const parsed = parseSDEFClasses(sdefXML);
    const typescriptCode = generateTypeScriptTypes(
      parsed.classes,
      parsed.enumerations
    );

    // Cache result
    this.cache[bundleId] = {
      ...parsed,
      typescriptCode,
      lastParsed: new Date(),
    };

    return this.cache[bundleId];
  }

  private isStale(sdefPath: string, lastParsed: Date): boolean {
    const stat = fs.statSync(sdefPath);
    return stat.mtime > lastParsed;
  }
}
```

---

## Progressive Discovery Strategy

### Hybrid Approach (Recommended)

**On ListTools request:**

```typescript
// src/mcp/server.ts
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools: Tool[] = [];

  // Existing: Command tools
  const commandTools = await generateCommandTools();
  tools.push(...commandTools);

  // NEW: Generic query tool
  tools.push({
    name: "query_app_objects",
    description: "Query any app's object model. First call will discover the schema dynamically.",
    inputSchema: {
      type: "object",
      properties: {
        app: {
          type: "string",
          description: "App bundle ID (e.g., 'com.apple.iCal')"
        },
        objectType: {
          type: "string",
          description: "Class name (will be validated on first call)"
        },
        timeRange: {
          type: "string",
          enum: ["today", "this_week", "this_month", "all"],
          description: "Time range filter (for date-based objects)"
        }
      },
      required: ["app", "objectType"]
    }
  });

  return { tools };
});
```

**On first CallTool(query_app_objects) for an app:**

```typescript
// src/mcp/handlers.ts
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === "query_app_objects") {
    const { app, objectType, timeRange } = request.params.arguments;

    // Lazy load type schema
    const typeSchema = await typeSchemaCacheManager.getOrParse(
      app,
      await findSDEFPath(app)
    );

    // Validate objectType exists
    const classExists = typeSchema.classes.find(c => c.name === objectType);
    if (!classExists) {
      throw new Error(`Class "${objectType}" not found in ${app}`);
    }

    // Execute query
    const results = await executeQuery({ app, objectType, timeRange });

    // Return results + discovered schema summary
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          results,
          schemaDiscovered: {
            classes: typeSchema.classes.map(c => c.name),
            message: `Discovered ${typeSchema.classes.length} classes for ${app}`
          }
        }, null, 2)
      }]
    };
  }

  // Existing command tool handling...
});
```

**Benefits:**
- ✅ LLM knows querying is possible (sees `query_app_objects` tool upfront)
- ✅ Only parses classes when needed (lazy loading)
- ✅ Caches parsed schemas (subsequent queries are fast)
- ✅ Preserves progressive discovery philosophy

---

## MCP Resource Exposure (Optional Phase 2+)

**Expose app dictionaries as MCP resources:**

```typescript
// src/mcp/resources.ts
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  const resources: Resource[] = [];

  // For each discovered app with SDEF
  for (const app of discoveredApps) {
    resources.push({
      uri: `iac://${app.bundleId}/dictionary`,
      name: `${app.name} - Scripting Dictionary`,
      mimeType: "application/json",
      description: "Object model classes and properties"
    });
  }

  return { resources };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;
  const match = uri.match(/^iac:\/\/([^/]+)\/dictionary$/);
  if (!match) {
    throw new Error("Invalid resource URI");
  }

  const bundleId = match[1];
  const typeSchema = await typeSchemaCacheManager.getOrParse(
    bundleId,
    await findSDEFPath(bundleId)
  );

  return {
    contents: [{
      uri,
      mimeType: "application/json",
      text: JSON.stringify({
        classes: typeSchema.classes,
        enumerations: typeSchema.enumerations,
        typescriptCode: typeSchema.typescriptCode
      }, null, 2)
    }]
  };
});
```

---

## File Structure (Proposed)

```
src/
  jitd/
    discovery/              # Existing: Find apps, SDEF files

    class-parser/           # NEW
      index.ts              # Main parser entry point
      xml-parser.ts         # XML parsing utilities
      inheritance-resolver.ts  # Resolve inheritance chains
      class-extension-merger.ts  # Merge <class-extension>
      types.ts              # ParsedClass, ParsedProperty, etc.

    type-generator/         # NEW
      index.ts              # Main generator entry point
      type-mapper.ts        # SDEF type → TypeScript type
      enum-generator.ts     # Generate enums
      interface-generator.ts  # Generate interfaces

    query-tool-generator/   # NEW
      index.ts              # Generate query tool schemas
      predefined-queries.ts  # Phase 1: Safe, predefined queries
      filter-validator.ts    # Phase 2+: Validate JXA expressions

    query-executor/         # NEW
      index.ts              # Execute JXA queries
      jxa-script-generator.ts  # Generate JXA scripts
      result-formatter.ts    # Format query results

    cache/
      sdef-cache.ts         # Existing: Cache SDEF files
      type-schema-cache.ts  # NEW: Cache parsed class schemas

    tool-generator/         # Existing: Command tools

  mcp/
    server.ts               # Existing: MCP server
    handlers.ts             # Existing: Tool handlers
    resources.ts            # NEW: Resource handlers (optional)

  types/
    sdef.ts                 # Existing: SDEF types
    class-schema.ts         # NEW: ParsedClass, etc.

tests/
  unit/
    class-parser.test.ts    # NEW: 100% coverage required
    type-generator.test.ts  # NEW: 100% coverage required
    query-executor.test.ts  # NEW: 100% coverage required

  integration/
    calendar-query.test.ts  # NEW: End-to-end Calendar query
    finder-query.test.ts    # NEW: End-to-end Finder query
    mail-query.test.ts      # NEW: End-to-end Mail query
```

---

## Testing Strategy

**See [CODE-QUALITY.md](../../../CODE-QUALITY.md) for 100% coverage requirements.**

### Unit Tests (100% coverage)

```typescript
// tests/unit/class-parser.test.ts
describe('parseSDEFClasses', () => {
  it('should parse simple class with properties', () => {
    const sdefXML = `
      <class name="event" code="wrev">
        <property name="summary" code="summ" type="text"/>
        <property name="start date" code="sdst" type="date"/>
      </class>
    `;
    const result = parseSDEFClasses(sdefXML);
    expect(result.classes).toHaveLength(1);
    expect(result.classes[0].name).toBe('event');
    expect(result.classes[0].properties).toHaveLength(2);
  });

  it('should handle inheritance', () => {
    const sdefXML = `
      <class name="account" code="mact">
        <property name="name" code="pnam" type="text"/>
      </class>
      <class name="imap account" code="iact" inherits="account">
        <property name="port" code="port" type="integer"/>
      </class>
    `;
    const result = parseSDEFClasses(sdefXML);
    const inheritanceChain = resolveInheritanceChain('imap account', result.classes);
    expect(inheritanceChain).toHaveLength(2);
    expect(inheritanceChain[0].name).toBe('imap account');
    expect(inheritanceChain[1].name).toBe('account');
  });

  it('should handle union types', () => {
    const sdefXML = `
      <class name="message">
        <property name="signature" code="sig">
          <type type="signature"/>
          <type type="missing value"/>
        </property>
      </class>
    `;
    const result = parseSDEFClasses(sdefXML);
    const prop = result.classes[0].properties[0];
    expect(prop.type).toEqual(['signature', 'missing value']);
  });

  it('should skip hidden classes', () => {
    const sdefXML = `
      <class name="visible" code="vis"/>
      <class name="hidden" code="hid" hidden="yes"/>
    `;
    const result = parseSDEFClasses(sdefXML);
    expect(result.classes).toHaveLength(1);
    expect(result.classes[0].name).toBe('visible');
  });
});
```

### Integration Tests (End-to-End)

```typescript
// tests/integration/calendar-query.test.ts
describe('Calendar query integration', () => {
  it('should query events for today', async () => {
    const result = await executeQuery({
      app: 'com.apple.iCal',
      objectType: 'event',
      timeRange: 'today'
    });

    expect(Array.isArray(result)).toBe(true);
    result.forEach(event => {
      expect(event).toHaveProperty('summary');
      expect(event).toHaveProperty('startDate');
      expect(event).toHaveProperty('endDate');
    });
  });

  it('should filter by calendar name', async () => {
    const result = await executeQuery({
      app: 'com.apple.iCal',
      objectType: 'event',
      timeRange: 'this_week',
      calendarName: 'Work'
    });

    // Verify all events are from "Work" calendar
    result.forEach(event => {
      expect(event.calendar?.name).toBe('Work');
    });
  });
});
```

---

## Security Considerations (Phase 3)

### JXA Filter Validation

**Threat model:**
- LLM generates malicious filter expression
- Filter contains code injection attempts
- Arbitrary code execution via `require()`, `eval()`, etc.

**Mitigation layers:**

1. **Static analysis (AST parsing):**

```typescript
// src/jitd/query-executor/filter-validator.ts
import * as acorn from 'acorn';

export function validateFilter(filter: string): void {
  // Parse JavaScript AST
  const ast = acorn.parse(filter, { ecmaVersion: 2020 });

  // Walk AST and block dangerous patterns
  walk(ast, {
    CallExpression(node) {
      const callee = node.callee;
      if (callee.type === 'Identifier') {
        const FORBIDDEN = ['require', 'eval', 'Function'];
        if (FORBIDDEN.includes(callee.name)) {
          throw new Error(`Forbidden function: ${callee.name}`);
        }
      }
    },
    MemberExpression(node) {
      // Block fs.*, child_process.*, etc.
      if (node.object.type === 'Identifier') {
        const FORBIDDEN_OBJECTS = ['process', 'fs', 'child_process'];
        if (FORBIDDEN_OBJECTS.includes(node.object.name)) {
          throw new Error(`Forbidden object: ${node.object.name}`);
        }
      }
    }
  });
}
```

2. **Sandboxed execution (osascript is already isolated):**

```bash
# osascript runs in separate process with limited permissions
osascript -l JavaScript -e "<script>"
```

3. **User confirmation (permission system):**

```typescript
// Ask user before executing query with custom filter
if (params.filter && !isPreapproved(params.filter)) {
  await requestPermission({
    app: params.app,
    action: 'query',
    filter: params.filter,
    message: `Allow query with filter: ${params.filter}?`
  });
}
```

---

## Performance Optimization

### Pagination (Phase 2+)

```typescript
interface QueryParams {
  app: string;
  objectType: string;
  filter?: string;
  limit?: number;        // Default: 100
  offset?: number;       // Default: 0
}

function generateJXAScriptWithPagination(params: QueryParams): string {
  const limit = params.limit || 100;
  const offset = params.offset || 0;

  return `
    const app = Application("${params.app}");
    const objects = app.${params.objectType}s();
    const filtered = ${params.filter ? `objects.filter(${params.filter})` : 'objects'};
    const paginated = filtered.slice(${offset}, ${offset + limit});
    JSON.stringify(paginated.map(obj => ({ /* properties */ })));
  `;
}
```

### Result Size Limits

```typescript
const MAX_RESULT_SIZE = 1_000_000;  // 1MB

async function executeQuery(params: QueryParams): Promise<any[]> {
  const result = await executeJXA(script);

  if (result.length > MAX_RESULT_SIZE) {
    throw new Error(
      `Result too large (${result.length} bytes). Use pagination (limit/offset).`
    );
  }

  return JSON.parse(result);
}
```

---

## Error Handling

### Graceful Degradation

```typescript
async function getTypeSchema(bundleId: string): Promise<TypeSchema | null> {
  try {
    const sdefPath = await findSDEFPath(bundleId);
    if (!sdefPath) {
      console.warn(`No SDEF file found for ${bundleId}`);
      return null;
    }

    const schema = await typeSchemaCacheManager.getOrParse(bundleId, sdefPath);
    return schema;
  } catch (error) {
    console.error(`Failed to parse SDEF for ${bundleId}:`, error);
    return null;  // Fall back to command-only mode
  }
}
```

### User-Friendly Error Messages

```typescript
try {
  const result = await executeQuery(params);
  return { content: [{ type: "text", text: JSON.stringify(result) }] };
} catch (error) {
  if (error.message.includes('not found')) {
    return {
      content: [{
        type: "text",
        text: `Error: Class "${params.objectType}" not found in ${params.app}. Available classes: ${availableClasses.join(', ')}`
      }],
      isError: true
    };
  }
  throw error;
}
```

---

## Open Questions & Decisions Needed

| Question | Options | Recommendation | Status |
|----------|---------|----------------|--------|
| **Phase 1 query scope** | Predefined only vs limited JXA | Predefined only | ✅ Decided |
| **Type output location** | File vs in-memory | File (Phase 1), in-memory (Phase 2+) | 🔄 TBD |
| **Resource exposure** | Expose dictionaries as resources? | Optional (Phase 2+) | 🔄 TBD |
| **Element relationships** | Model as properties vs query tools | Query tools (keep types simple) | ✅ Decided |
| **Specifier type handling** | `any` vs custom `Specifier<T>` | `any` with JSDoc (Phase 1) | ✅ Decided |

---

## Next Steps

1. ✅ Design complete
2. 📝 Get user approval on approach
3. 📝 Create Phase 1 implementation plan (Calendar POC)
4. 📝 Start implementation with /doit workflow

---

## Related Documents

- **[README.md](README.md)** - Problem statement and solution overview
- **[01-research-findings.md](01-research-findings.md)** - SDEF analysis and feasibility
- **[CODE-QUALITY.md](../../../CODE-QUALITY.md)** - 100% test coverage requirements
