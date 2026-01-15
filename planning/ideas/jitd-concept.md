# Just-In-Time Discovery (JITD) Concept

## Core Idea

**JITD**: Dynamically discover application capabilities and generate MCP tools at runtime, similar to Just-In-Time Compilation.

```
Application installed → Discover capabilities → Generate MCP tools → LLM calls tools
```

## Mental Model

Not "LLM writes code to execute" but "LLM calls dynamically-discovered tools."

### Traditional Approach (Code Generation)
```
User: "List files on desktop"
→ LLM reads AppleScript documentation
→ LLM writes: 'tell application "Finder" to get name of every item of desktop'
→ Server executes string as code
→ Hope for no syntax errors
```

### JITD Approach (Tool Discovery)
```
User: "List files on desktop"
→ Server already discovered Finder has list_folder capability
→ Server generated tool: finder_list_folder(path: string)
→ LLM calls: finder_list_folder({ path: "~/Desktop" })
→ Server translates to AppleEvent/COM/D-Bus
→ Returns structured data
```

## The Flow

### Startup Sequence
1. **Discovery Phase**
   - Scan installed applications
   - Find scriptable apps (SDEF on macOS, TypeLib on Windows, D-Bus on Linux)
   - Parse capability definitions

2. **Tool Generation Phase**
   - Convert each capability to MCP tool
   - Generate JSON Schema for parameters
   - Create tool descriptions for LLM

3. **Registration Phase**
   - Register all tools with MCP server
   - Make available to LLM client

4. **Runtime Phase**
   - LLM sees available tools
   - Calls tools with typed parameters
   - Server validates and executes

### Example: Finder Discovery

```typescript
// 1. Discovery
Discovered: /Applications/Finder.app
  - Has SDEF at: Contents/Resources/Finder.sdef
  - Bundle ID: com.apple.finder

// 2. Parsing SDEF
Found capabilities:
  - Command: open (parameters: item, using?)
  - Command: move (parameters: item, to)
  - Query: items of folder (parameters: folder_path)

// 3. Tool Generation
Generated tools:
  - finder_open({ item: string, using?: string })
  - finder_move({ item: string, to: string })
  - finder_list_folder({ path: string })

// 4. MCP Registration
Registered 3 tools for Finder
Total tools available: 2,847
```

## Advantages Over Code Generation

### Type Safety
```typescript
// JITD: Parameters validated before execution
finder_open({ item: "/path/to/file" })
✓ Valid: string parameter matches schema

finder_open({ item: 123 })
✗ Error: Expected string, got number

// Code Generation: No validation until runtime
execute('tell app "Finder" to open 123')
✗ AppleScript error at runtime
```

### Better Error Messages
```typescript
// JITD
Error: Parameter 'item' is required but was not provided

// Code Generation
Error: Syntax error in AppleScript at line 1, column 37
```

### Platform Abstraction
```typescript
// Same logical operation across platforms
Tool: file_manager_list_folder(path: string)

// Platform adapter routes to:
// - macOS: Finder AppleEvents
// - Windows: Explorer COM
// - Linux: File manager D-Bus
```

### No Syntax Errors
```typescript
// JITD: Parameters → Validated → Compiled → Executed
// Never sees invalid syntax

// Code Generation: LLM must write perfect code
// Syntax errors, quoting issues, escaping problems common
```

### Composability
```typescript
// LLM can chain tool calls
results = finder_list_folder({ path: "~/Desktop" })
for file in results:
  finder_move({ item: file.path, to: "~/Archive" })

// With code generation, harder to compose programmatically
```

## Challenges

### Tool Explosion
- Finder: ~200 commands
- Safari: ~100 commands
- Mail: ~150 commands
- System-wide: 10,000+ potential tools

**Solutions:**
- Lazy registration (discover on-demand)
- Smart filtering (common tools first)
- Hierarchical tools (category-based)
- Search capabilities (find tools by description)

### Parameter Complexity
AppleScript types don't map 1:1 to JSON:
- `alias` → file path string
- `record` → JSON object
- Object specifiers → ???
- Enumerations → string unions

**Solution:** Type mapping layer in adapter

### Name Collisions
Multiple apps might have same command name:
- `open` exists in Finder, Safari, Mail, etc.

**Solution:** App-prefixed naming (`finder_open`, `safari_open`)

### Performance
Parsing hundreds of SDEF files on startup:

**Solutions:**
- Cache parsed capabilities
- Lazy parsing (on-demand)
- Background scanning
- Incremental updates

## Implementation Strategy

### Phase 1: Proof of Concept (macOS)
- Discover Finder only
- Generate ~50 tools
- Prove JITD concept works
- Validate with real LLM usage

### Phase 2: Full macOS Support
- Scan all applications
- Handle tool explosion
- Implement caching
- Performance optimization

### Phase 3: Cross-Platform
- Add Windows discovery (COM TypeLibs)
- Add Linux discovery (D-Bus introspection)
- Unified tool naming
- Platform adapters

### Phase 4: Advanced Features
- Tool search/discovery
- Natural language capability matching
- Usage analytics (which tools are actually used)
- Smart tool suggestions

## Success Metrics

- **Discovery speed**: < 5 seconds for full system scan
- **Tool generation**: < 1 second for average app
- **Execution latency**: < 100ms for simple commands
- **Cache hit rate**: > 90% (avoid re-parsing)
- **LLM success rate**: > 95% for valid tool calls

## Open Questions

1. Should tools be registered lazily or eagerly?
2. How many tools can MCP protocol handle efficiently?
3. What's the right granularity (fine-grained vs coarse-grained tools)?
4. Should we expose raw capabilities or normalized operations?
5. How do we handle apps that update and add new capabilities?
