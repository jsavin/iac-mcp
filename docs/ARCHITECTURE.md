# IAC-MCP Architecture

This document describes the system architecture, component design, data flow, and extensibility patterns for IAC-MCP.

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Component Interactions](#component-interactions)
5. [Extensibility](#extensibility)
6. [Performance Considerations](#performance-considerations)
7. [Security Architecture](#security-architecture)

## System Overview

IAC-MCP is a universal bridge between AI/LLMs and native applications using Just-In-Time Discovery (JITD). The architecture is designed for:

- **Dynamic Discovery**: Automatically discover installed applications without pre-built integrations
- **Zero Configuration**: Work with any scriptable application immediately
- **Cross-Platform**: Modular design supports multiple platforms (macOS, Windows, Linux)
- **Performance**: Sub-second warm startup, aggressive caching
- **Reliability**: 95%+ success rate with comprehensive error handling

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         MCP Client                          │
│                    (Claude Desktop, etc.)                   │
└───────────────────────────┬─────────────────────────────────┘
                            │ MCP Protocol (stdio)
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                      MCP Server Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Tool Handler │  │   Resource   │  │  Prompt      │     │
│  │              │  │   Handler    │  │  Handler     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                    JITD Engine (Core)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Discovery  │→│    Parser    │→│  Generator   │     │
│  │              │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Executor   │  │     Cache    │  │   Naming     │     │
│  │              │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                 Platform Adapter Layer                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │    macOS     │  │   Windows    │  │    Linux     │     │
│  │ (AppleScript)│  │   (VBA/COM)  │  │   (D-Bus)    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                   Native Applications                       │
│        (Finder, Safari, Mail, Excel, Word, etc.)            │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. MCP Server Layer (`src/index.ts`, `src/mcp/`)

**Responsibilities:**
- Implement MCP protocol (stdio transport)
- Handle tool listing and execution requests
- Manage server lifecycle and state
- Route requests to JITD engine

**Key Patterns:**
- Request/response handlers for MCP protocol
- Error handling and logging
- Graceful shutdown

**Files:**
- `src/index.ts` - Server entry point
- `src/mcp/handlers.ts` - MCP request handlers
- `src/mcp/server.ts` - Server initialization

### 2. JITD Engine

The core of dynamic discovery and tool generation.

#### 2.1 Discovery (`src/jitd/discovery/`)

**Responsibilities:**
- Find installed applications
- Locate scripting definition files (SDEF, AETE, etc.)
- Extract app metadata (name, bundle ID, version)

**Key Files:**
- `app-discovery.ts` - Main discovery orchestrator
- `sdef-discovery.ts` - Platform-specific SDEF locators
- `sdef-parser.ts` - SDEF XML parser

**Algorithms:**
- Parallel directory scanning for performance
- Symlink handling for app bundles
- Caching of discovered apps

#### 2.2 Tool Generation (`src/jitd/tool-generation/`)

**Responsibilities:**
- Convert SDEF commands to MCP tool definitions
- Generate JSON schemas from SDEF types
- Handle name collisions and normalization

**Key Files:**
- `tool-generator.ts` - Main generator
- `type-mapper.ts` - SDEF type → JSON Schema mapping
- `naming.ts` - Tool naming and collision resolution

**Patterns:**
- Schema generation from SDEF types
- Recursive type mapping
- Collision detection and resolution

#### 2.3 Execution (`src/jitd/execution/`)

**Responsibilities:**
- Execute generated tools on native apps
- Marshal parameters to native formats
- Handle execution errors and timeouts

**Key Files:**
- `executor.ts` - Execution orchestrator
- `parameter-marshaler.ts` - Parameter conversion
- Platform-specific adapters

**Safety:**
- Timeout enforcement (30s default)
- Resource cleanup
- Error isolation

#### 2.4 Caching (`src/jitd/cache/`)

**Responsibilities:**
- Cache parsed SDEF files
- Invalidate on app updates
- Manage cache lifecycle

**Key Files:**
- `tool-cache.ts` - Cache implementation

**Strategy:**
- Timestamp-based invalidation
- Atomic reads/writes
- Graceful fallback on cache errors

### 3. Platform Adapters (`src/adapters/`)

**Responsibilities:**
- Abstract platform-specific automation
- Execute commands via native automation APIs
- Handle platform-specific quirks

**Current Platforms:**
- **macOS** (`adapters/macos/`): AppleScript/JXA via `osascript`
- **Windows** (planned): VBA/COM
- **Linux** (planned): D-Bus

**Pattern:**
- Common interface for all platforms
- Platform detection at runtime
- Fallback strategies

### 4. Error Handling (`src/error-handler.ts`)

**Responsibilities:**
- Centralized error handling
- Error categorization
- Contextual logging
- Recovery strategies

**Categories:**
- Discovery errors
- Parsing errors
- Generation errors
- Execution errors
- MCP protocol errors

**Features:**
- Structured error context
- Configurable logging
- User-friendly messages

## Data Flow

### Cold Start Flow (First Run)

```
1. MCP Client connects → Server starts
2. Server initializes → Discovery starts
3. Discovery scans filesystem → Finds apps
4. For each app:
   a. Locate SDEF file
   b. Parse SDEF → Capabilities
   c. Generate tools → Tool definitions
   d. Cache results
5. Return tool list to client
6. Ready for execution
```

**Timeline:** ~8-10 seconds for 10+ apps

### Warm Start Flow (Cached)

```
1. MCP Client connects → Server starts
2. Server checks cache → Load cached tools
3. Validate timestamps → Tools still valid
4. Return tool list to client
5. Ready for execution
```

**Timeline:** <2 seconds

### Tool Execution Flow

```
1. Client calls tool → MCP request
2. Server receives request → Extract parameters
3. Look up tool → Find app + command
4. Marshal parameters → Native format
5. Execute via adapter → osascript (macOS)
6. Parse result → JSON/text
7. Return to client → MCP response
```

**Timeline:** <5 seconds per command

## Component Interactions

### Discovery → Parser → Generator

```typescript
// Discovery finds apps
const apps = await discovery.discoverApps();

// For each app
for (const app of apps) {
  // Parser extracts capabilities
  const capabilities = await parser.parseSdef(app.sdefPath, app.bundleId);

  // Generator creates tools
  const tools = generator.generateToolsFromCapabilities(capabilities);

  // Cache results
  await cache.saveCachedTools(app.bundleId, tools, capabilities);
}
```

### Executor → Adapter → Native App

```typescript
// Tool execution request
const result = await executor.executeTool({
  toolName: 'finder_open',
  parameters: { target: '/Users/jake/Desktop' }
});

// Executor marshals parameters
const nativeParams = marshaler.marshal(parameters, parameterSchema);

// Adapter executes
const output = await adapter.execute(appBundleId, commandName, nativeParams);

// Result returned to client
return { content: [{ type: 'text', text: output }] };
```

### Cache → File System

```typescript
// Cache structure
{
  "version": "1.0.0",
  "lastUpdated": "2026-01-16T...",
  "apps": {
    "com.apple.finder": {
      "bundleId": "com.apple.finder",
      "bundlePath": "/System/Library/CoreServices/Finder.app",
      "lastModified": "2025-12-01T...",
      "tools": [...],
      "capabilities": {...}
    }
  }
}
```

## Extensibility

### Adding New Platforms

1. **Create Platform Adapter** (`src/adapters/<platform>/`)
   ```typescript
   export class WindowsAdapter implements PlatformAdapter {
     async execute(bundleId: string, command: string, params: any): Promise<any> {
       // Implement Windows-specific execution (VBA/COM)
     }
   }
   ```

2. **Implement Discovery** (`src/jitd/discovery/<platform>-discovery.ts`)
   ```typescript
   export class WindowsDiscovery {
     async discoverApps(): Promise<AppInfo[]> {
       // Scan registry, Program Files, etc.
     }
   }
   ```

3. **Register Platform** (`src/index.ts`)
   ```typescript
   const adapter = platform === 'win32'
     ? new WindowsAdapter()
     : new MacOSAdapter();
   ```

### Adding New Tool Types

1. **Extend Type Mapper** (`src/jitd/tool-generation/type-mapper.ts`)
   ```typescript
   case 'new-type':
     return { type: 'string', format: 'custom' };
   ```

2. **Update Parameter Marshaler** (`src/jitd/execution/parameter-marshaler.ts`)
   ```typescript
   if (schema.format === 'custom') {
     return convertToCustomFormat(value);
   }
   ```

### Adding Caching Strategies

1. **Extend Cache Interface** (`src/jitd/cache/tool-cache.ts`)
   ```typescript
   async cacheWithExpiry(key: string, value: any, ttl: number): Promise<void>
   ```

2. **Implement Strategy**
   ```typescript
   class TTLCache extends ToolCache {
     // Time-based expiration
   }
   ```

## Performance Considerations

### Startup Performance

**Bottlenecks:**
1. Filesystem scanning (parallel mitigates)
2. SDEF parsing (cached after first run)
3. Tool generation (cached)

**Optimizations:**
- Parallel app discovery
- Lazy parsing (parse on demand)
- Aggressive caching
- Incremental updates

### Execution Performance

**Targets:**
- Tool execution: <5s
- Parameter marshaling: <100ms
- Adapter overhead: <50ms

**Strategies:**
- Connection pooling (future)
- Command batching (future)
- Result caching (future)

### Memory Management

**Considerations:**
- Cache size (10MB typical)
- Tool definitions in memory (~1MB)
- Execution contexts (short-lived)

**Strategies:**
- LRU cache eviction (future)
- Lazy loading
- Cleanup on shutdown

## Security Architecture

### Input Validation

**All inputs validated:**
- Tool parameters (JSON Schema)
- File paths (sanitization)
- Command injection prevention

### Execution Safety

**Sandboxing:**
- No shell command injection
- Timeout enforcement
- Resource limits

### Permission System (Future)

**Planned:**
- User confirmation for sensitive operations
- Allowlist/blocklist
- Audit logging

### Error Handling

**Security-focused:**
- No sensitive data in errors
- Sanitized error messages
- Structured logging

## Future Enhancements

### Phase 2: Advanced Features

1. **Multi-Platform Support**
   - Windows (VBA/COM)
   - Linux (D-Bus)

2. **Performance**
   - Connection pooling
   - Command batching
   - Predictive caching

3. **Security**
   - Permission system
   - Audit logging
   - Sandboxing

4. **Developer Experience**
   - Plugin system
   - Custom adapters
   - Tool debugging

### Phase 3: Enterprise Features

1. **Scalability**
   - Distributed caching
   - Load balancing
   - High availability

2. **Monitoring**
   - Metrics collection
   - Performance tracking
   - Error aggregation

3. **Integration**
   - REST API
   - WebSocket support
   - Multi-client

## Conclusion

The IAC-MCP architecture is designed for:

- **Flexibility**: Support any platform and app
- **Performance**: Sub-second warm startup
- **Reliability**: 95%+ success rate
- **Maintainability**: Clean separation of concerns
- **Extensibility**: Easy to add platforms and features

This modular design enables the vision of universal AI-native app automation while maintaining high quality standards and developer experience.
