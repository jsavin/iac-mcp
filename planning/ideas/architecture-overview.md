# Architecture Overview

## System Layers

```
┌─────────────────────────────────────────────────────┐
│                    MCP Client                       │
│              (Claude Desktop, Claude Code)          │
└─────────────────────────────────────────────────────┘
                         ↕ stdio / MCP Protocol
┌─────────────────────────────────────────────────────┐
│                   MCP Server Layer                  │
├─────────────────────────────────────────────────────┤
│  • Tool Registry & Dispatch                         │
│  • Permission Management                            │
│  • Request/Response Handling                        │
└─────────────────────────────────────────────────────┘
                         ↕
┌─────────────────────────────────────────────────────┐
│              Tool Generation Layer                  │
├─────────────────────────────────────────────────────┤
│  • JITD Engine                                      │
│  • Capability → Tool Mapping                        │
│  • JSON Schema Generation                           │
│  • Tool Categorization & Filtering                  │
└─────────────────────────────────────────────────────┘
                         ↕
┌─────────────────────────────────────────────────────┐
│            Discovery & Caching Layer                │
├─────────────────────────────────────────────────────┤
│  • Application Scanner                              │
│  • Capability Parser (SDEF, COM, D-Bus)             │
│  • Cache Management                                 │
│  • Change Detection                                 │
└─────────────────────────────────────────────────────┘
                         ↕
┌─────────────────────────────────────────────────────┐
│              Platform Adapter Layer                 │
├─────────────────────────────────────────────────────┤
│  macOS Adapter  │  Windows Adapter  │  Linux Adapter│
│  • AppleEvents  │  • COM            │  • D-Bus      │
│  • JXA          │  • PowerShell     │  • Shell      │
└─────────────────────────────────────────────────────┘
                         ↕
┌─────────────────────────────────────────────────────┐
│                Native Platform APIs                 │
│          (Operating System & Applications)          │
└─────────────────────────────────────────────────────┘
```

## Core Components

### 1. MCP Server Layer

**Responsibilities:**
- Implement MCP protocol (stdio transport)
- Handle tool discovery requests
- Route tool execution requests
- Manage permissions and safety checks
- Handle errors and responses

**Key Classes:**
```typescript
class IACMCPServer {
  private toolRegistry: ToolRegistry;
  private permissionManager: PermissionManager;
  private executor: ToolExecutor;

  async handleListTools(): Promise<Tool[]>;
  async handleCallTool(name: string, args: object): Promise<Result>;
  async handleListResources(): Promise<Resource[]>;
  async handleReadResource(uri: string): Promise<ResourceContent>;
}
```

### 2. Tool Generation Layer (JITD Engine)

**Responsibilities:**
- Convert discovered capabilities to MCP tools
- Generate JSON schemas for parameters
- Implement tool filtering strategies
- Handle tool naming and namespacing
- Manage tool lifecycle (lazy loading, caching)

**Key Classes:**
```typescript
class JITDEngine {
  generateTools(apps: DiscoveredApp[]): Tool[];
  generateToolSchema(capability: Capability): JSONSchema;
  filterCommonTools(tools: Tool[]): Tool[];
  categorizeTool(tool: Tool): Category;
}

class ToolRegistry {
  private tools: Map<string, RegisteredTool>;

  registerTool(tool: Tool): void;
  getTool(name: string): RegisteredTool | null;
  listTools(filter?: ToolFilter): Tool[];
  searchTools(query: string): Tool[];
}
```

### 3. Discovery & Caching Layer

**Responsibilities:**
- Scan for installed applications
- Parse capability definitions (SDEF, TypeLib, etc.)
- Cache discovered data
- Detect application changes
- Manage invalidation

**Key Classes:**
```typescript
interface ApplicationDiscoverer {
  discover(): Promise<DiscoveredApp[]>;
  getAppInfo(appId: string): Promise<DiscoveredApp>;
  watchForChanges(callback: (change: AppChange) => void): void;
}

class MacOSDiscoverer implements ApplicationDiscoverer {
  private sdefParser: SDEFParser;
  private fileWatcher: FileSystemWatcher;

  async findScriptableApps(): Promise<string[]>;
  async parseSDEF(path: string): Promise<Capability[]>;
}

class CapabilityCache {
  private cacheFile: string;
  private cache: CachedData;

  async load(): Promise<void>;
  async save(): Promise<void>;
  get(appId: string): CachedApp | null;
  set(appId: string, data: CachedApp): void;
  invalidate(appId: string): void;
}
```

### 4. Platform Adapter Layer

**Responsibilities:**
- Execute tool calls on native platform
- Translate parameters to native types
- Handle platform-specific execution models
- Return results in universal format

**Key Classes:**
```typescript
interface PlatformAdapter {
  readonly platform: Platform;

  initialize(): Promise<void>;
  execute(appId: string, capability: string, params: object): Promise<any>;
  getNativeType(universalType: UniversalType): NativeType;
}

class MacOSAdapter implements PlatformAdapter {
  async execute(appId: string, capability: string, params: object) {
    const appleEvent = this.buildAppleEvent(capability, params);
    return this.sendEvent(appId, appleEvent);
  }

  private buildAppleEvent(capability: string, params: object): AppleEvent {
    // Construct AppleEvent from capability and parameters
  }

  private async sendEvent(appId: string, event: AppleEvent): Promise<any> {
    // Send AppleEvent via JXA or native bridge
  }
}

class WindowsAdapter implements PlatformAdapter {
  async execute(appId: string, capability: string, params: object) {
    const comCall = this.buildCOMCall(capability, params);
    return this.invokeCOM(appId, comCall);
  }
}
```

### 5. Permission Management

**Responsibilities:**
- Check if operation requires permission
- Prompt user for confirmation
- Store user preferences
- Apply central safety rules
- Maintain audit log

**Key Classes:**
```typescript
class PermissionManager {
  private store: PermissionStore;
  private ruleEngine: SafetyRuleEngine;

  async checkPermission(
    appId: string,
    capability: string,
    params: object
  ): Promise<PermissionResult>;

  async requestPermission(
    appId: string,
    operation: string,
    context: Context
  ): Promise<boolean>;

  storeUserDecision(decision: UserDecision): void;
  logExecution(log: AuditEntry): void;
}

class SafetyRuleEngine {
  private centralRules: SafetyRule[];
  private userRules: UserRule[];

  classify(capability: string, params: object): SafetyLevel;
  isBlocked(capability: string): boolean;
  requiresConfirmation(capability: string): boolean;
}
```

## Data Flow

### Tool Discovery Flow
```
1. Server Startup
   ↓
2. ApplicationDiscoverer.discover()
   ↓
3. For each app: parse capabilities
   ↓
4. CapabilityCache: check cache, parse if needed
   ↓
5. JITDEngine.generateTools(apps)
   ↓
6. ToolRegistry.registerTools(tools)
   ↓
7. Server ready, tools available
```

### Tool Execution Flow
```
1. MCP Client: CallTool request
   ↓
2. MCP Server: validate tool exists
   ↓
3. PermissionManager: check if allowed
   ↓  (if requires permission)
4. Prompt user → wait for response
   ↓
5. ToolExecutor: dispatch to platform adapter
   ↓
6. PlatformAdapter: translate & execute
   ↓
7. Native API call (AppleEvent, COM, D-Bus)
   ↓
8. Result: translate back to universal format
   ↓
9. Return to MCP Client
```

### Change Detection Flow
```
1. FileSystemWatcher: detects app install/update/remove
   ↓
2. ApplicationDiscoverer: triggered
   ↓
3. Parse new/changed app capabilities
   ↓
4. CapabilityCache: update cache
   ↓
5. JITDEngine: regenerate tools for changed app
   ↓
6. ToolRegistry: update tool list
   ↓
7. Optionally: notify MCP client of new tools
```

## Configuration

### Server Configuration
```typescript
interface IACConfig {
  // Platform
  platform: Platform;
  adapters: AdapterConfig[];

  // Discovery
  discovery: {
    scanOnStartup: boolean;
    watchForChanges: boolean;
    scanPaths: string[];
    excludeApps: string[];
  };

  // Tool Generation
  toolGeneration: {
    strategy: "eager" | "lazy" | "hybrid";
    maxEagerTools: number;
    includeCategories: string[];
    filterRareTools: boolean;
  };

  // Permissions
  permissions: {
    enablePrompts: boolean;
    autoAllowSafe: boolean;
    requireConfirmationFor: string[];
    centralRulesUrl?: string;
    updateRulesAutomatically: boolean;
  };

  // Caching
  cache: {
    enabled: boolean;
    directory: string;
    ttl: number;
    maxSize: number;
  };

  // Performance
  performance: {
    maxConcurrentExecutions: number;
    executionTimeout: number;
    discoveryTimeout: number;
  };
}
```

### User Configuration
```json
{
  "enabledApps": ["com.apple.finder", "com.apple.Safari"],
  "disabledApps": ["com.example.untrusted"],
  "autoAllowFor": {
    "com.apple.finder": ["list_folder", "get_info"]
  },
  "alwaysDeny": {
    "com.apple.finder": ["delete_immediately"]
  },
  "preferences": {
    "skipConfirmationsThisSession": false,
    "verboseLogging": false
  }
}
```

## Storage

### Cache Structure
```
~/Library/Application Support/iac-mcp/
  ├── app-cache.json          # Discovered apps and capabilities
  ├── permissions.json        # User permission decisions
  ├── central-rules.json      # Downloaded safety rules
  ├── usage-stats.json        # Tool usage analytics
  └── audit-log.jsonl         # Execution audit log
```

### Cache Format
```typescript
interface AppCache {
  version: string;
  platform: Platform;
  lastScan: string; // ISO date
  apps: {
    [appId: string]: {
      name: string;
      version: string;
      path: string;
      lastModified: string;
      capabilities: Capability[];
      parsedAt: string;
    }
  };
}
```

## Performance Targets

### Discovery
- Full system scan: < 10 seconds
- Single app parse: < 100ms
- Cache load: < 50ms
- Change detection: < 1 second

### Execution
- Tool call latency: < 200ms (simple operations)
- Permission check: < 10ms (cached decisions)
- Tool lookup: < 5ms

### Memory
- Base: < 50MB
- With full cache: < 200MB
- Per discovered app: < 500KB

## Testing Strategy

### Unit Tests
- SDEF parsing
- Tool generation
- Permission logic
- Type mapping
- Cache operations

### Integration Tests
- Full discovery flow
- Tool execution end-to-end
- Permission prompts
- Cache invalidation
- Change detection

### Platform Tests
- macOS: Test with Finder, Safari, Mail
- Windows: Test with Explorer, Edge (when implemented)
- Cross-platform: Same logical operation on different platforms

### Performance Tests
- Large-scale discovery (500+ apps)
- Tool explosion scenarios
- Concurrent execution
- Memory leak detection

## Security Considerations

### Input Validation
- All parameters validated against schema
- Path traversal prevention
- Command injection prevention
- Type coercion safety

### Sandboxing
- Consider running executions in sandbox
- Limit file system access
- Network access controls
- Resource limits (CPU, memory, time)

### Audit Trail
- Log all executions
- Capture parameters and results
- Track permission decisions
- Export for security review

### Updates
- Verify central rule signatures
- Secure update channel (HTTPS)
- Rollback capability
- User notification of security updates
