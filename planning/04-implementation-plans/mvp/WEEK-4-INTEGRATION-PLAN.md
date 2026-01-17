# Week 4: JITD Integration & End-to-End Validation

## Executive Summary

**Goal:** Complete the JITD proof of concept by integrating all components (discovery, parsing, tool generation, execution) and validating the full system works end-to-end with Claude Desktop.

**Timeline:** 5-7 days (25-35 hours @ 5 hours/day)

**Current Status:**
- Week 1-2: SDEF parsing and tool generation ✓ COMPLETE
- Week 3: Tool execution layer (JXAExecutor, ParameterMarshaler, PermissionChecker) ✓ COMPLETE (1,125+ passing tests)
- Week 4: Integration and validation ← **YOU ARE HERE**

**What We're Building:**
1. Full JITD pipeline: App discovery → SDEF parsing → Tool generation → Execution
2. MCP server with complete ListTools/CallTool handlers
3. Resource caching for fast startup
4. Integration with Claude Desktop
5. End-to-end validation with real applications
6. Production-ready error handling and logging

**Success Criteria:**
- JITD discovers 10+ macOS apps automatically
- Generates 50+ MCP tools from discovered apps
- Claude Desktop can list and call tools
- Full execution pipeline works reliably (>95% success rate)
- Startup time < 10 seconds
- Response time < 5 seconds for typical commands
- Clear error messages for all failure modes
- Ready for Phase 1 (Month 2+)

---

## Architecture Overview

### Complete System Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         MCP Client                               │
│                      (Claude Desktop)                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ MCP Protocol (stdio)
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                    IACMCPServer                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ ListTools   │  │  CallTool   │  │  Resources  │            │
│  │  Handler    │  │   Handler   │  │   Handler   │            │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
└─────────┼─────────────────┼─────────────────┼──────────────────┘
          │                 │                 │
          │                 │                 │
┌─────────▼─────────────────▼─────────────────▼──────────────────┐
│                      JITD Engine                                 │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │  App Discovery   │  │   Tool Cache     │                    │
│  │  findAllApps()   │  │  (JSON storage)  │                    │
│  └────────┬─────────┘  └────────┬─────────┘                    │
│           │                      │                               │
│  ┌────────▼──────────────────────▼─────────┐                   │
│  │        SDEF Parser                        │                   │
│  │        parse(sdefPath)                    │                   │
│  └────────┬──────────────────────────────────┘                   │
│           │                                                       │
│  ┌────────▼──────────────────────────────────┐                   │
│  │        Tool Generator                      │                   │
│  │        generateTools(dictionary, appInfo) │                   │
│  └────────┬──────────────────────────────────┘                   │
└───────────┼───────────────────────────────────────────────────────┘
            │
            │ MCPTool[]
            │
┌───────────▼───────────────────────────────────────────────────┐
│                   Execution Pipeline                           │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐ │
│  │  Permission    │→ │   MacOS        │→ │   Result        │ │
│  │  Checker       │  │   Adapter      │  │   Parser        │ │
│  └────────────────┘  └────────────────┘  └─────────────────┘ │
│                      ┌────────────────┐                        │
│                      │  JXA Executor  │                        │
│                      │  (osascript)   │                        │
│                      └────────────────┘                        │
└───────────────────────────────────────────────────────────────┘
```

### Data Flow

**Startup Sequence:**
```
1. IACMCPServer.initialize()
   ├─ Check cache (if enabled)
   │  └─ Load cached app data if valid
   ├─ Discover apps (findAllScriptableApps)
   │  ├─ Scan /Applications
   │  ├─ Scan /System/Library/CoreServices
   │  └─ Return [{appName, bundlePath, sdefPath}]
   ├─ For each discovered app:
   │  ├─ Parse SDEF file (SDEFParser.parse)
   │  ├─ Generate tools (ToolGenerator.generateTools)
   │  └─ Store in generatedTools[]
   ├─ Setup MCP handlers (setupHandlers)
   └─ Ready to accept requests

2. IACMCPServer.start()
   ├─ Create StdioServerTransport
   ├─ Connect server to transport
   └─ Start listening for MCP requests
```

**Tool Execution Flow:**
```
1. Claude Desktop → ListTools request
   └─ MCP Server → Return generatedTools[]

2. Claude Desktop → CallTool request {name, arguments}
   ├─ Lookup tool by name
   ├─ Validate arguments (validateToolArguments)
   ├─ Check permissions (PermissionChecker.check)
   ├─ If denied → Return permission error
   ├─ Execute tool (MacOSAdapter.execute)
   │  ├─ Marshal parameters (ParameterMarshaler)
   │  ├─ Build JXA script
   │  ├─ Execute via osascript (JXAExecutor)
   │  ├─ Parse result (ResultParser)
   │  └─ Return parsed data
   ├─ Record in audit log
   └─ Return success/error response
```

---

## Week 4 Implementation Plan

### Phase 1: Tool Cache System (Day 1)

**Goal:** Implement caching to make startup fast (<5s instead of 10-30s)

**Background:**
- Parsing 10-15 SDEF files on every startup is slow
- SDEF files rarely change (only on app updates)
- Cache invalidation: Check app bundle modification time

#### 1.1 Cache Data Structure

**File:** `src/jitd/cache/tool-cache.ts`

```typescript
/**
 * Tool cache for fast startup
 *
 * Stores parsed SDEF data and generated tools to avoid re-parsing on every startup.
 * Invalidates cache when app bundle is modified.
 */

export interface CachedAppData {
  appName: string;
  bundlePath: string;
  bundleId: string;
  sdefPath: string;
  sdefModifiedTime: number;  // Unix timestamp
  bundleModifiedTime: number; // Unix timestamp
  parsedSDEF: SDEFDictionary;
  generatedTools: MCPTool[];
  cachedAt: number; // Unix timestamp
}

export interface CacheManifest {
  version: string; // Cache format version
  cachedAt: number;
  apps: CachedAppData[];
}

export class ToolCache {
  private cacheDir: string;
  private cacheFile: string;

  constructor(cacheDir?: string) {
    this.cacheDir = cacheDir ?? path.join(os.tmpdir(), 'iac-mcp-cache');
    this.cacheFile = path.join(this.cacheDir, 'tool-cache.json');
  }

  /**
   * Load cached data if valid
   *
   * @returns Cached data or null if invalid/missing
   */
  async load(): Promise<CacheManifest | null> {
    try {
      if (!fs.existsSync(this.cacheFile)) {
        return null;
      }

      const data = await fs.promises.readFile(this.cacheFile, 'utf-8');
      const manifest: CacheManifest = JSON.parse(data);

      // Validate cache version
      if (manifest.version !== CACHE_VERSION) {
        console.error('[ToolCache] Cache version mismatch, invalidating');
        return null;
      }

      return manifest;
    } catch (error) {
      console.error('[ToolCache] Failed to load cache:', error);
      return null;
    }
  }

  /**
   * Save cache to disk
   *
   * @param manifest - Cache manifest to save
   */
  async save(manifest: CacheManifest): Promise<void> {
    try {
      // Ensure cache directory exists
      await fs.promises.mkdir(this.cacheDir, { recursive: true });

      // Write cache file
      await fs.promises.writeFile(
        this.cacheFile,
        JSON.stringify(manifest, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.error('[ToolCache] Failed to save cache:', error);
    }
  }

  /**
   * Check if cached app data is still valid
   *
   * @param cached - Cached app data
   * @returns True if cache is valid, false if stale
   */
  async isValid(cached: CachedAppData): Promise<boolean> {
    try {
      // Check if app bundle still exists
      const bundleStat = await fs.promises.stat(cached.bundlePath);
      const sdefStat = await fs.promises.stat(cached.sdefPath);

      // Invalidate if modification times changed
      if (bundleStat.mtimeMs !== cached.bundleModifiedTime) {
        return false;
      }

      if (sdefStat.mtimeMs !== cached.sdefModifiedTime) {
        return false;
      }

      return true;
    } catch {
      // If files don't exist, cache is invalid
      return false;
    }
  }

  /**
   * Invalidate cache (delete cache file)
   */
  async invalidate(): Promise<void> {
    try {
      if (fs.existsSync(this.cacheFile)) {
        await fs.promises.unlink(this.cacheFile);
      }
    } catch (error) {
      console.error('[ToolCache] Failed to invalidate cache:', error);
    }
  }
}

const CACHE_VERSION = '1.0.0';
```

#### 1.2 Integrate Cache into IACMCPServer

**Update:** `src/mcp/server.ts`

```typescript
// Add cache to constructor
private cache: ToolCache;

constructor(options?: ServerOptions) {
  // ... existing code ...
  this.cache = new ToolCache(this.options.cacheDir);
}

// Update initialize() to use cache
async initialize(): Promise<void> {
  try {
    if (this.options.enableLogging) {
      console.error('[IACMCPServer] Starting initialization...');
    }

    // Try to load cache
    let cacheManifest: CacheManifest | null = null;
    if (this.options.enableCache) {
      cacheManifest = await this.cache.load();

      if (cacheManifest) {
        // Validate cached apps
        const validApps: CachedAppData[] = [];
        for (const cached of cacheManifest.apps) {
          if (await this.cache.isValid(cached)) {
            validApps.push(cached);
          }
        }

        if (validApps.length > 0) {
          console.error(`[IACMCPServer] Loaded ${validApps.length} apps from cache`);

          // Use cached data
          this.discoveredApps = validApps.map(a => ({
            appName: a.appName,
            bundlePath: a.bundlePath,
            sdefPath: a.sdefPath,
          }));

          this.generatedTools = validApps.flatMap(a => a.generatedTools);
          this.status.appsDiscovered = this.discoveredApps.length;
          this.status.toolsGenerated = this.generatedTools.length;

          // Setup handlers and return early
          await this.setupMCPHandlers();
          this.status.initialized = true;
          return;
        }
      }
    }

    // No valid cache, proceed with full discovery
    this.discoveredApps = await this.discoverer({
      useCache: false, // Don't use SDEF discovery cache, we have our own
    });

    // ... existing parsing and generation code ...

    // Save to cache if enabled
    if (this.options.enableCache) {
      const manifest: CacheManifest = {
        version: '1.0.0',
        cachedAt: Date.now(),
        apps: this.discoveredApps.map((app, i) => ({
          ...app,
          bundleId: this.extractBundleId(app.bundlePath),
          sdefModifiedTime: fs.statSync(app.sdefPath).mtimeMs,
          bundleModifiedTime: fs.statSync(app.bundlePath).mtimeMs,
          parsedSDEF: {} as any, // We could cache this too
          generatedTools: this.generatedTools.filter(t =>
            t._metadata.appName === app.appName
          ),
          cachedAt: Date.now(),
        })),
      };

      await this.cache.save(manifest);
    }

    await this.setupMCPHandlers();
    this.status.initialized = true;
  } catch (error) {
    // ... error handling ...
  }
}
```

#### 1.3 Tests for Cache

**File:** `tests/unit/tool-cache.test.ts`

```typescript
describe('ToolCache', () => {
  describe('save() and load()', () => {
    it('should save and load cache manifest');
    it('should create cache directory if missing');
    it('should handle missing cache file gracefully');
    it('should reject cache with wrong version');
  });

  describe('isValid()', () => {
    it('should validate cache when files unchanged');
    it('should invalidate cache when bundle modified');
    it('should invalidate cache when SDEF modified');
    it('should invalidate cache when files deleted');
  });

  describe('invalidate()', () => {
    it('should delete cache file');
    it('should handle missing cache file gracefully');
  });
});
```

**Validation:**
- Cache reduces startup time from 10-30s to <2s
- Cache invalidates correctly when apps updated
- Cache survives system restarts

---

### Phase 2: Complete MCP Handler Integration (Day 2)

**Goal:** Wire ListTools and CallTool handlers to use real JITD pipeline

#### 2.1 Update MCP Handlers

**File:** `src/mcp/handlers.ts`

Current state: Handlers return placeholder responses.
Target state: Handlers use real discovered tools and execute via adapter.

**Changes needed:**

1. Remove placeholder ListTools handler (already overridden in server.ts)
2. Remove placeholder CallTool handler (already overridden in server.ts)
3. Keep utility functions (validateToolArguments, formatErrorResponse, etc.)

**Verification:** The handlers are already integrated in `server.ts`, so this is mostly cleanup.

#### 2.2 Enhanced Error Responses

**Update:** `src/mcp/handlers.ts`

Add more detailed error responses:

```typescript
/**
 * Enhanced error response with suggestions
 */
function formatEnhancedErrorResponse(
  error: Error | string,
  context: {
    toolName?: string;
    appName?: string;
    operation?: string;
  }
): Record<string, any> {
  const message = error instanceof Error ? error.message : error;

  // Determine error type and suggestion
  let suggestion: string | undefined;

  if (message.includes('Application can\'t be found')) {
    suggestion = `Please ensure ${context.appName} is installed in /Applications`;
  } else if (message.includes('Not authorized')) {
    suggestion = 'Grant automation permission in System Settings → Privacy & Security → Automation';
  } else if (message.includes('timeout')) {
    suggestion = 'The operation timed out. Try again or check if the app is responding.';
  }

  return {
    error: message,
    code: getErrorCode(message),
    suggestion,
    context,
    timestamp: new Date().toISOString(),
  };
}
```

#### 2.3 Integration Tests

**File:** `tests/integration/mcp-server.test.ts`

```typescript
describe('MCP Server Integration', () => {
  let server: IACMCPServer;

  beforeAll(async () => {
    server = new IACMCPServer({
      enableCache: false, // Force fresh discovery for tests
      enableLogging: true,
    });
    await server.initialize();
  });

  afterAll(async () => {
    // Server doesn't need stop() for tests (no transport)
  });

  describe('ListTools handler', () => {
    it('should return discovered tools', async () => {
      const status = server.getStatus();
      expect(status.toolsGenerated).toBeGreaterThan(0);

      // The actual ListTools request is tested in e2e-workflows.test.ts
    });

    it('should include Finder tools', async () => {
      const status = server.getStatus();
      expect(status.appsDiscovered).toBeGreaterThan(0);

      // Verify Finder is discovered
      // Note: actual tool verification is in e2e tests
    });
  });

  describe('CallTool handler', () => {
    it('should execute valid tool', async () => {
      // This will be tested via the full execution pipeline
      // in e2e-workflows.test.ts
    });

    it('should return error for unknown tool', async () => {
      // Test error handling
    });

    it('should validate arguments', async () => {
      // Test argument validation
    });

    it('should check permissions', async () => {
      // Test permission checking
    });
  });
});
```

**Validation:**
- ListTools returns all discovered tools (50+)
- CallTool executes tools correctly
- Error responses are informative
- Permission checks work

---

### Phase 3: End-to-End Validation (Days 3-4)

**Goal:** Test complete system with real apps and real workflows

#### 3.1 Expand Integration Tests

**File:** `tests/integration/e2e-workflows.test.ts`

Add comprehensive end-to-end workflows:

```typescript
describe('End-to-End Workflows', () => {
  let server: IACMCPServer;
  let transport: StdioServerTransport;

  beforeAll(async () => {
    server = new IACMCPServer({
      enableCache: false,
      enableLogging: true,
    });
    await server.initialize();

    // Note: For unit testing, we don't actually start the stdio transport
    // as it would block. Instead, we test the handlers directly.
  });

  describe('Discovery and Tool Generation', () => {
    it('should discover 10+ macOS apps', async () => {
      const status = server.getStatus();
      expect(status.appsDiscovered).toBeGreaterThanOrEqual(10);
    });

    it('should generate 50+ tools', async () => {
      const status = server.getStatus();
      expect(status.toolsGenerated).toBeGreaterThanOrEqual(50);
    });

    it('should include common apps', async () => {
      // Verify Finder, Safari, Mail, etc. are discovered
      const status = server.getStatus();
      expect(status.appsDiscovered).toBeGreaterThan(0);

      // Check specific apps by querying tools
      // finder_*, safari_*, mail_* tools should exist
    });
  });

  describe('Finder Workflows', () => {
    it('should list desktop files', async () => {
      // Test finder_list_folder with ~/Desktop
    });

    it('should get file information', async () => {
      // Test finder_get_file_info
    });

    it('should handle errors gracefully', async () => {
      // Test with non-existent path
    });
  });

  describe('Safari Workflows (if Safari running)', () => {
    it('should get current URL', async () => {
      // Skip if Safari not running
    });

    it('should get page title', async () => {
      // Skip if Safari not running
    });
  });

  describe('Permission System', () => {
    it('should allow safe operations', async () => {
      // Test read-only operations
    });

    it('should classify modify operations', async () => {
      // Test modify operations (e.g., move file)
    });

    it('should classify dangerous operations', async () => {
      // Test dangerous operations (e.g., delete)
    });
  });

  describe('Error Handling', () => {
    it('should handle app not found', async () => {
      // Test with non-existent app
    });

    it('should handle invalid arguments', async () => {
      // Test with wrong argument types
    });

    it('should handle timeouts', async () => {
      // Test with very slow operation (mock)
    });
  });
});
```

#### 3.2 Performance Testing

**File:** `tests/integration/performance.test.ts`

```typescript
describe('Performance Tests', () => {
  describe('Startup Performance', () => {
    it('should initialize in < 10 seconds (cold start)', async () => {
      const start = Date.now();

      const server = new IACMCPServer({
        enableCache: false, // Force cold start
      });
      await server.initialize();

      const duration = Date.now() - start;
      expect(duration).toBeLessThan(10000);
    });

    it('should initialize in < 2 seconds (warm start)', async () => {
      // First run to populate cache
      const server1 = new IACMCPServer({ enableCache: true });
      await server1.initialize();

      // Second run with cache
      const start = Date.now();
      const server2 = new IACMCPServer({ enableCache: true });
      await server2.initialize();
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(2000);
    });
  });

  describe('Execution Performance', () => {
    it('should execute simple command in < 5 seconds', async () => {
      const server = new IACMCPServer();
      await server.initialize();

      // Test finder_list_folder
      const start = Date.now();
      // Execute command
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(5000);
    });

    it('should handle concurrent requests', async () => {
      // Test multiple requests in parallel
      // Ensure no race conditions or resource leaks
    });
  });
});
```

#### 3.3 Real App Testing Matrix

Test with these apps to ensure broad compatibility:

| App | Commands to Test | Expected Results |
|-----|-----------------|------------------|
| **Finder** | list_folder, get_file_info, open | Should work reliably |
| **Safari** | get_url, get_title, count_tabs | Should work if Safari running |
| **Mail** | count_messages, get_mailboxes | Should work if Mail configured |
| **Calendar** | list_calendars, count_events | Should work if Calendar configured |
| **Notes** | list_notes, create_note | Should work |
| **Reminders** | list_reminders, count_todos | Should work if Reminders configured |
| **Messages** | send_message | Should work but permission needed |
| **Music** | get_current_track, play/pause | Should work if Music running |
| **Photos** | count_photos, get_albums | Should work |
| **Contacts** | count_contacts, search | Should work |

**Testing Strategy:**
- Run automated tests with Finder (always available)
- Manual testing with Safari, Mail, Calendar
- Document any app-specific quirks
- Create workarounds for common issues

---

### Phase 4: Claude Desktop Integration (Day 5)

**Goal:** Test with real MCP client (Claude Desktop) and validate user experience

#### 4.1 Build and Package

```bash
# Build TypeScript
npm run build

# Verify build artifacts
ls -la dist/

# Test CLI entry point
node dist/index.js --help
```

#### 4.2 Configure Claude Desktop

**File:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "iac-bridge": {
      "command": "node",
      "args": ["/Users/jake/dev/jsavin/iac-mcp/dist/index.js"],
      "env": {
        "IAC_LOG_LEVEL": "info"
      }
    }
  }
}
```

**Alternative (using npm link):**

```bash
# Link package locally
npm link

# Configure Claude Desktop
{
  "mcpServers": {
    "iac-bridge": {
      "command": "iac-mcp"
    }
  }
}
```

#### 4.3 Manual Testing Checklist

**Setup:**
- [ ] Build project: `npm run build`
- [ ] Configure Claude Desktop
- [ ] Restart Claude Desktop
- [ ] Verify server starts (check Claude logs)

**Discovery:**
- [ ] Ask Claude: "What Mac apps can you control?"
- [ ] Verify Claude lists discovered apps
- [ ] Verify tool count matches expected (50+)

**Basic Operations (Finder):**
- [ ] "List files on my desktop"
- [ ] "Get information about my Documents folder"
- [ ] "Count items in my Downloads folder"
- [ ] Verify results are accurate

**Safari Integration (if Safari running):**
- [ ] "What URL is open in Safari?"
- [ ] "What's the title of my Safari tab?"
- [ ] "How many Safari tabs do I have open?"

**Mail Integration (if Mail configured):**
- [ ] "How many unread emails do I have?"
- [ ] "What mailboxes do I have in Mail?"

**Error Scenarios:**
- [ ] Try command with non-existent app
- [ ] Try command with invalid arguments
- [ ] Try dangerous command (should explain permission level)
- [ ] Verify error messages are clear and helpful

**Performance:**
- [ ] First request after restart (cold start) < 10s
- [ ] Subsequent requests < 5s
- [ ] No hanging or timeouts

**Edge Cases:**
- [ ] Very long file paths
- [ ] Special characters in filenames
- [ ] Empty results (empty folder)
- [ ] Large results (folder with many files)

#### 4.4 User Experience Validation

**Criteria for Success:**
- Claude understands tool descriptions
- Claude uses tools correctly without user needing to specify exact syntax
- Error messages help user fix issues
- No crashes or hangs
- Performance feels responsive

**Example Interactions:**

```
User: "Show me what's on my desktop"
Claude: [Calls finder_list_folder with target: ~/Desktop]
Claude: "I found 12 items on your desktop: [list]"

User: "Open the file called report.pdf"
Claude: [Calls finder_open with target: ~/Desktop/report.pdf]
Claude: "Opened report.pdf"

User: "Delete my Downloads folder"
Claude: [Checks permission level: DANGEROUS]
Claude: "I need permission to delete folders. This is a dangerous operation that can't be undone."
```

---

### Phase 5: Production Readiness (Days 6-7)

**Goal:** Polish, documentation, and prepare for Phase 1

#### 5.1 Logging and Debugging

**Add structured logging:**

```typescript
// src/utils/logger.ts

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

export class Logger {
  private level: LogLevel;

  constructor(levelName?: string) {
    this.level = this.parseLevel(levelName ?? 'info');
  }

  debug(message: string, context?: any) {
    if (this.level <= LogLevel.DEBUG) {
      console.error(`[DEBUG] ${message}`, context ?? '');
    }
  }

  info(message: string, context?: any) {
    if (this.level <= LogLevel.INFO) {
      console.error(`[INFO] ${message}`, context ?? '');
    }
  }

  warn(message: string, context?: any) {
    if (this.level <= LogLevel.WARN) {
      console.error(`[WARN] ${message}`, context ?? '');
    }
  }

  error(message: string, context?: any) {
    if (this.level <= LogLevel.ERROR) {
      console.error(`[ERROR] ${message}`, context ?? '');
    }
  }

  private parseLevel(levelName: string): LogLevel {
    const normalized = levelName.toLowerCase();
    if (normalized === 'debug') return LogLevel.DEBUG;
    if (normalized === 'info') return LogLevel.INFO;
    if (normalized === 'warn') return LogLevel.WARN;
    if (normalized === 'error') return LogLevel.ERROR;
    return LogLevel.INFO;
  }
}

// Global logger instance
export const logger = new Logger(process.env.IAC_LOG_LEVEL);
```

**Use logger throughout codebase:**

```typescript
// Replace console.error with logger
logger.info('[IACMCPServer] Starting initialization...');
logger.debug('[IACMCPServer] Discovered apps:', discoveredApps);
logger.error('[IACMCPServer] Initialization failed:', error);
```

#### 5.2 CLI Interface

**File:** `src/cli.ts`

```typescript
#!/usr/bin/env node

import { IACMCPServer } from './mcp/server.js';
import { logger } from './utils/logger.js';

const args = process.argv.slice(2);

// Parse CLI arguments
const options: any = {
  enableCache: true,
  enableLogging: false,
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];

  if (arg === '--help' || arg === '-h') {
    console.log(`
IAC-MCP Bridge - Just-In-Time Discovery for macOS Apps

Usage: iac-mcp [options]

Options:
  --help, -h          Show this help message
  --version, -v       Show version
  --no-cache          Disable tool cache (slower startup)
  --cache-dir <dir>   Set cache directory (default: /tmp/iac-mcp-cache)
  --timeout <ms>      Set execution timeout in milliseconds (default: 30000)
  --debug             Enable debug logging
  --log-level <level> Set log level (debug|info|warn|error)

Environment Variables:
  IAC_LOG_LEVEL       Log level (debug|info|warn|error)
  IAC_CACHE_DIR       Cache directory path

Examples:
  iac-mcp                    # Start server with defaults
  iac-mcp --debug            # Start with debug logging
  iac-mcp --no-cache         # Disable cache (slower but always fresh)
    `);
    process.exit(0);
  }

  if (arg === '--version' || arg === '-v') {
    console.log('iac-mcp version 0.1.0');
    process.exit(0);
  }

  if (arg === '--no-cache') {
    options.enableCache = false;
  }

  if (arg === '--debug') {
    options.enableLogging = true;
    process.env.IAC_LOG_LEVEL = 'debug';
  }

  if (arg === '--cache-dir') {
    options.cacheDir = args[++i];
  }

  if (arg === '--timeout') {
    options.timeoutMs = parseInt(args[++i], 10);
  }

  if (arg === '--log-level') {
    process.env.IAC_LOG_LEVEL = args[++i];
  }
}

// Start server
async function main() {
  try {
    logger.info('Starting IAC-MCP Bridge...');

    const server = new IACMCPServer(options);
    await server.initialize();
    await server.start();

    logger.info('Server started successfully');

    // Handle shutdown
    process.on('SIGINT', async () => {
      logger.info('Shutting down...');
      await server.stop();
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      logger.info('Shutting down...');
      await server.stop();
      process.exit(0);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

main();
```

**Update package.json:**

```json
{
  "bin": {
    "iac-mcp": "./dist/cli.js"
  },
  "scripts": {
    "build": "tsc",
    "dev": "tsx src/cli.ts",
    "start": "node dist/cli.js",
    "test": "vitest",
    "test:watch": "vitest --watch",
    "test:coverage": "vitest --coverage"
  }
}
```

#### 5.3 Documentation Updates

**Update:** `README.md`

```markdown
# IAC-MCP Bridge

Just-In-Time Discovery (JITD) MCP server for macOS native applications.

## Features

- **Automatic Discovery**: Discovers all scriptable macOS apps automatically
- **Dynamic Tool Generation**: Generates MCP tools from app SDEF files
- **Zero Configuration**: No manual app integrations needed
- **Permission System**: Safe execution with permission classification
- **Caching**: Fast startup with intelligent cache invalidation
- **Broad Compatibility**: Works with 10+ macOS apps out of the box

## Quick Start

### Installation

```bash
npm install -g iac-mcp
```

### Configuration

Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "iac-bridge": {
      "command": "iac-mcp"
    }
  }
}
```

### Usage

Restart Claude Desktop and ask:
- "What Mac apps can you control?"
- "List files on my desktop"
- "What's my current Safari URL?"

## Supported Applications

- **Finder**: File and folder operations
- **Safari**: Browser automation
- **Mail**: Email management
- **Calendar**: Event management
- **Notes**: Note creation and management
- **Reminders**: Task management
- **Messages**: Send messages
- **Music**: Playback control
- **Photos**: Photo library access
- **Contacts**: Contact management
- And more...

## How It Works

1. **Discovery**: Scans /Applications for apps with SDEF files
2. **Parsing**: Parses SDEF XML to understand app capabilities
3. **Generation**: Generates MCP tool definitions dynamically
4. **Execution**: Executes commands via JavaScript for Automation (JXA)
5. **Caching**: Caches parsed data for fast subsequent startups

## Architecture

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build

# Run locally
npm run dev
```

## Troubleshooting

### Permission Denied

Grant automation permission:
1. System Settings → Privacy & Security → Automation
2. Enable Terminal or Claude Desktop to control apps

### App Not Found

Ensure the app is installed in /Applications or /System/Library/CoreServices.

### Slow Startup

First startup may take 10-15 seconds while parsing SDEF files. Subsequent startups use cache and take <2 seconds.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT License - see [LICENSE](LICENSE)
```

**Create:** `docs/ARCHITECTURE.md`

Document the complete system architecture, data flow, and component interactions. Include diagrams from this plan.

**Create:** `docs/TROUBLESHOOTING.md`

Document common issues and solutions:
- Permission problems
- Performance issues
- App compatibility
- Cache invalidation
- Debugging tips

#### 5.4 Final Testing

**Complete Testing Checklist:**

**Unit Tests:**
- [ ] All unit tests pass (1,125+ tests)
- [ ] New cache tests pass
- [ ] Coverage > 80%

**Integration Tests:**
- [ ] Finder integration tests pass
- [ ] E2E workflow tests pass
- [ ] Performance tests pass
- [ ] Cache tests pass

**Manual Tests:**
- [ ] Works with Claude Desktop
- [ ] 10+ apps discovered
- [ ] 50+ tools generated
- [ ] All manual testing checklist items pass
- [ ] No crashes or hangs
- [ ] Error messages clear

**Performance:**
- [ ] Cold start < 10s
- [ ] Warm start < 2s
- [ ] Command execution < 5s
- [ ] Cache working correctly

**Polish:**
- [ ] Logging works
- [ ] CLI help works
- [ ] Documentation complete
- [ ] No console spam (unless debug mode)

---

## Success Criteria

### Technical Validation

**Must Have:**
- [x] Week 1-2: SDEF parsing and tool generation working
- [x] Week 3: Execution layer working (1,125+ tests passing)
- [ ] Week 4: Full integration working
  - [ ] Cache system implemented and tested
  - [ ] MCP handlers fully integrated
  - [ ] E2E tests passing
  - [ ] Claude Desktop integration working
  - [ ] Performance targets met

**Metrics:**
- [ ] Discovers ≥10 macOS apps automatically
- [ ] Generates ≥50 MCP tools
- [ ] Test coverage ≥80%
- [ ] Cold startup ≤10 seconds
- [ ] Warm startup ≤2 seconds
- [ ] Command execution ≤5 seconds
- [ ] Success rate ≥95% for valid commands

### User Experience Validation

**Must Have:**
- [ ] Works reliably with Claude Desktop
- [ ] Claude can discover available tools
- [ ] Claude can execute tools successfully
- [ ] Error messages are clear and actionable
- [ ] No crashes or hangs during normal usage
- [ ] Performance feels responsive

**Should Have:**
- [ ] Works with multiple apps (Finder, Safari, Mail, etc.)
- [ ] Handles edge cases gracefully
- [ ] Provides helpful suggestions in error messages
- [ ] Logs useful debugging information

### Phase 0 Completion Criteria

**Definition of "JITD Proof of Concept Works":**

1. **Discovery Works**
   - Can discover macOS apps with SDEF files
   - Finds 10+ apps reliably
   - No crashes during discovery

2. **Parsing Works**
   - Can parse SDEF files
   - Extracts commands, parameters, types
   - Handles SDEF variations

3. **Generation Works**
   - Generates valid MCP tool definitions
   - Proper JSON Schema for parameters
   - Correct type mappings

4. **Execution Works**
   - Can execute tools via JXA
   - Parameters marshaled correctly
   - Results parsed correctly
   - Errors handled gracefully

5. **Integration Works**
   - Full pipeline works end-to-end
   - MCP server responds correctly
   - Claude Desktop can use tools
   - Performance acceptable

6. **Ready for Phase 1**
   - Codebase is clean and well-tested
   - Documentation is complete
   - Known issues are documented
   - Clear path forward for expansion

---

## Risk Mitigation

### Technical Risks

**Risk: Cache invalidation too aggressive**
- **Mitigation:** Check both bundle and SDEF modification times
- **Fallback:** Add --no-cache flag for users to disable

**Risk: Performance targets not met**
- **Mitigation:** Profile slow operations, optimize parsing
- **Fallback:** Document expected performance on different systems

**Risk: Some apps don't work**
- **Mitigation:** Test with 10+ apps, document quirks
- **Fallback:** Create app-specific workarounds in Phase 1

**Risk: Claude Desktop integration issues**
- **Mitigation:** Follow MCP protocol strictly, test early
- **Fallback:** Use MCP Inspector for debugging

### Integration Risks

**Risk: Components don't integrate smoothly**
- **Mitigation:** Integration tests on Day 3
- **Fallback:** Simplify interfaces if needed

**Risk: MCP SDK changes**
- **Mitigation:** Pin SDK version
- **Fallback:** Can implement MCP protocol manually

### Timeline Risks

**Risk: Tasks take longer than estimated**
- **Mitigation:** Focus on MVP features first
- **Fallback:** Can punt cache to Phase 1 if needed

**Risk: Testing reveals major issues**
- **Mitigation:** Test early and often
- **Fallback:** Have contingency time in Days 6-7

---

## Implementation Timeline

### Day 1: Tool Cache System (5 hours)

**Morning (3 hours):**
- Implement ToolCache class
- Add save/load/isValid methods
- Write unit tests

**Afternoon (2 hours):**
- Integrate cache into IACMCPServer
- Test cache invalidation
- Verify startup performance improvement

**Deliverable:** Cache reduces startup time to <2s

---

### Day 2: MCP Handler Integration (5 hours)

**Morning (2 hours):**
- Clean up placeholder handlers
- Add enhanced error responses
- Update error formatting

**Afternoon (3 hours):**
- Write integration tests for handlers
- Test ListTools with real data
- Test CallTool with real execution
- Verify permission checks

**Deliverable:** Handlers use real JITD pipeline

---

### Day 3: E2E Testing - Part 1 (5 hours)

**Morning (3 hours):**
- Write e2e-workflows.test.ts
- Test discovery and generation
- Test Finder workflows
- Test permission system

**Afternoon (2 hours):**
- Write performance.test.ts
- Test startup performance
- Test execution performance
- Identify bottlenecks

**Deliverable:** E2E tests passing

---

### Day 4: E2E Testing - Part 2 (5 hours)

**Full Day:**
- Test with Safari, Mail, Calendar
- Test error scenarios
- Test edge cases
- Document app-specific quirks
- Fix any issues found
- Ensure all tests pass

**Deliverable:** Comprehensive test coverage

---

### Day 5: Claude Desktop Integration (6 hours)

**Morning (2 hours):**
- Build and package
- Configure Claude Desktop
- Initial smoke tests

**Afternoon (4 hours):**
- Run manual testing checklist
- Test all scenarios
- Test with multiple apps
- Verify user experience
- Document findings

**Deliverable:** Works with Claude Desktop

---

### Day 6: Production Polish (5 hours)

**Morning (3 hours):**
- Add structured logging
- Implement CLI interface
- Add --help, --version, etc.
- Test CLI options

**Afternoon (2 hours):**
- Update README
- Write ARCHITECTURE.md
- Write TROUBLESHOOTING.md
- Update CLAUDE.md

**Deliverable:** Production-ready polish

---

### Day 7: Final Validation (4 hours)

**Morning (2 hours):**
- Run complete test suite
- Verify all success criteria met
- Final manual testing
- Performance validation

**Afternoon (2 hours):**
- Document known issues
- Create Phase 1 planning notes
- Clean up code
- Prepare for Phase 1

**Deliverable:** Phase 0 complete, ready for Phase 1

---

## Total Time: 35 hours over 7 days

**Breakdown:**
- Cache implementation: 5 hours
- MCP integration: 5 hours
- E2E testing: 10 hours
- Claude Desktop: 6 hours
- Production polish: 5 hours
- Final validation: 4 hours

---

## Deliverables

### Code Deliverables

**New Files:**
- `src/jitd/cache/tool-cache.ts` - Caching system
- `src/utils/logger.ts` - Structured logging
- `src/cli.ts` - CLI interface
- `tests/unit/tool-cache.test.ts` - Cache tests
- `tests/integration/mcp-server.test.ts` - Server integration tests
- `tests/integration/performance.test.ts` - Performance tests
- Enhanced `tests/integration/e2e-workflows.test.ts` - Comprehensive E2E tests

**Updated Files:**
- `src/mcp/server.ts` - Add cache integration
- `src/mcp/handlers.ts` - Clean up placeholders, enhance errors
- `README.md` - Complete user documentation
- `package.json` - Add bin, update scripts

**New Documentation:**
- `docs/ARCHITECTURE.md` - System architecture
- `docs/TROUBLESHOOTING.md` - Common issues and solutions
- `docs/DEVELOPMENT.md` - Development guide

### Testing Deliverables

**Test Coverage:**
- Unit tests: 1,125+ passing (Week 3 baseline)
- Integration tests: 50+ tests
- E2E tests: 20+ workflows
- Performance tests: 5+ benchmarks
- Total coverage: >80%

**Manual Testing:**
- Claude Desktop integration checklist (completed)
- Multi-app testing matrix (completed)
- Performance validation (completed)
- Edge case testing (completed)

### Documentation Deliverables

**User Documentation:**
- README with quick start guide
- Installation instructions
- Configuration examples
- Usage examples
- Troubleshooting guide

**Developer Documentation:**
- Architecture overview
- Component descriptions
- Data flow diagrams
- Testing guide
- Contributing guide

**Planning Documentation:**
- Known issues list
- Future improvements
- Phase 1 planning notes
- Lessons learned

---

## Validation Checklist

### Pre-Integration (Before Day 1)

- [x] Week 3 execution layer complete
- [x] 1,125+ tests passing
- [x] JXAExecutor works
- [x] ParameterMarshaler works
- [x] PermissionChecker works
- [ ] Codebase is clean and documented

### Mid-Integration (End of Day 3)

- [ ] Cache system implemented
- [ ] MCP handlers integrated
- [ ] E2E tests written and passing
- [ ] Performance measured and acceptable
- [ ] No critical bugs

### Pre-Claude Testing (End of Day 4)

- [ ] All automated tests passing
- [ ] 10+ apps discovered
- [ ] 50+ tools generated
- [ ] Startup performance <10s cold, <2s warm
- [ ] Execution performance <5s
- [ ] Ready for manual testing

### Post-Claude Testing (End of Day 5)

- [ ] Works with Claude Desktop
- [ ] All manual tests passing
- [ ] User experience validated
- [ ] Error messages clear
- [ ] No crashes or hangs
- [ ] Performance acceptable in real use

### Final Validation (End of Day 7)

- [ ] All success criteria met
- [ ] Documentation complete
- [ ] Known issues documented
- [ ] Phase 1 planning ready
- [ ] Code is clean and maintainable
- [ ] Ready to proceed to Phase 1

---

## Next Steps After Week 4

### Immediate Next Actions (Week 5+)

If Week 4 succeeds (Phase 0 complete):

1. **Expand App Support** (Week 5)
   - Test with 20+ apps
   - Document app-specific quirks
   - Create workarounds for edge cases
   - Build app compatibility matrix

2. **Enhanced Permission System** (Week 6)
   - Persistent permission storage
   - User preference UI (basic)
   - More granular classification
   - Audit log viewer

3. **Performance Optimization** (Week 7)
   - Profile slow operations
   - Optimize SDEF parsing
   - Optimize tool generation
   - Parallel processing where possible

4. **npm Package Preparation** (Week 8)
   - Package.json finalization
   - npm publish setup
   - CI/CD pipeline
   - Release process

### Phase 1 Decision Point

**After Week 4, evaluate:**

**If Phase 0 succeeded:**
- JITD concept validated ✓
- Proceed to Phase 1 (Months 2-5)
- Focus on expanding app support
- Prepare for open source release

**If Phase 0 revealed issues:**
- Document what worked vs. what didn't
- Determine if issues are solvable
- Decide: Fix and continue, or pivot approach
- Adjust Phase 1 plan accordingly

**Key Questions:**
1. Does JITD work reliably across multiple apps?
2. Is the user experience acceptable?
3. Are there fundamental blockers we didn't anticipate?
4. Is the performance acceptable for real use?
5. Are we confident we can expand to 10-15 apps?

---

## Appendix A: Testing Matrices

### App Discovery Testing Matrix

| App Name | Location | SDEF Present | Should Discover | Notes |
|----------|----------|--------------|-----------------|-------|
| Finder | /System/Library/CoreServices | Yes | Yes | Always present |
| Safari | /Applications | Yes | Yes | Should always find |
| Mail | /Applications | Yes | Yes | Should always find |
| Calendar | /Applications | Yes | Yes | Should always find |
| Notes | /Applications | Yes | Yes | Should always find |
| Reminders | /Applications | Yes | Yes | Should always find |
| Messages | /Applications | Yes | Yes | Should always find |
| Music | /Applications | Yes | Yes | Should always find |
| Photos | /Applications | Yes | Yes | Should always find |
| Contacts | /Applications | Yes | Yes | Should always find |
| Preview | /Applications | Yes | Yes | Should always find |
| TextEdit | /Applications | Yes | Yes | Should always find |
| Chrome | /Applications | Maybe | Maybe | User installed |
| Brave | /Applications | Maybe | Maybe | User installed |
| Spotify | /Applications | No | No | Not scriptable |
| VS Code | /Applications | No | No | Not scriptable |

### Tool Generation Testing Matrix

| App | Expected Command Count | Expected Tool Count | Key Commands |
|-----|----------------------|-------------------|-------------|
| Finder | 20+ | 20+ | open, list, get, move, copy |
| Safari | 10+ | 10+ | get_url, get_title, reload |
| Mail | 15+ | 15+ | send, count, get_mailboxes |
| Calendar | 10+ | 10+ | list_calendars, count_events |
| Notes | 5+ | 5+ | list_notes, create_note |
| Reminders | 5+ | 5+ | list_reminders, create_todo |

### Execution Testing Matrix

| Command | App | Args | Expected Result | Permission Level |
|---------|-----|------|----------------|-----------------|
| list_folder | Finder | path: ~/Desktop | Array of file names | SAFE |
| get_file_info | Finder | path: ~/Documents | File metadata | SAFE |
| open | Finder | target: ~/file.pdf | Opens file | MODIFY |
| get_url | Safari | (none) | Current URL string | SAFE |
| get_title | Safari | (none) | Page title string | SAFE |
| count_messages | Mail | (none) | Number of messages | SAFE |

---

## Appendix B: Error Message Templates

### User-Facing Error Messages

**App Not Found:**
```
Error: The application '{appName}' could not be found.

Suggestion: Please ensure {appName} is installed in /Applications.

Details: {technicalDetails}
```

**Permission Denied:**
```
Error: Permission denied to control {appName}.

Suggestion: Grant automation permission in System Settings:
1. Open System Settings
2. Go to Privacy & Security → Automation
3. Enable Terminal (or Claude Desktop) to control {appName}

Details: {technicalDetails}
```

**Timeout:**
```
Error: The operation timed out after {timeout} seconds.

Suggestion: The app may be busy or unresponsive. Try again or check if {appName} is responding.

Details: {technicalDetails}
```

**Invalid Arguments:**
```
Error: Invalid arguments provided to {toolName}.

Required: {requiredArgs}
Provided: {providedArgs}
Issues: {validationErrors}

Suggestion: Check the parameter types and try again.
```

---

## Appendix C: Performance Targets

### Startup Performance

| Scenario | Target | Acceptable | Notes |
|----------|--------|------------|-------|
| Cold start (no cache) | <10s | <15s | First run only |
| Warm start (cache valid) | <2s | <5s | Most startups |
| Cache invalidation | <10s | <15s | After app updates |

### Execution Performance

| Operation Type | Target | Acceptable | Notes |
|---------------|--------|------------|-------|
| Simple query (Finder list) | <2s | <5s | Most common |
| Complex query | <5s | <10s | Multiple operations |
| Modify operation | <3s | <7s | File operations |
| App launch required | <10s | <15s | If app needs to start |

### Resource Usage

| Resource | Target | Acceptable | Notes |
|----------|--------|------------|-------|
| Memory (startup) | <100MB | <200MB | After initialization |
| Memory (running) | <150MB | <300MB | With cache |
| Cache size | <10MB | <50MB | Depends on app count |

---

## Questions & Clarifications

**Q: Should we implement Resources (ListResources/ReadResource) in Week 4?**
**A:** Optional. Focus on Tools (ListTools/CallTool) first. Resources can be added in Phase 1 if LLMs benefit from seeing app dictionaries.

**Q: What if cache causes more problems than it solves?**
**A:** Include --no-cache flag as escape hatch. If cache is problematic, we can disable by default and make it opt-in.

**Q: Should we test with Ollama or other MCP clients?**
**A:** Focus on Claude Desktop for Phase 0. Testing with other clients comes in Phase 1.

**Q: What if we discover apps don't work as reliably as expected?**
**A:** Document which apps work well, which have quirks. Build workarounds in Phase 1. The key is proving JITD concept works for *most* apps, not all.

**Q: Should we implement user prompts for dangerous operations?**
**A:** Not in Phase 0. For now, permission system just classifies. Claude can tell the user "this requires permission". Full prompting UI comes with native app (Phase 2).

---

## Summary

**Week 4 bridges the gap between "components work in isolation" and "system works end-to-end".**

**Key Activities:**
1. Add caching for fast startup
2. Wire all components together
3. Test exhaustively (automated + manual)
4. Validate with Claude Desktop
5. Polish for production
6. Document everything
7. Validate Phase 0 complete

**Success Looks Like:**
- Claude Desktop discovers and uses 50+ tools across 10+ apps
- Startup is fast (<10s cold, <2s warm)
- Execution is reliable (>95% success rate)
- Errors are clear and helpful
- Documentation is complete
- Ready to expand in Phase 1

**After Week 4:**
- Phase 0 complete: JITD concept proven ✓
- Proceed to Phase 1: Expand to 10-15 apps, polish, prepare for open source release
- Confidence to build native UI (Phase 2)
- Clear path to sustainability and profitability

**This is the final validation before committing to the full 18-month roadmap.**
