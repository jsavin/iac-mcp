# MVP Implementation Plan

## Goal: Ship Open Source MCP Bridge in 2-3 Months

**Target:** Working MCP server with JITD for macOS scriptable apps
**Distribution:** npm package + GitHub repository
**Timeline:** 8-12 weeks (accelerated from original 16-week plan)

---

## Phase 0: Technical Validation (Weeks 1-2)

### Week 1: SDEF Parsing Prototype

**Objective:** Parse one SDEF file and extract structured data

**Tasks:**
- [x] Set up Node.js/TypeScript project
- [ ] Find Finder.app SDEF file (`/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef`)
- [ ] Parse XML using Node.js (xml2js or fast-xml-parser)
- [ ] Extract commands, parameters, classes, enumerations
- [ ] Output structured JSON representation

**Deliverable:** JSON file with Finder's parsed capabilities

**Validation:**
```bash
# Should output structured JSON
node dist/prototype/parse-sdef.js /path/to/Finder.sdef > finder-capabilities.json
```

### Week 2: Tool Generation & Execution Prototype

**Objective:** Generate MCP tool and execute via JXA

**Tasks:**
- [ ] Create MCP tool definition generator
- [ ] Map SDEF types to JSON Schema types
- [ ] Build minimal MCP server (stdio transport)
- [ ] Implement JXA execution layer
- [ ] Test with Claude Desktop manually

**Deliverable:** Working proof of concept

**Validation:**
- Claude Desktop can call `finder_list_folder` tool
- Tool executes and returns results
- JITD concept proven ✓

---

## Phase 1: Core MCP Bridge (Weeks 3-10)

### Week 3-4: Project Foundation

**Repository Structure:**
```
osa-mcp/
├── src/
│   ├── index.ts              # MCP server entry point
│   ├── jitd/
│   │   ├── discovery.ts      # Find apps with SDEF files
│   │   ├── parser.ts         # Parse SDEF XML
│   │   ├── generator.ts      # Generate MCP tools
│   │   └── cache.ts          # Cache manager
│   ├── adapters/
│   │   └── macos.ts          # macOS JXA execution
│   ├── mcp/
│   │   ├── server.ts         # MCP protocol implementation
│   │   └── types.ts          # MCP type definitions
│   ├── permissions/
│   │   └── checker.ts        # Permission system
│   └── utils/
│       ├── types.ts          # Type mappings
│       └── logger.ts         # Logging
├── tests/
│   ├── unit/
│   └── integration/
├── examples/                  # Example usage
├── docs/                      # Documentation
├── package.json
├── tsconfig.json
├── README.md
└── LICENSE                    # MIT or Apache 2.0
```

**Setup Tasks:**
- [ ] Initialize npm package
- [ ] Configure TypeScript (ES2022, strict mode)
- [ ] Set up testing (Jest or Vitest)
- [ ] Set up linting (ESLint + Prettier)
- [ ] Create basic README

**Dependencies:**
```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0",
    "fast-xml-parser": "^4.3.0",
    "zod": "^3.22.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.3.0",
    "tsx": "^4.7.0",
    "vitest": "^1.2.0",
    "eslint": "^8.56.0",
    "prettier": "^3.2.0"
  }
}
```

### Week 5-6: Discovery & Parsing

**Discovery System:**
```typescript
// src/jitd/discovery.ts
export class AppDiscoverer {
  private searchPaths = [
    '/Applications',
    '/System/Library/CoreServices',
    '~/Applications'
  ];

  async discover(): Promise<DiscoveredApp[]> {
    // 1. Scan directories for .app bundles
    // 2. Check each for SDEF file (Contents/Resources/*.sdef)
    // 3. Return list of apps with SDEF paths
  }

  async watchForChanges(callback: (change: AppChange) => void): void {
    // Use chokidar to watch for app installations/removals
  }
}
```

**SDEF Parser:**
```typescript
// src/jitd/parser.ts
export class SDEFParser {
  async parse(sdefPath: string): Promise<ParsedSDEF> {
    // 1. Read SDEF XML file
    // 2. Parse with fast-xml-parser
    // 3. Extract suites, commands, classes, enums
    // 4. Return structured representation
  }

  private extractCommands(suite: any): Command[] {
    // Parse <command> elements
    // Extract name, code, description, parameters, return type
  }
}
```

**Cache System:**
```typescript
// src/jitd/cache.ts
export class CapabilityCache {
  private cachePath = '~/.osa-mcp/cache.json';

  async load(): Promise<CachedData> {
    // Load cached app capabilities
  }

  async save(apps: DiscoveredApp[]): Promise<void> {
    // Save to disk for fast startup
  }

  needsRefresh(app: DiscoveredApp): boolean {
    // Check if app version or SDEF modified time changed
  }
}
```

**Tasks:**
- [ ] Implement app discovery (scan directories)
- [ ] Implement SDEF parser (XML → structured data)
- [ ] Implement cache system (JSON storage)
- [ ] Add file watching for app changes
- [ ] Unit tests for parser (test with 3-5 real SDEF files)

### Week 7-8: Tool Generation & Execution

**Tool Generator:**
```typescript
// src/jitd/generator.ts
export class ToolGenerator {
  generate(apps: DiscoveredApp[]): MCPTool[] {
    // For each app, for each command:
    // 1. Create tool name (app_command)
    // 2. Map parameters to JSON schema
    // 3. Generate tool definition
  }

  private mapType(sdefType: string): JSONSchemaType {
    // text → string
    // integer/real → number
    // file/alias → string (path)
    // list → array
    // record → object
  }
}
```

**macOS Adapter:**
```typescript
// src/adapters/macos.ts
export class MacOSAdapter {
  async execute(appId: string, command: string, params: Record<string, any>): Promise<any> {
    // 1. Build JXA script
    // 2. Execute via osascript
    // 3. Parse result
    // 4. Return to MCP
  }

  private buildJXA(appId: string, command: string, params: any): string {
    // Generate JXA code from structured parameters
    // Example: Application("Finder").desktop.items()
  }

  private executeJXA(script: string): Promise<string> {
    // Use child_process to run: osascript -l JavaScript -e "script"
  }
}
```

**Tasks:**
- [ ] Implement tool generator (SDEF → MCP tools)
- [ ] Implement type mapping (AppleScript → JSON Schema)
- [ ] Implement JXA adapter (execution layer)
- [ ] Add timeout and error handling
- [ ] Integration tests (execute on real apps)

### Week 9: MCP Server Integration

**MCP Server:**
```typescript
// src/mcp/server.ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

export class IACMCPServer {
  private server: Server;
  private discoverer: AppDiscoverer;
  private generator: ToolGenerator;
  private adapter: MacOSAdapter;

  async initialize() {
    // 1. Discover apps
    // 2. Generate tools
    // 3. Register handlers
    // 4. Start server
  }

  private setupHandlers() {
    // ListTools handler
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.generatedTools
    }));

    // CallTool handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const result = await this.executeTool(request.params.name, request.params.arguments);
      return { content: [{ type: 'text', text: JSON.stringify(result) }] };
    });
  }
}
```

**Tasks:**
- [ ] Implement MCP server setup
- [ ] Register ListTools handler
- [ ] Register CallTool handler
- [ ] Add error handling and logging
- [ ] Test with MCP Inspector

### Week 10: Permission System & Polish

**Basic Permissions:**
```typescript
// src/permissions/checker.ts
export class PermissionChecker {
  check(appId: string, command: string): PermissionLevel {
    // Classify operations:
    // - Read-only: always allow
    // - Modify: prompt (TODO: implement prompting)
    // - Delete/quit: always prompt
  }

  private isDangerous(command: string): boolean {
    return /delete|remove|quit|shutdown|trash/.test(command);
  }
}
```

**Tasks:**
- [ ] Implement basic permission checker
- [ ] Add dangerous operation detection
- [ ] Document permission requirements
- [ ] Add README with usage examples
- [ ] Create example scripts

**Polish:**
- [ ] Add CLI flags (--help, --version, --cache-dir)
- [ ] Improve error messages
- [ ] Add debug logging
- [ ] Performance optimization

---

## Phase 2: Testing & Documentation (Week 11)

### Testing Strategy

**Unit Tests (Vitest):**
```typescript
// tests/unit/parser.test.ts
describe('SDEFParser', () => {
  it('should parse Finder SDEF correctly', async () => {
    const parser = new SDEFParser();
    const result = await parser.parse('./fixtures/Finder.sdef');
    expect(result.suites).toHaveLength(1);
    expect(result.commands).toContainEqual(
      expect.objectContaining({ name: 'open' })
    );
  });
});
```

**Integration Tests:**
```typescript
// tests/integration/finder.test.ts
describe('Finder Integration', () => {
  it('should list desktop items', async () => {
    const adapter = new MacOSAdapter();
    const result = await adapter.execute(
      'com.apple.finder',
      'list_folder',
      { path: '~/Desktop' }
    );
    expect(Array.isArray(result)).toBe(true);
  });
});
```

**MCP Inspector Testing:**
```bash
# Manual testing with MCP Inspector
npx @modelcontextprotocol/inspector node dist/index.js
```

### Documentation

**README.md:**
```markdown
# IAC MCP Bridge

Just-In-Time Discovery (JITD) MCP server for macOS native applications.

## Features
- Automatic discovery of scriptable Mac apps
- Dynamic tool generation from SDEF files
- Works with any app that supports AppleScript
- Zero configuration required

## Installation
npm install -g iac-mcp

## Usage
[Usage examples]

## Supported Clients
- Claude Desktop
- Claude Code
- Cursor
- Any MCP-compatible client

## Contributing
[Contribution guide]
```

**docs/:**
- [ ] Getting Started guide
- [ ] Architecture overview
- [ ] API documentation
- [ ] Troubleshooting guide
- [ ] Contributing guidelines

---

## Phase 3: Publishing & Distribution (Week 12)

### npm Package Setup

**package.json:**
```json
{
  "name": "iac-mcp",
  "version": "0.1.0",
  "description": "MCP server for macOS native application automation with Just-In-Time Discovery",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "bin": {
    "iac-mcp": "dist/cli.js"
  },
  "files": [
    "dist",
    "README.md",
    "LICENSE"
  ],
  "scripts": {
    "build": "tsc",
    "test": "vitest",
    "prepublishOnly": "npm run build && npm test"
  },
  "keywords": [
    "mcp",
    "model-context-protocol",
    "macos",
    "applescript",
    "automation",
    "jxa",
    "claude",
    "ai"
  ],
  "author": "Your Name",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/yourusername/iac-mcp"
  }
}
```

### Publishing Steps

**1. Prepare for Release:**
```bash
# Ensure clean state
npm run lint
npm test
npm run build

# Version bump
npm version patch  # or minor, major
```

**2. Publish to npm:**
```bash
# First time: login
npm login

# Publish
npm publish

# Or publish as scoped package
npm publish --access public
```

**3. GitHub Release:**
```bash
# Tag the release
git tag v0.1.0
git push origin v0.1.0

# Create GitHub release with changelog
gh release create v0.1.0 --generate-notes
```

### Distribution Channels

**npm Registry:**
- Primary distribution method
- Easy `npm install -g iac-mcp`
- Automatic updates via npm

**GitHub Releases:**
- Source code distribution
- Release notes and changelog
- Binary releases (future: pkg or similar)

**Homebrew (Future):**
```ruby
# Formula for Homebrew
class IacMcp < Formula
  desc "MCP server for macOS native app automation"
  homepage "https://github.com/yourusername/iac-mcp"
  url "https://github.com/yourusername/iac-mcp/archive/v0.1.0.tar.gz"
  # ...
end
```

---

## Client Integration Guides

### 1. Claude Desktop

**Location:** `~/Library/Application Support/Claude/claude_desktop_config.json`

**Configuration:**
```json
{
  "mcpServers": {
    "iac-bridge": {
      "command": "npx",
      "args": ["-y", "iac-mcp"]
    }
  }
}
```

**Alternative (global install):**
```json
{
  "mcpServers": {
    "iac-bridge": {
      "command": "iac-mcp"
    }
  }
}
```

**Testing:**
1. Edit config file
2. Restart Claude Desktop
3. Ask Claude: "What apps can you control on my Mac?"
4. Try: "List the files on my desktop"

### 2. Claude Code (VS Code Extension)

**Location:** VS Code settings or `.claude/config.json`

**Configuration:**
```json
{
  "mcp": {
    "servers": {
      "iac-bridge": {
        "command": "npx",
        "args": ["-y", "iac-mcp"]
      }
    }
  }
}
```

**Usage:**
- Open Command Palette: "Claude: Manage MCP Servers"
- Add iac-mcp
- Restart VS Code

### 3. Cursor

**Location:** Cursor settings (Settings → Claude → MCP Servers)

**Configuration (UI):**
- Open Settings
- Navigate to Claude section
- Add MCP Server:
  - Name: IAC Bridge
  - Command: `npx`
  - Args: `-y iac-mcp`

**Configuration (JSON):**
```json
{
  "cursor.mcpServers": {
    "iac-bridge": {
      "command": "npx",
      "args": ["-y", "iac-mcp"]
    }
  }
}
```

### 4. Codeium / Codex

**Note:** MCP support varies by client

**If supported via config file:**
```json
{
  "mcp_servers": {
    "iac-bridge": {
      "command": "npx",
      "args": ["-y", "iac-mcp"]
    }
  }
}
```

**If not natively supported:**
- May require wrapper or proxy
- Check client documentation for extension points

### 5. Gemini CLI / Google AI Studio

**Status:** Check if MCP protocol is supported

**Potential approaches:**
- If API-based: Need MCP-to-API adapter
- If local: May support stdio MCP servers
- Check Google's AI SDK documentation

**Example (if supported):**
```bash
# Set environment variable for MCP server
export MCP_SERVERS='{"iac-bridge":{"command":"npx","args":["-y","iac-mcp"]}}'
gemini-cli
```

### 6. LM Studio

**Location:** Settings → Advanced → Model Context Protocol

**Configuration:**
1. Open LM Studio
2. Go to Settings → Advanced
3. Enable MCP support
4. Add server:
   ```json
   {
     "name": "IAC Bridge",
     "command": "npx",
     "args": ["-y", "iac-mcp"]
   }
   ```

**Alternative:** Direct execution
```bash
# Start MCP server
iac-mcp &

# Configure LM Studio to connect via stdio
```

### 7. Ollama + MCP Bridge

**Status:** Ollama doesn't natively support MCP (as of Jan 2026)

**Workaround Options:**

**Option A: Use Ollama with MCP-compatible client**
```bash
# Use a client that supports both Ollama and MCP
# Example: Custom client or wrapper
```

**Option B: Build MCP-to-Ollama bridge**
```typescript
// Custom bridge that:
// 1. Connects to our MCP server
// 2. Formats for Ollama's API
// 3. Routes tool calls
```

**Option C: Wait for native support**
- Track Ollama repository for MCP integration
- Community may build plugins

### 8. Open WebUI (Ollama Frontend)

**If Open WebUI adds MCP support:**
```yaml
# docker-compose.yml or config
mcp_servers:
  iac-bridge:
    command: npx
    args: ["-y", "iac-mcp"]
```

### 9. Generic MCP Client Integration

**For any MCP-compatible client:**

**Method 1: npx (no installation)**
```json
{
  "command": "npx",
  "args": ["-y", "iac-mcp"]
}
```

**Method 2: Global install**
```bash
npm install -g iac-mcp
```
```json
{
  "command": "iac-mcp"
}
```

**Method 3: Local project**
```bash
npm install iac-mcp
```
```json
{
  "command": "node_modules/.bin/iac-mcp"
}
```

---

## Documentation Structure

### README.md
```markdown
# IAC MCP Bridge

## Quick Start
npm install -g iac-mcp

## Usage with Claude Desktop
[Config example]

## Usage with Other Clients
[Links to guides]

## Features
- JITD (Just-In-Time Discovery)
- Automatic tool generation
- 100+ macOS apps supported

## Examples
[Common workflows]
```

### docs/clients/
- `claude-desktop.md` - Detailed Claude Desktop setup
- `cursor.md` - Cursor integration
- `vscode.md` - VS Code / Claude Code
- `lm-studio.md` - LM Studio setup
- `ollama.md` - Ollama integration (when available)
- `generic.md` - Generic MCP client guide

### docs/development/
- `architecture.md` - System architecture
- `contributing.md` - How to contribute
- `testing.md` - Testing guide
- `debugging.md` - Debugging tips

### docs/guides/
- `getting-started.md` - First steps
- `supported-apps.md` - List of tested apps
- `troubleshooting.md` - Common issues
- `permissions.md` - macOS permissions guide

---

## Launch Strategy

### Week 12: Public Launch

**Day 1-2: Soft Launch**
- [ ] Publish to npm
- [ ] Create GitHub release
- [ ] Update README with installation instructions
- [ ] Test installation on fresh machine

**Day 3: Community Launch**
- [ ] Post to Hacker News (Show HN: JITD for macOS app automation)
- [ ] Post to Reddit (r/MacOS, r/ClaudeAI, r/LocalLLaMA)
- [ ] Share on Twitter/X with demo video
- [ ] Post in MCP Discord/community

**Day 4-5: Content**
- [ ] Blog post: "Building JITD for MCP"
- [ ] Demo video (3-5 minutes on YouTube)
- [ ] Share on Product Hunt (if appropriate)

**Day 6-7: Engagement**
- [ ] Respond to issues and questions
- [ ] Gather feedback
- [ ] Make quick fixes if needed
- [ ] Update documentation based on feedback

### Success Metrics (Week 12)

**Technical:**
- [ ] npm package published
- [ ] 100+ npm downloads
- [ ] 50+ GitHub stars
- [ ] 5+ successful user reports

**Quality:**
- [ ] Works with 10-15 apps reliably
- [ ] No critical bugs reported
- [ ] Documentation clear and complete
- [ ] Positive community feedback

---

## Post-Launch: Weeks 13-16

### Iteration & Improvement

**Based on feedback:**
- Add most-requested app support
- Fix bugs and edge cases
- Improve documentation
- Add examples and tutorials

**Community building:**
- Create discussions on GitHub
- Share user workflows
- Encourage contributions
- Build ecosystem

**Prepare for Phase 2:**
- Start planning Swift UI wrapper
- Validate business model interest
- Gather feature requests
- Plan Windows version

---

## Risk Mitigation

### Technical Risks

**Risk: SDEF parsing fails for some apps**
- Mitigation: Test with 20+ apps, handle edge cases
- Fallback: Manual overrides for problematic apps

**Risk: JXA execution unreliable**
- Mitigation: Extensive testing, timeout handling
- Fallback: Option to use AppleScript instead

**Risk: Performance issues**
- Mitigation: Caching, lazy loading, profiling
- Target: < 5s startup, < 200ms per tool call

### Distribution Risks

**Risk: npm package rejected**
- Mitigation: Follow npm guidelines, valid license
- Fallback: GitHub releases, manual installation

**Risk: Low adoption**
- Mitigation: Clear docs, demo video, community engagement
- Pivot: Focus on specific use case (developer tools)

**Risk: Negative feedback**
- Mitigation: Respond quickly, fix issues, iterate
- Acceptance: MVP won't be perfect, iterate based on feedback

---

## Timeline Summary

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1 | Prototype | SDEF parser working |
| 2 | Prototype | JITD proof of concept |
| 3-4 | Foundation | Project setup, structure |
| 5-6 | Core | Discovery & parsing |
| 7-8 | Core | Tool generation & execution |
| 9 | Integration | MCP server working |
| 10 | Polish | Permissions, documentation |
| 11 | Testing | Comprehensive tests |
| 12 | Launch | npm publish, public release |

**Total: 12 weeks to public launch**

---

## Success Criteria

### Phase 0 Success (Week 2)
- ✅ SDEF parser works for Finder
- ✅ Can generate MCP tool
- ✅ Can execute via JXA
- ✅ Claude Desktop can call tool
- **Decision: Proceed to Phase 1**

### Phase 1 Success (Week 10)
- ✅ Discovers 10-15 Mac apps automatically
- ✅ Generates tools for all discovered apps
- ✅ Executes commands reliably (>90% success)
- ✅ Works with Claude Desktop
- ✅ Basic permission system
- **Decision: Proceed to documentation and launch**

### Launch Success (Week 12)
- ✅ Published on npm
- ✅ 100+ downloads in first week
- ✅ 50+ GitHub stars
- ✅ Positive community feedback
- ✅ At least 5 users successfully using it
- **Decision: Continue with Phase 2 (UI wrapper)**

---

## Next Immediate Actions

### This Week
1. Set up project repository
2. Initialize npm package
3. Start Week 1 prototype (SDEF parsing)

### Week 1 Checklist
- [ ] Set up TypeScript project
- [ ] Add xml2js or fast-xml-parser
- [ ] Locate Finder.sdef file
- [ ] Parse XML and extract structure
- [ ] Output JSON representation
- [ ] Validate: Can we extract all commands?

**Let's start building! 🚀**
