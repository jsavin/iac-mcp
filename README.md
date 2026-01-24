# iac-mcp

**Universal bridge between AI/LLMs and native applications**

iac-mcp is an MCP (Model Context Protocol) server that uses Just-In-Time Discovery (JITD) to dynamically discover and orchestrate any installed application without pre-built integrations.

## Platform Support

**Current (Phase 1):** macOS
- AppleScript/JXA automation
- SDEF (Scripting Definition) parsing
- Scriptable apps (Finder, Mail, Safari, etc.)

**Planned (Phase 5+):** Multi-platform
- **Windows**: VBA, COM, Windows Messaging
- **Linux**: D-Bus, command-line tools
- **Cross-platform**: Electron apps, web automation

The JITD architecture is designed to work with any platform's native automation capabilities.

## Features

- 🔍 **Just-In-Time Discovery**: Automatically discovers installed apps and their capabilities
- 🛠️ **Dynamic Tool Generation**: Generates MCP tools from app automation interfaces
- 🔐 **Permission System**: Safe execution with user-controlled permissions
- 🚀 **Zero Configuration**: Works with apps immediately, no pre-built integrations
- 🌍 **Platform-Agnostic Design**: Extensible to any platform with native automation

## Status

**Current Phase**: Phase 0 - Technical Validation (macOS)

This project is in early development. The goal of Phase 0 is to prove the JITD concept works on macOS by:
1. Parsing SDEF files (starting with Finder)
2. Generating MCP tool definitions
3. Executing commands via JXA
4. Testing with Claude Desktop

See [planning/ROADMAP.md](planning/ROADMAP.md) for the complete 18-month plan including multi-platform expansion.

## Prerequisites

**For macOS (Phase 1):**
- macOS Monterey or later
- Node.js 20.11+ (LTS) - see [Node Version Management](#node-version-management)
- Claude Desktop (for testing)

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/jsavin/iac-mcp.git
cd iac-mcp

# Install dependencies (uses package-lock.json for exact versions)
npm ci

# Build the project
npm run build

# Verify installation
npm run verify
```

### Node Version Management

This project requires **Node.js 20+**. We recommend Node.js 20.x LTS for stability, but any 20+ version (including 22.x LTS or 25.x Current) works fine.

**Option 1: Using Homebrew (macOS)**
```bash
# Install Node.js LTS
brew install node@20

# Or use the current release (25.x)
brew install node
```

**Option 2: Using nvm (recommended for multiple versions)**
```bash
# Install nvm if you don't have it
# See: https://github.com/nvm-sh/nvm

# Use the LTS version (reads .nvmrc automatically)
nvm use

# Or install if you don't have Node 20+
nvm install 20  # or 'nvm install --lts'
```

**Option 3: Using Volta**
```bash
# Volta automatically detects .node-version
# See: https://volta.sh/

# Just cd into the directory and Volta handles it
cd iac-mcp
```

**Option 4: Manual installation**
- Download from https://nodejs.org/
- Install either LTS (20.x, 22.x) or Current (25.x)
- Verify: `node --version` should show `v20+`

### Dependency Management

We use `package-lock.json` to ensure **everyone gets identical dependencies**:

- **For fresh install:** `npm ci` (faster, stricter, uses lock file)
- **For development:** `npm install` (updates lock file if needed)
- **Never delete** `package-lock.json` - it's committed to git

This prevents "works on my machine" issues from dependency version drift.

## Development

```bash
# Watch mode (rebuilds on file changes)
npm run dev

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Lint code
npm run lint
npm run lint:fix
```

## Testing with MCP Inspector

The MCP Inspector is a browser-based tool for testing MCP servers before integrating with Claude Desktop:

```bash
# Start the MCP Inspector
npx @modelcontextprotocol/inspector node dist/index.js
```

This will open a browser window where you can:
- View available tools
- Test tool execution
- Inspect request/response payloads
- Debug server behavior

## Testing with Claude Desktop

### Step 1: Configure Claude Desktop

1. Locate your Claude Desktop configuration file:
   ```bash
   ~/Library/Application Support/Claude/claude_desktop_config.json
   ```

2. Add the iac-mcp server configuration:
   ```json
   {
     "mcpServers": {
       "iac-mcp": {
         "command": "node",
         "args": ["/absolute/path/to/iac-mcp/dist/index.js"],
         "env": {
           "NODE_ENV": "production"
         }
       }
     }
   }
   ```

3. **Important:** Replace `/absolute/path/to/iac-mcp` with the actual absolute path to your iac-mcp directory.

**Quick way to get the absolute path:**
```bash
cd /path/to/iac-mcp
pwd
# Copy the output and append /dist/index.js
```

**Example configuration:**
```json
{
  "mcpServers": {
    "iac-mcp": {
      "command": "node",
      "args": ["/Users/yourusername/dev/iac-mcp/dist/index.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

**Configuration Template:**
A ready-to-use template is available in `claude_desktop_config.json` at the repository root.

### Step 2: Restart Claude Desktop

1. Completely quit Claude Desktop (Cmd+Q)
2. Relaunch Claude Desktop
3. The iac-mcp server will start automatically

### Step 3: Verify Connection

In a new Claude conversation, you can verify the server is working by asking Claude to list available tools or use the example tool:

```
Can you show me what tools are available from iac-mcp?
```

or

```
Use the example_tool to echo "Hello from Claude Desktop"
```

### Step 4: Monitor Server Logs

Server logs are written to stderr and can be viewed in Claude Desktop's developer console (if available) or by running the server manually:

```bash
node dist/index.js
# Then interact with Claude Desktop
# Logs will appear in this terminal
```

### Troubleshooting Claude Desktop Integration

**Problem: Server not appearing in Claude Desktop**

1. Verify the config file path is correct
2. Check that the absolute path to `dist/index.js` is correct
3. Ensure the project is built: `npm run build`
4. Check for syntax errors in the JSON config file
5. Restart Claude Desktop completely

**Problem: Tools not showing up**

1. Test with MCP Inspector first to verify the server works
2. Check Claude Desktop logs/console for errors
3. Verify Node.js version: `node --version` (must be 20+)

**Problem: Tool execution fails**

1. Check server logs for error messages
2. Verify the tool is being called with correct parameters
3. Test the same tool call in MCP Inspector to isolate the issue

For comprehensive testing procedures, see [docs/MANUAL-TESTING.md](docs/MANUAL-TESTING.md).

## Project Structure

```
src/
├── index.ts              # MCP server entry point
├── jitd/                 # JITD engine
│   ├── discovery/        # App discovery and SDEF parsing
│   ├── tool-generator/   # MCP tool generation
│   └── cache/            # Capability caching
├── adapters/             # Platform adapters
│   └── macos/            # macOS JXA/AppleEvents
├── mcp/                  # MCP protocol implementation
│   ├── server.ts         # MCP server setup
│   └── tools.ts          # Tool handlers
├── permissions/          # Permission system
└── types/                # TypeScript type definitions

planning/                 # Vision, strategy, roadmap
tests/                    # Unit and integration tests
tools/                    # Development helper scripts
```

## Documentation

- [Vision](planning/VISION.md) - Project vision and philosophy
- [Roadmap](planning/ROADMAP.md) - 18-month development plan
- [Start Here](planning/START-HERE.md) - Quick start guide
- [Decisions](planning/DECISIONS.md) - Architectural decisions
- [CLAUDE.md](CLAUDE.md) - Development workflow and patterns

## Philosophy

**Interoperability above all.** Make everything work with everything else.

- Local-first: Your apps, your data, your control
- No vendor lock-in: Open standards (MCP), open source core
- Universal: Works with any scriptable app, not just popular ones
- Zero configuration: Discovers capabilities automatically

## License

MIT - see [LICENSE](LICENSE) for details

## Contributing

This project is in early development. Contributions welcome once Phase 0 is complete.

## Open Source Roadmap

- **Phase 0** (Month 1): Technical validation - prove JITD works on macOS
- **Phase 1** (Months 2-5): Open source MCP bridge (macOS scriptable apps)

See [planning/ROADMAP.md](planning/ROADMAP.md) for details.

---

**Status**: Phase 0 (Technical Validation) - Proving JITD concept
