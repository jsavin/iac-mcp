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

This project uses **Node.js 20.11.0** (LTS). We provide `.nvmrc` and `.node-version` files for automatic version management.

**Option 1: Using nvm (recommended)**
```bash
# Install nvm if you don't have it
# See: https://github.com/nvm-sh/nvm

# Use the correct Node version (reads .nvmrc automatically)
nvm use

# Or install if you don't have Node 20.11.0
nvm install
```

**Option 2: Using Volta**
```bash
# Volta automatically detects .node-version
# See: https://volta.sh/

# Just cd into the directory and Volta handles it
cd iac-mcp
```

**Option 3: Manual installation**
- Download Node.js 20.11.0 from https://nodejs.org/
- Verify: `node --version` should show `v20.11.0`

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

## Testing with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "iac-bridge": {
      "command": "node",
      "args": ["/absolute/path/to/iac-mcp/dist/index.js"]
    }
  }
}
```

Then restart Claude Desktop.

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

## Roadmap

- **Phase 0** (Month 1): Technical validation - prove JITD works on macOS
- **Phase 1** (Months 2-5): Open source MCP bridge (macOS scriptable apps)
- **Phase 2** (Months 6-9): Native Swift UI (macOS)
- **Phase 3** (Months 10-12): Public launch (macOS)
- **Phase 4** (Months 13-18): Grow to sustainability
- **Phase 5** (18+ months): **Multi-platform expansion**
  - Windows (VBA, COM, Windows Messaging) - 14x market opportunity
  - Accessibility APIs (non-scriptable macOS apps)
  - Linux/cross-platform support
  - Vision AI integration

See [planning/ROADMAP.md](planning/ROADMAP.md) for details.

---

**Status**: Phase 0 (Technical Validation) - Proving JITD concept
