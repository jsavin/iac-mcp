# iac-mcp

**Universal bridge between AI/LLMs and native macOS applications**

iac-mcp is an MCP (Model Context Protocol) server that uses Just-In-Time Discovery (JITD) to dynamically discover and orchestrate any installed scriptable macOS application without pre-built integrations.

## Features

- 🔍 **Just-In-Time Discovery**: Automatically discovers installed scriptable apps
- 📝 **SDEF Parsing**: Parses application Scripting Definitions dynamically
- 🛠️ **Tool Generation**: Generates MCP tools from app capabilities
- 🔐 **Permission System**: Safe execution with user-controlled permissions
- 🚀 **Zero Configuration**: Works with apps immediately, no setup required

## Status

**Current Phase**: Phase 0 - Technical Validation

This project is in early development. The goal of Phase 0 is to prove the JITD concept works by:
1. Parsing one SDEF file (Finder)
2. Generating MCP tool definitions
3. Executing commands via JXA
4. Testing with Claude Desktop

See [planning/ROADMAP.md](planning/ROADMAP.md) for the complete 18-month plan.

## Prerequisites

- macOS (Monterey or later recommended)
- Node.js 20+ (LTS)
- TypeScript 5+
- Claude Desktop (for testing)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/iac-mcp.git
cd iac-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

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

- **Phase 0** (Month 1): Technical validation - prove JITD works
- **Phase 1** (Months 2-5): Open source MCP bridge
- **Phase 2** (Months 6-9): Native Swift UI
- **Phase 3** (Months 10-12): Public launch
- **Phase 4** (Months 13-18): Grow to sustainability
- **Phase 5** (18+ months): Windows, accessibility APIs, advanced features

See [planning/ROADMAP.md](planning/ROADMAP.md) for details.

---

**Status**: Phase 0 (Technical Validation) - Proving JITD concept
