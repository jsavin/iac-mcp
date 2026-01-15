# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Vision

**Building a universal bridge between AI/LLMs and native applications** using Just-In-Time Discovery (JITD) to dynamically discover and orchestrate any installed app without pre-built integrations.

**Core philosophy:** Interoperability above all. Make everything work with everything else. Local-first, user control, no vendor lock-in.

**Strategy:** Bootstrap (no VCs), sustainable growth, open source core + proprietary UI.

**Read the complete vision:** `planning/VISION.md` and `planning/ideas/the-complete-vision.md`

## What We're Building

### Phase 1: MCP Bridge (Open Source Core)
**Current focus:** Node.js/TypeScript MCP server with JITD engine

**Key innovation:** Just-In-Time Discovery (JITD)
- Automatically discovers installed Mac applications
- Parses their SDEF (Scripting Definition) files
- Generates MCP tools dynamically
- Works with any app immediately, no pre-configuration

**Components:**
- JITD engine (discovery, parsing, tool generation)
- macOS platform adapter (AppleEvents via JXA)
- MCP server (stdio protocol)
- Permission system (safe execution)

### Phase 2: Native UI (Proprietary)
**Future:** Swift macOS app with workflow builder
- Hybrid architecture (Swift UI + Node.js backend)
- Visual/conversational workflow creation
- Freemium business model

## Current Development Phase

**Phase 0: Technical Validation** (Weeks 1-4)
- Prove JITD concept works
- Parse Finder SDEF → Generate tools → Execute commands
- Test with Claude Desktop

See `planning/ROADMAP.md` for complete 18-month plan.

## Key Architectural Decisions

**Decided:**
- ✅ Bootstrap (no VC funding)
- ✅ Scriptable apps only for MVP (30-40% coverage)
- ✅ Hybrid tech stack (Swift UI + Node.js backend)
- ✅ Open source core, proprietary UI
- ✅ Freemium: Free tier + subscription pricing Pro

**See:** `planning/DECISIONS.md` for all decisions

## Project Structure (Current/Planned)

```
src/
  index.ts              # MCP server entry point
  jitd/                 # JITD engine
    discovery/          # Find apps, parse SDEF files
    tool-generator/     # SDEF → MCP tools
    cache/              # Cache parsed capabilities
  adapters/             # Platform adapters
    macos/              # macOS AppleEvents/JXA
  mcp/                  # MCP protocol implementation
    server.ts           # MCP server
    tools.ts            # Tool handlers
    resources.ts        # Resource handlers
  permissions/          # Permission system
  types/                # TypeScript types

tests/
  unit/                 # Unit tests
  integration/          # Integration tests

planning/               # Vision, strategy, roadmap
docs/                   # Documentation (future)
```

## Development Commands

**Note:** Project is in early planning/prototype phase. Standard commands will be added as we build.

### When Project is Set Up
```bash
npm install            # Install dependencies
npm run build          # Compile TypeScript
npm test               # Run tests
npm start              # Start MCP server
```

### Testing with Claude Desktop
Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "iac-bridge": {
      "command": "node",
      "args": ["/absolute/path/to/osa-mcp/dist/index.js"]
    }
  }
}
```

## JITD Implementation Notes

### SDEF Parsing
**Location:** SDEF files are in app bundles at `Contents/Resources/*.sdef`

**Example:**
```bash
# Finder's SDEF
/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef
```

**Format:** XML containing:
- Suites (groups of commands)
- Commands (operations with parameters)
- Classes (objects with properties)
- Enumerations (valid values)

**Parser should extract:**
- Command names and descriptions
- Parameter names, types, required/optional
- Return types
- Relationships between classes

### Tool Generation
**SDEF → MCP Tool Mapping:**
```typescript
// SDEF command
<command name="open" code="aevtodoc">
  <parameter name="target" type="file" />
</command>

// Generated MCP tool
{
  name: "finder_open",
  description: "Open the specified file or folder",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "Path to file or folder" }
    },
    required: ["target"]
  }
}
```

### Execution via JXA
**Use JavaScript for Automation (JXA) instead of AppleScript:**
- More reliable than AppleScript strings
- Better error handling
- JSON serialization support
- Modern JavaScript syntax

**Example:**
```javascript
const app = Application("Finder");
const result = app.open(Path("/Users/username/Desktop"));
```

## macOS Platform Notes

### Required Permissions
- **Automation**: Allow Terminal/app to control other apps
- **Accessibility**: May be needed for some operations
- Test permission prompts early

### SDEF File Locations
```bash
# System apps
/System/Library/CoreServices/*.app/Contents/Resources/*.sdef

# User apps
/Applications/*.app/Contents/Resources/*.sdef
~/Applications/*.app/Contents/Resources/*.sdef
```

### Finding Apps with SDEF Support
```bash
# Find all apps with SDEF files
find /Applications -name "*.sdef" 2>/dev/null
find /System/Library/CoreServices -name "*.sdef" 2>/dev/null
```

### Common Scriptable Apps
- Finder
- Mail
- Safari
- Calendar
- Notes
- Reminders
- Messages
- Photos
- Music
- Contacts
- Preview

## MCP Protocol Implementation

### Tools vs Resources Approach

**We use Tools (not pure resources):**
- Dynamically generate MCP tools from discovered app capabilities
- LLM calls typed tools with validated parameters
- More reliable than LLM writing AppleScript strings

### Tool Registration
```typescript
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: generatedTools // From JITD engine
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  // Route to platform adapter for execution
  const result = await adapter.execute(
    request.params.name,
    request.params.arguments
  );
  return { content: [{ type: "text", text: JSON.stringify(result) }] };
});
```

### Resources (Optional)
Expose app dictionaries as resources for LLM to understand capabilities:
```typescript
// Resource: iac://apps/{bundleId}/dictionary
// Returns: Parsed SDEF in LLM-friendly format
```

## Security & Permissions

### Permission Levels
1. **Always safe** (no prompt): Read-only operations
2. **Requires confirmation**: Modifying data, sending messages
3. **Always confirm** (can't bypass): Deleting, quitting apps, shell commands

### Implementation
```typescript
interface PermissionCheck {
  appBundleId: string;
  command: string;
  parameters: object;
  user: {
    alwaysAllow: boolean;  // User granted "always allow"
    blocked: boolean;       // User blocked this operation
  };
  rule: SafetyLevel;        // Global safety rule
}
```

## Common Patterns & Gotchas

### SDEF Parsing
- Not all apps have SDEF files (older apps may use AETE)
- SDEF format can vary (handle gracefully)
- Multiple suites per app (group logically)
- Four-character codes (preserve for AppleEvents)

### Type Mapping
**AppleScript/SDEF types → JSON Schema types:**
- `text` → `string`
- `integer` / `real` → `number`
- `boolean` → `boolean`
- `file` / `alias` → `string` (path)
- `list` → `array`
- `record` → `object`

### Execution
- JXA is asynchronous (handle promises)
- Apps must be installed and may need to be running
- Some commands require apps to be frontmost
- Timeout commands (don't hang forever)

### Error Handling
- AppleScript errors: Parse error codes and messages
- App not found: Graceful failure
- Permission denied: Clear user message
- Invalid parameters: Validate before execution

## Testing Strategy

### Unit Tests
- SDEF parser (parse various SDEF files)
- Tool generator (SDEF → correct tool schemas)
- Type mapper (AppleScript types → JSON)
- Permission checker (classify operations correctly)

### Integration Tests
- End-to-end: Discovery → Tools → Execution
- Test with real apps (Finder, Safari, Mail)
- Permission prompts (mock user responses)
- Error cases (app not found, invalid params)

### Manual Testing
- Use MCP Inspector: `npx @modelcontextprotocol/inspector`
- Test with Claude Desktop
- Try various workflows
- Test permission system

## What to Avoid

### Don't
- ❌ Hard-code app integrations (defeats JITD purpose)
- ❌ Use string-based AppleScript generation (use JXA)
- ❌ Assume all apps have SDEF files (check first)
- ❌ Skip permission checks (safety critical)
- ❌ Block on long-running operations (use timeouts)

### Do
- ✅ Dynamically discover and adapt
- ✅ Cache parsed SDEF files (avoid re-parsing)
- ✅ Validate parameters before execution
- ✅ Handle errors gracefully
- ✅ Test with multiple apps

## Current Priorities

**Phase 0 (Now):** Prove JITD concept
1. Parse one SDEF file (Finder)
2. Generate MCP tool definition
3. Execute via JXA
4. Test with Claude Desktop

**Next:** Build complete MCP bridge (see `planning/ROADMAP.md`)

## Resources & References

### Internal Docs
- `planning/START-HERE.md` - Quick overview and next steps
- `planning/VISION.md` - Complete vision
- `planning/ROADMAP.md` - 18-month development plan
- `planning/DECISIONS.md` - All key decisions
- `planning/ideas/jitd-concept.md` - JITD technical details

### External Resources
- MCP Documentation: https://modelcontextprotocol.io
- JXA Guide: https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/
- SDEF Format: https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ScriptingDefinitions/

## Questions or Blockers?

**Strategic questions:** Review `planning/` docs
**Technical questions:** Check MCP docs or AppleScript/JXA references
**Need to adjust:** Update `planning/DECISIONS.md` and proceed

**Remember:** This is Phase 0. Focus on proving JITD works before building everything.

---

**Status:** Phase 0 (Technical Validation)
**Next milestone:** JITD proof of concept (Finder working end-to-end)
