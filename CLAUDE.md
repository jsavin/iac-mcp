# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Vision

**Building a universal bridge between AI/LLMs and native applications** using Just-In-Time Discovery (JITD) to dynamically discover and orchestrate any installed app without pre-built integrations.

**Core philosophy:** Interoperability above all. Make everything work with everything else. Local-first, user control, no vendor lock-in.

**Strategy:** Bootstrap (no VCs), sustainable growth, open source core + proprietary UI.

**Platform Strategy:**
- **Phase 1**: macOS (AppleScript/JXA, SDEF parsing)
- **Phase 5+**: Multi-platform (Windows VBA/COM, Linux D-Bus, cross-platform)
- JITD architecture designed for any platform's native automation

**Read the complete vision:** `planning/VISION.md` and `planning/ideas/the-complete-vision.md`

---

## Quick Reference

### Essential Commands

```bash
# Development
npm install            # Install dependencies
npm run build          # Compile TypeScript
npm run dev            # Development mode with watch
npm test               # Run tests
npm start              # Start MCP server

# Testing
npm run test:unit      # Unit tests only
npm run test:integration  # Integration tests
npx @modelcontextprotocol/inspector node dist/index.js  # MCP Inspector

# Git workflow
git worktree add ../iac-mcp-<feature> -b feature/<name>  # Create worktree
git push origin feature/<name>  # Push feature branch (NEVER push to origin/main)
```

### Documentation Quick Links

- **[Code Quality Standards](CODE-QUALITY.md)** - **MANDATORY** testing and DRY principles
- **[Vision](planning/VISION.md)** - Complete project vision
- **[Roadmap](planning/ROADMAP.md)** - 18-month plan with phases
- **[Start Here](planning/START-HERE.md)** - New contributor guide
- **[Decisions](planning/DECISIONS.md)** - All key decisions documented
- **[MVP Plan](planning/MVP-IMPLEMENTATION.md)** - Current phase implementation

---

## 🚀 LAUNCH STRATEGY (Critical Path for Bootstrapped Startup)

**Core Vision:** Every scriptable Mac app available via an MCP tool.

**Launch Definition:** MCP server that discovers all installed scriptable apps and exposes their commands as Claude-callable tools.

### Coverage Prioritization for Launch

**The vision lives or dies on MCP server quality.** Not on metrics, not on CLI, not on every line of code being tested.

**CRITICAL PATH (100% coverage required before launch):**
- `src/mcp/server.ts` - Server initialization, ListTools, CallTool handlers
- `src/mcp/handlers.ts` - Tool execution, error handling, response formatting
- `src/index.ts` - Entry point

**Tests must verify:**
- ✅ Every scriptable app is discovered (ListTools completeness)
- ✅ Every app's commands become MCP tools
- ✅ Tool execution works end-to-end (Claude → MCP → App → Result)
- ✅ Error handling is graceful (app not found, permission denied, timeout)
- ✅ Server is stable under load (no hangs/crashes)
- ✅ Performance is acceptable (<5s for listing, <5s for execution)

**NOT required before launch:**
- Phase 4 metrics/coverage analysis (important for post-launch optimization)
- CLI testing (library is the primary distribution, not CLI)
- Type definition tests (can't meaningfully test runtime behavior of types)
- Example code (not customer-facing)

---

## 📂 Private Business Documentation

**CRITICAL: Keep business-sensitive information out of the public repository.**

### Storage Location for Private Docs

**ALL private business documents MUST be stored at:**
```
~/Documents/Personal/Coules Labs/IAC-MCP/
```

### What Belongs in Private Docs (NOT in repo)

- ❌ Business strategy details (pricing, monetization, competitive analysis)
- ❌ User-facing product roadmap (phases involving end-users, not developers)
- ❌ Marketing plans and go-to-market strategy
- ❌ Partnership discussions and negotiations
- ❌ Financial projections and funding plans
- ❌ Customer research and feedback
- ❌ Competitive intelligence
- ❌ Any information that could reveal business strategy to competitors

### What Belongs in Public Repo

- ✅ Technical architecture and design decisions
- ✅ Developer-facing implementation plans
- ✅ Code quality standards and testing requirements
- ✅ API documentation and protocol specifications
- ✅ Open source contribution guidelines
- ✅ Technical roadmap (implementation phases, not business phases)

### Protocol for Removing Sensitive Content

If sensitive business content accidentally appears in:
1. **README or public docs**: Remove immediately, update with technical-only content
2. **Commit messages**: Be cautious - commits are permanent in git history
3. **Planning docs**: Move to `~/Documents/Personal/Coules Labs/IAC-MCP/`

**When in doubt**: If it reveals business strategy, pricing, or market positioning → keep it private.

---

## ⚠️ MANDATORY: Code Quality Standards

**READ THIS FIRST:** [CODE-QUALITY.md](CODE-QUALITY.md)

### Non-Negotiable Requirements

Every contribution MUST meet these standards:

1. **100% Test Coverage**
   - NOT 90%. NOT 95%. **100%**.
   - Combination of unit + integration tests
   - CI enforced - PRs blocked if < 100%
   - Rationale: Enable development without manual code inspection

2. **Zero Code Duplication**
   - No duplicated logic anywhere
   - If you see same code twice → refactor immediately
   - Automated detection via jscpd
   - Pre-commit hook enforced

3. **DRY Principle (Don't Repeat Yourself)**
   - Extract shared code to `src/utils/` or module `common.ts`
   - Parameterize variations
   - Delete duplicates completely

**Quick checks before committing:**
```bash
npm run test:coverage  # Must show 100% for all metrics
npx jscpd src/        # Must show zero duplications
npm run lint          # Must pass with no errors
```

**See [CODE-QUALITY.md](CODE-QUALITY.md) for complete standards, enforcement, and examples.**

---

## ⚠️ MANDATORY: Pre-Work Location Verification

**STOP AND VERIFY BEFORE STARTING ANY WORK**

Before writing code, making changes, or committing ANYTHING, you MUST verify your location and branch:

```bash
pwd && git branch --show-current
```

### Decision Tree: Where Should I Work?

```
┌─────────────────────────────────────────┐
│ Am I about to start coding work?       │
└──────────────┬──────────────────────────┘
               │
               ▼
       ┌───────────────┐
       │ Is it TRIVIAL?│ (single-line typo, doc fix)
       └───┬───────────┘
           │
    ┌──────┴──────┐
    │             │
   YES           NO
    │             │
    │             ▼
    │      ┌─────────────────────────┐
    │      │ Am I on main branch?  │
    │      └──────┬──────────────────┘
    │             │
    │      ┌──────┴──────┐
    │      │             │
    │     YES           NO (already on feature branch)
    │      │             │
    │      │             ▼
    │      │      ┌──────────────────┐
    │      │      │ Am I in worktree?│
    │      │      └──────┬───────────┘
    │      │             │
    │      │      ┌──────┴──────┐
    │      │      │             │
    │      │     YES           NO
    │      │      │             │
    │      ▼      ▼             ▼
    │   ┌───────────────┐   ┌─────────────────┐
    │   │ STOP!         │   │ STOP!           │
    │   │ Create        │   │ Create worktree │
    │   │ worktree      │   │ for this branch │
    │   │ & branch NOW  │   └─────────────────┘
    │   └───────────────┘
    │
    ▼
┌──────────────────────────┐
│ OK to proceed            │
│ - Trivial on main OR   │
│ - Non-trivial in worktree│
└──────────────────────────┘
```

### Pre-Work Checklist (MANDATORY)

Before **EVERY** coding session:

1. ✅ **Verify location and branch**
   ```bash
   pwd && git branch --show-current
   ```

2. ✅ **Evaluate task complexity**
   - Trivial: Single-line fix, typo, quick doc update → OK on main
   - Non-trivial: Feature, bug fix, multi-file change → MUST use worktree

3. ✅ **If non-trivial AND on main → STOP**
   ```bash
   # From main iac-mcp directory
   cd /Users/jake/dev/jsavin/iac-mcp
   git worktree add ../iac-mcp-<feature-name> -b feature/<feature-name>
   cd ../iac-mcp-<feature-name>
   # NOW start work here
   ```

4. ✅ **If already in worktree → Verify it's the right one**
   ```bash
   # Should show: /Users/jake/dev/jsavin/iac-mcp-<feature-name>
   # Should show: * feature/<feature-name>
   ```

### Commit Verification (MANDATORY)

Before **EVERY** commit:

1. ✅ **Verify you're in the right place**
   ```bash
   pwd && git branch --show-current
   ```

2. ✅ **Check output:**
   - `/Users/jake/dev/jsavin/iac-mcp` + `main` → ONLY if user explicitly said "commit to main"
   - `/Users/jake/dev/jsavin/iac-mcp-<name>` + `feature/*` → ✅ CORRECT for non-trivial work
   - Anything else → STOP AND ASK USER

3. ✅ **Never push to origin/main directly** (use PR workflow)

### Why This Matters

**Violating this process causes:**
- ❌ Commits bypass PR review
- ❌ Work not properly tracked in GitHub
- ❌ No visibility for user on what's changing
- ❌ Breaks the documented workflow
- ❌ Makes merge conflicts more likely

**Following this process ensures:**
- ✅ All non-trivial work reviewed before merge
- ✅ User has visibility and approval control
- ✅ Clean git history with proper PR documentation

---

## Technical Decision-Making Principles

**When evaluating multiple approaches to solve a problem, default to the proper, maintainable, long-term solution.**

This project is building foundational infrastructure for AI-native app automation. Quick fixes and workarounds accumulate as technical debt that becomes costly to unwind later.

**Decision Framework:**

When presented with options like:
- **Option 1: Quick Fix** (90% solution, fast)
- **Option 2: Proper Solution** (100% solution, maintainable)
- **Option 3: Workaround** (temporary band-aid)

**Default to the proper fix (Option 2) unless:**
- User explicitly requests quick fix for time constraints
- Proper fix would block critical path work (then quick fix + filed issue)
- Quick fix is genuinely the right long-term solution (rare)

**In 90% of cases, recommend the "Proper fix" or "maintainable long-term solution" approach.**

---

## Communication Standards

### Privacy & Entity References

**NEVER mention specific people or entities** (partnerships, companies, individuals, etc.) unless the user explicitly asks. This includes in commit messages, PR descriptions, code comments, and documentation. Keep communications focused on technical details.

**Rationale**: Strategic relationships are user-managed information. Technical work should focus on implementation.

### Commit Messages

**Format:**
```bash
# Use imperative mood and HEREDOC for multi-line
git commit -m "$(cat <<'EOF'
Add SDEF parser with XML validation

- Extract commands, parameters, and classes
- Handle malformed XML gracefully
- Cache parsed results

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Worktree Workflow

**Rule:** All non-trivial work happens in worktrees, NOT in main directory.

### Creating Worktrees

```bash
# From main iac-mcp directory
cd /Users/jake/dev/jsavin/iac-mcp
git worktree add ../iac-mcp-<feature-name> -b feature/<feature-name>
cd ../iac-mcp-<feature-name>
# Start work here
```

### Worktree Naming Convention

```
main-repo/ → iac-mcp-feature-name/

feature/jxa-executor → iac-mcp-jxa-executor
feature/permission-system → iac-mcp-permission-system
fix/sdef-parser → iac-mcp-sdef-parser
```

### Why Worktrees

- ✅ Complete isolation (build artifacts, git state)
- ✅ No git interference (worktrees don't appear in main repo status)
- ✅ IDE-friendly (each appears as separate project)
- ✅ Clear naming pattern
- ✅ Easy cleanup when done

### Cleaning Up Worktrees

```bash
# When feature is merged and pushed
cd /Users/jake/dev/jsavin/iac-mcp
git worktree remove ../iac-mcp-<feature-name>

# Or use /tidy skill after PR is merged
```

---

## PR Workflow

**Protocol:**
1. Create feature branch in worktree
2. Implement and commit work (multiple commits OK)
3. **BEFORE FIRST PUSH: Run tests** ⚠️
   ```bash
   npm test  # All tests must pass
   ```
4. Push feature branch to origin
   ```bash
   git push origin feature/<branch-name>
   # NEVER: git push origin main
   ```
5. Create PR using pull-request agent or `gh` command
6. **NEVER merge PRs without explicit user approval**

### Creating PRs

```bash
# After pushing feature branch
gh pr create --title "Add SDEF parser" --body "$(cat <<'EOF'
## Summary
- Implemented XML parser for SDEF files
- Added validation and error handling
- Included unit tests

## Test Plan
- [x] Unit tests pass
- [x] Integration tests pass
- [x] Tested with Finder.sdef

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

### Monitoring PR Reviews

After creating the PR, start the background monitor:

```bash
# Start background monitor (auto-backgrounds itself, returns immediately)
./tools/monitor_pr_review.sh <PR_NUMBER>

# Watch the output asynchronously (Ctrl-C to stop tail)
tail -f tests/tmp/pr_monitor_<PR_NUMBER>.log

# Kill if needed
kill <PID>  # PID shown when monitor starts
```

**Key Property**: The monitor script auto-backgrounds itself - it is **always non-blocking**, regardless of how it's invoked.

---

## Working with Agents

### Available Agents

| Agent | Use When | Capabilities |
|-------|----------|--------------|
| **system-architect** | Architecture design, tech stack decisions | System design, scalability planning |
| **mcp-protocol-expert** | MCP server implementation, tool schemas | Protocol compliance, MCP patterns |
| **macos-automation-expert** | SDEF parsing, JXA execution, permissions | macOS automation, AppleEvents |
| **security-reviewer** | Security reviews, permission system | Vulnerability analysis, secure coding |
| **typescript-engineer** | TypeScript patterns, Node.js architecture | Type system design, async patterns |
| **Explore** | Multi-file codebase exploration | Fast search, architectural context |
| **Plan** | Implementation planning before coding | Step-by-step plans, file identification |

### When to Use Agents

- ✅ Multi-file codebase exploration → **Explore** agent
- ✅ Architecture decisions → **system-architect**
- ✅ MCP protocol questions → **mcp-protocol-expert**
- ✅ macOS automation → **macos-automation-expert**
- ✅ Security review → **security-reviewer** (proactive after security-sensitive code)
- ✅ Planning before implementation → **Plan** agent
- ✅ TypeScript patterns → **typescript-engineer**

**Don't do complex analysis or design work manually when an agent can do it better and faster.**

### Agent Best Practices

1. **Background execution**: Use `run_in_background: true` by default
2. **Parallelize**: Launch multiple agents in single message when independent
3. **Context**: Provide clear task description with constraints
4. **Trust output**: Agent results are generally reliable
5. **Update agents**: When you learn something an agent should know, update the agent definition

### ⚠️⚠️⚠️ CRITICAL: Working Directory Context for Agents ⚠️⚠️⚠️

**MANDATORY when working in feature branches/worktrees:**

When launching ANY sub-agent that will make code changes during /doit workflow or worktree development, you MUST explicitly pass the working directory path in the agent's task prompt:

```markdown
WORKING DIRECTORY: /Users/jake/dev/jsavin/iac-mcp-<feature-name>
BRANCH: feature/<feature-name>

You MUST execute all commands and file operations in this working directory.
Verify your location with 'pwd && git branch' before making any changes.

[Rest of task description...]
```

**Why This is Critical**:
- Agents don't automatically inherit working directory context
- Without explicit path, agents may work in main iac-mcp directory on main
- This introduces breaking changes to main instead of feature branch
- Creates redundant work and violates worktree workflow discipline

**When This Applies**:
- ✅ During /doit workflow (all phases)
- ✅ When working in any worktree for feature development
- ✅ Any agent that will modify code, run tests, or commit changes
- ❌ Not needed for pure research/exploration agents (read-only analysis)

**Verification After Agent Completes**:
```bash
cd <worktree-path> && git status  # Verify changes are on correct branch
```

---

## /doit Workflow - Feature Development

**For comprehensive /doit workflow guidance**, see the global instructions in `~/.claude/CLAUDE.md`.

This section provides **iac-mcp-specific agent selection** for each /doit phase.

### /doit Agent Selection for iac-mcp

| Phase | Primary Agent(s) | When to Use in Parallel | Notes |
|-------|------------------|-------------------------|-------|
| **Phase 2: Research** | Explore | Always use for multi-file analysis | Fast codebase exploration and architectural context |
| **Phase 3: Planning** | Plan, system-architect | Use system-architect if architecture/design decisions needed | Plan for implementation steps, system-architect for tech decisions |
| **Phase 4: Implementation** | typescript-engineer (TypeScript code)<br>mcp-protocol-expert (MCP protocol)<br>macos-automation-expert (SDEF/JXA) | Parallelize independent modules:<br>- TypeScript + tests<br>- MCP protocol + adapters<br>- SDEF parsing + tool generation | Choose based on domain:<br>- TypeScript patterns → typescript-engineer<br>- MCP compliance → mcp-protocol-expert<br>- macOS automation → macos-automation-expert |
| **Phase 5: Testing** | typescript-engineer | Can parallel with code-review-bar-raiser | Write tests (unit + integration), ensure 100% coverage |
| **Phase 6: PR** | pull-request<br>code-review-bar-raiser<br>security-reviewer | **Always parallel**: All three agents | PR creation + quality review + security review |

### Common Parallel Agent Patterns for iac-mcp

**New SDEF parser feature**:
1. Explore (find existing parsers) + Plan (design approach) - sequential
2. typescript-engineer (parser impl) + typescript-engineer (tests) - **parallel**
3. code-review-bar-raiser + security-reviewer - **parallel**

**MCP tool generation**:
1. mcp-protocol-expert (tool schema design) + macos-automation-expert (execution strategy) - **parallel**
2. typescript-engineer (implementation) + typescript-engineer (tests) - **parallel**
3. code-review-bar-raiser + security-reviewer - **parallel**

**Permission system feature**:
1. security-reviewer (threat model) + system-architect (design) - sequential
2. typescript-engineer (implementation) + typescript-engineer (tests) - **parallel**
3. security-reviewer (validation) - sequential after implementation

---

## Task Completion Protocol

**Pattern:** Stop and report after each milestone.

**Protocol:**
1. Complete task or milestone
2. Stop and report what was completed
3. Do local commit (if under source control and there are changes)
4. **Suggest next logical step(s) and ask which to pursue**
5. Wait for user response before proceeding

**Exception:** Only proceed automatically if user's original request explicitly included multiple steps (e.g., "do X, then Y, then Z").

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

**See [CODE-QUALITY.md](CODE-QUALITY.md) for comprehensive testing standards.**

**Summary:**
- ✅ **100% coverage required** (unit + integration)
- ✅ **Every function needs:** happy path, error paths, edge cases
- ✅ **Test naming:** Descriptive, start with "should"
- ✅ **CI enforced:** PRs blocked if coverage < 100%

**Testing tools:**
```bash
npm run test              # Run all tests
npm run test:coverage     # Run with coverage (must be 100%)
npm run test:unit         # Unit tests only
npm run test:integration  # Integration tests only
npm run test:watch        # Watch mode for development
```

**Manual testing:**
- MCP Inspector: `npx @modelcontextprotocol/inspector`
- Claude Desktop integration
- Real-world app testing (Finder, Safari, Mail)

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
