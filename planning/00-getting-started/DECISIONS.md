# Key Decisions

## Strategy: Bootstrap, Not VC-Funded
**Decision:** Build sustainably with your own resources, no investors
**Rationale:** Maintains control, aligns with interoperability mission, no pressure for walled gardens or exits
**Status:** ✅ Decided

## Timeline & Availability
**Decision:** Part-time development (20-30 hours/week)
**Realistic MVP Timeline:** 6-9 months to working MCP bridge + basic UI
**Status:** ✅ Decided

## MVP Scope
**Decision:** Scriptable apps only (no accessibility APIs or vision AI in v1)
**Coverage:** ~30-40% of Mac apps (Finder, Mail, Safari, Calendar, Notes, etc.)
**Rationale:**
- Proves JITD concept completely
- Faster to build and ship
- Still highly valuable
- Can add broader coverage later, ongoing development
**Status:** ✅ Decided

## Technology Stack

### Backend: MCP Bridge Core
**Decision:** Node.js/TypeScript
**Rationale:** Standard for MCP servers, good ecosystem, proven
**Status:** ✅ Decided

### Frontend: UI Wrapper
**Decision:** Hybrid architecture (Swift UI + Node.js backend)
**Components:**
- Native macOS app in Swift/SwiftUI (menu bar or main app)
- Node.js MCP bridge backend (reused core code)
- IPC between Swift and Node.js (XPC, HTTP, or stdio)
**Rationale:**
- Native feel and performance
- Reuse MCP bridge code (don't rewrite in Swift)
- Smaller binary than Electron
- Better macOS integration
**Trade-offs:**
- More complex than pure Electron
- Need to design clean IPC layer
- Two languages/codebases to maintain
**Status:** ✅ Decided

## Open Source Strategy
**Decision:** Core open source, UI proprietary
**License Structure:**
- **MCP bridge core:** MIT or Apache 2.0 (open source)
  - JITD engine
  - Platform adapters
  - Tool generation
  - Discovery and parsing
- **Swift UI wrapper:** Proprietary (closed source)
  - Workflow builder
  - Visual interface
  - Advanced features
  - Paid product
**Rationale:**
- Open core builds community and credibility
- Shows expertise and transparency
- Developers can contribute to core
- Business model preserved (paid UI wrapper)
- Can't be easily forked as complete product
**Status:** ✅ Decided

## Business Model
**Decision:** Freemium SaaS
**Tiers:**
- **Free:** 3 apps (Finder, Safari, Mail), 5 saved workflows
- **Pro:** subscription pricing or subscription pricing, unlimited apps/workflows
- **Lifetime (optional):** one-time pricing, limited availability
**Status:** ✅ Decided

## Frontier Integration
**Decision:** Build independently, integrate later
**Rationale:**
- Don't wait for Frontier modernization to complete
- Prove bridge concept and business independently
- Integration happens when both are ready and revenue-positive
**Status:** ✅ Decided

## Go-to-Market
**Decision:** Developer-first, then expand to non-technical users
**Phase 1:** Open source MCP bridge for developers (validation)
**Phase 2:** Paid UI wrapper for broader audience (revenue)
**Rationale:**
- Developers validate technical approach
- Feedback informs UI design
- Community builds around open core
- Then expand market with paid product
**Status:** ✅ Decided

## Future Expansion (Not MVP)
**Deferred to post-launch, ongoing development:**
- ❌ Accessibility API support (Tier 2)
- ❌ Vision AI for non-scriptable apps (Tier 3)
- ❌ Windows version
- ❌ Linux version
- ❌ Visual workflow canvas (conversational UI sufficient for v1)
- ❌ Workflow marketplace
- ❌ Team/enterprise features

**Status:** Deferred

## Dual Approach for App Discovery (Resource + Tool)

**Date:** 2026-01-22
**Context:** PR #19 - list_apps tool implementation
**Decision:** Provide BOTH MCP resource (`iac://apps`) AND MCP tool (`list_apps`) for app discovery

**Rationale:**

Resources and tools serve complementary purposes in MCP:

1. **Resource (`iac://apps`)**:
   - Loaded at session initialization
   - Cached by MCP clients for duration of session
   - Efficient: Single fetch at session start
   - Use case: Claude starts with immediate context of available apps

2. **Tool (`list_apps`)**:
   - Discoverable during conversation (shows in tool list)
   - Can refresh app list mid-session
   - Better UX: Users can explicitly request "what apps are available?"
   - Use case: User asks about capabilities or apps change during session

**Implementation Details:**

- Both resource and tool use shared `discoverAppMetadata()` function
- Ensures consistency - identical data from both endpoints
- Resource URI: `iac://apps`
- Tool name: `list_apps` (no parameters)
- Response format: JSON with `totalApps` count and `apps` array

**Trade-offs:**

- ✅ **Pro:** Optimizes for both session initialization (resource) and discoverability (tool)
- ✅ **Pro:** MCP clients can cache resource, reducing repeated calls
- ✅ **Pro:** Tool provides user-friendly "list apps" action
- ⚠️ **Con:** Some code duplication between resource and tool handlers
  - Mitigated: Both use shared `discoverAppMetadata()` function (DRY)
- ⚠️ **Con:** Two ways to get same data
  - Acceptable: Different use cases justify redundancy

**Alternative Considered:** Resource-only approach

- More semantically correct per MCP spec (app list is "data")
- But poor discoverability - users wouldn't find it easily
- No way to refresh mid-session without knowing URI scheme

**Precedent:**

This reverses the decision from PR #15 to remove all resource handlers. PR #15 removed resources to simplify the architecture, but user feedback identified the complementary value of resources for session initialization.

**Future Considerations:**

- Could add additional resources: `iac://apps/{bundleId}` (per-app details)
- Could add resource for object model: `iac://apps/{bundleId}/object-model`
- These would complement existing `get_app_tools` tool

**References:**
- PR #19: https://github.com/jsavin/iac-mcp/pull/19
- Bot review discussion on resources vs tools
- MCP Protocol specification on resources

**Status:** ✅ Decided

## Open Questions (Still To Decide)

### 1. IPC Architecture for Hybrid Stack
**Question:** How should Swift UI communicate with Node.js backend?
**Options:**
- XPC (Apple's native IPC, but complex)
- HTTP/REST (Swift calls localhost Express server)
- stdio (Swift spawns Node process, communicates via stdin/stdout)
- WebSocket (bidirectional, good for live updates)
**Need to research:** Which is most maintainable for solo developer?

### 2. App Count for MVP
**Question:** How many apps should MVP support?
**Options:**
- Minimal (5 apps): Finder, Safari, Mail, Calendar, Notes
- Good (10 apps): + Messages, Photos, Music, Reminders, TextEdit
- Complete (20+ apps): + Preview, Contacts, Podcasts, etc.
**Consider:** More apps = longer development, but more compelling demos

### 3. Permission UX
**Question:** How to handle permission prompts in hybrid architecture?
**Options:**
- Native macOS alerts (NSAlert in Swift)
- Custom UI (in-app dialogs)
- Mix (system for dangerous, custom for routine)
**Consider:** Native feels more trustworthy, custom more flexible

### 4. Launch Timing
**Question:** When to launch open source core vs paid UI?
**Options:**
- Simultaneous (core + UI launched together)
- Staggered (core first, UI 1-2 months later)
**Consider:** Staggered gets early feedback, simultaneous has more impact

### 5. Pricing Validation
**Question:** Is subscription pricing right, or test different price points?
**Consider:** Could do early bird pricing ($79 lifetime) to validate willingness to pay

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-01-15 | Bootstrap strategy | Maintain control, align with values |
| 2026-01-15 | Scriptable apps only (MVP) | Faster to ship, proves concept |
| 2026-01-15 | Hybrid tech stack | Native feel + code reuse |
| 2026-01-15 | Core open, UI proprietary | Community + business model |
| 2026-01-15 | Freemium subscription pricing | Proven pricing for Mac productivity apps |
| 2026-01-22 | Dual resource + tool for app discovery | Complementary use cases: session init + discoverability |

---

**Next step:** Create detailed roadmap based on these decisions.
