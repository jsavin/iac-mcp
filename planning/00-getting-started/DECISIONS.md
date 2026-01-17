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
- Can add broader coverage later, funded by revenue
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
- **Pro:** $9.99/month or $79/year, unlimited apps/workflows
- **Lifetime (optional):** $199 one-time, limited availability
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
**Deferred to post-launch, funded by revenue:**
- ❌ Accessibility API support (Tier 2)
- ❌ Vision AI for non-scriptable apps (Tier 3)
- ❌ Windows version
- ❌ Linux version
- ❌ Visual workflow canvas (conversational UI sufficient for v1)
- ❌ Workflow marketplace
- ❌ Team/enterprise features

**Status:** Deferred

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
**Question:** Is $9.99/month right, or test different price points?
**Consider:** Could do early bird pricing ($79 lifetime) to validate willingness to pay

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-01-15 | Bootstrap strategy | Maintain control, align with values |
| 2026-01-15 | Scriptable apps only (MVP) | Faster to ship, proves concept |
| 2026-01-15 | Hybrid tech stack | Native feel + code reuse |
| 2026-01-15 | Core open, UI proprietary | Community + business model |
| 2026-01-15 | Freemium $9.99/month | Proven pricing for Mac productivity apps |

---

**Next step:** Create detailed roadmap based on these decisions.
