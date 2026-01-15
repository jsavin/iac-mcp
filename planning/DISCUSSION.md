# Discussion Topics

## Vision Alignment ✅

The vision is documented and understood:
- **This project:** Universal AI-to-native-apps bridge using JITD
- **Complementary:** Works with modernized Frontier as foundation layer
- **Philosophy:** Interoperability above all, local-first, user control
- **Market gap:** AI companies miss native app ecosystems, we bridge it

## Critical Decisions to Discuss

### 1. Build Order & MVP Scope

**Question:** What should we build first?

#### Option A: MCP Bridge for Developers (Phase 1)
**What:**
- Node.js MCP server
- JITD engine (discovery, parsing, tool generation)
- Platform adapter (macOS AppleEvents/JXA)
- Works with Claude Desktop

**Pros:**
- Faster to validate core concept
- Proves JITD works technically
- Serves developer audience immediately
- Can iterate quickly (no UI development)
- Standard distribution (npm)

**Cons:**
- Limited audience (only Claude Desktop users)
- Doesn't serve non-technical users
- Doesn't fully realize vision (no visual workflows)
- Terminal/config file friction

**Timeline:** 3-6 months to working MCP server

#### Option B: Native App for End Users (Phase 2)
**What:**
- Native macOS application
- Visual/conversational workflow builder
- Embedded JITD engine
- AI assistant for workflow creation
- Full user-friendly experience

**Pros:**
- Serves actual target audience (non-technical users)
- Realizes complete vision immediately
- Competitive moat (not just another MCP server)
- Clear business model (paid app)
- Bigger market opportunity

**Cons:**
- Longer development time (6-12 months)
- More complex (UI + engine + AI integration)
- Higher risk (more to build before validation)
- Technology stack decisions (Electron vs Swift)

**Timeline:** 6-12 months to MVP

#### Option C: Hybrid Approach
**What:**
- Build MCP bridge first (3-6 months)
- Validate core JITD concept
- Then wrap in native app (6 months more)
- Total: 9-18 months to complete product

**Pros:**
- Validates incrementally
- Serves developers while building for users
- Reduces risk (prove concept first)
- Can pivot based on learnings

**Cons:**
- Longest overall timeline
- Potential for distraction (two audiences)
- May optimize for developers first, hurt user UX later

#### Recommendation Needed
**Your instinct:** Which approach aligns with your goals and timeline?

**Consider:**
- How important is the Frontier integration timeline?
- Would developers using MCP bridge inform the native app design?
- Is there value in serving developers first?
- Or should we go straight for the bigger vision?

---

### 2. Frontier Integration Strategy

**Context:** You're modernizing Frontier separately. This bridge will eventually integrate with it.

#### Question A: Design for Integration Now?

**Design for integration from start:**
- Architecture considers Frontier's object database
- APIs designed for Frontier calling bridge
- Data formats compatible with UserTalk
- May slow down initial development

**Prove concept independently first:**
- Build standalone bridge
- Validate JITD works
- Design Frontier integration later
- Faster to working prototype

**Which approach?**

#### Question B: Integration Timeline?

**When do you expect modernized Frontier to be ready?**
- 6 months?
- 1 year?
- 2+ years?

This affects whether we should wait for it or build independently.

#### Question C: Integration Points?

**What should the integration look like?**

Possibilities:
1. **Frontier calls bridge:** UserTalk scripts invoke IAC tools
2. **Bridge uses Frontier:** Bridge stores state in Frontier's object database
3. **Bidirectional:** Both can call each other
4. **Shared runtime:** Bridge runs inside Frontier process
5. **Separate but coordinated:** Two apps that communicate

**Your vision for how they work together?**

---

### 3. Technology Stack (If Building Native App)

#### Electron vs Swift

**Electron:**
- ✅ Reuse TypeScript/Node.js code from MCP bridge
- ✅ Faster development (web technologies)
- ✅ Cross-platform easier (Windows/Linux later)
- ✅ Rich UI libraries available
- ❌ Larger bundle size (~200MB+)
- ❌ Higher memory usage
- ❌ Less "native" feel
- ❌ Performance overhead

**Swift + SwiftUI:**
- ✅ Native performance
- ✅ Smaller binary size
- ✅ Better macOS integration
- ✅ Native feel and UX
- ✅ Lower memory usage
- ❌ Slower development
- ❌ Need to rewrite MCP bridge or use native bridge
- ❌ Cross-platform harder (separate Windows/Linux apps)
- ❌ Steeper learning curve

**Hybrid (Swift UI + Node.js backend):**
- ✅ Native UI, reuse MCP bridge code
- ✅ Best of both worlds
- ❌ Complex IPC between Swift and Node
- ❌ Two codebases to maintain

**Your preference?**

Consider:
- Speed to market vs polish
- Cross-platform plans
- Team size (just you? hiring?)
- Existing expertise

---

### 4. Business Model

#### Question A: Initial Distribution

**Option 1: Free for Developers**
- MCP server on npm, free and open source
- Proves concept, builds community
- Monetize native app later

**Option 2: Paid from Start**
- Even MCP server has commercial license ($99/year)
- Or free for personal, paid for commercial
- Validates willingness to pay early

**Option 3: Freemium Native App**
- Free tier: Basic apps, limited workflows
- Pro tier: $9.99/month or $79/year
- Build paid users from day one

**Which feels right?**

#### Question B: Eventual Pricing

**For the complete native app, what's fair?**

Comparisons:
- Keyboard Maestro: $36 one-time
- Alfred Powerpack: £34 (~$43) one-time or £19/year (~$25)
- Zapier: $20-50/month (but cloud service)
- Shortcuts: Free (but limited and Apple-only)

Options:
- **Premium one-time:** $49-99
- **Annual license:** $29-49/year
- **Subscription:** $9.99/month or $79/year
- **Freemium:** Free basic + $9.99/month pro

**Your instinct on pricing?**

---

### 5. MVP Feature Scope

#### Core Question: How minimal is "minimum"?

**Must have:**
- App discovery (JITD)
- Tool generation
- Execution layer
- Permission system
- Works with ___ apps

**How many apps for MVP?**

Option 1: **Just Finder** (1 app)
- Proves concept completely
- Fastest to working demo
- Limited real-world value

Option 2: **Core 5** (Finder, Safari, Mail, Notes, Calendar)
- Demonstrates cross-app workflows
- Useful for real tasks
- Reasonable scope

Option 3: **Popular 10-15** (add Messages, Photos, Music, Reminders, TextEdit, Preview, etc.)
- More compelling demos
- Broader appeal
- Longer development

**What's enough to validate the concept?**

#### AI Integration for MVP

**Which AI should MVP support?**

Option 1: **Claude API only**
- Simplest integration
- Requires internet and API key
- Costs per use

Option 2: **Local LLM (Ollama, etc.)**
- Privacy-first
- Offline capable
- Less capable than Claude

Option 3: **User's choice**
- Flexible but more complex
- Support multiple backends
- Harder to optimize experience

**Your preference for MVP?**

---

### 6. Success Metrics & Validation

**What does success look like for Phase 1?**

Possible metrics:
- X developers install and use it
- X workflows created by users
- X% of workflows execute successfully
- X apps successfully integrated
- Users report X hours saved per week
- X% would pay $Y for native app version

**What metrics matter to you?**

**How do we know we're ready for Phase 2?**

---

### 7. Project Naming & Branding

#### Repository vs Product Name

**Current:** `osa-mcp`
- Good: Descriptive for developers
- Bad: Too technical, macOS-specific

**Should we rename the repository?**

Or keep repo technical but plan product name separately?

#### Product Name (Eventually)

When we launch native app, what should it be called?

Criteria:
- Memorable
- Describes benefit or approach
- Not too technical
- Available domain
- Not conflicting with existing tools

**Ideas (or your own):**
- Frontier AI (honors legacy)
- Conductor (orchestrates apps)
- Weave (weaves apps together)
- Bridge (obvious)
- Workflow AI
- Automate AI
- Something entirely different?

**Name now or later?** (Later is fine, just asking if you have thoughts)

---

### 8. Community & Open Source Strategy

#### Open vs Closed Source

**MCP Bridge (core engine):**
- Open source? (More community, less business control)
- Proprietary? (More control, clear monetization)
- Open core? (Basic open, advanced proprietary)

**Native App:**
- Likely proprietary regardless (paid product)
- But could open source pieces (workflow library, platform adapters)

**Your philosophy on open source here?**

Given:
- Frontier is GPL open source
- Interoperability mission
- But need sustainable business
- Competitive concerns

---

## Discussion Format

For each topic above, please share:
1. **Your instinct** (what feels right)
2. **Your constraints** (time, resources, other projects)
3. **Your priorities** (what matters most)
4. **Open questions** (what you're unsure about)

We can then:
- Align on decisions
- Create concrete roadmap
- Start building with clear direction

---

## Quick Poll (If Helpful)

**Most Important Question:**
What should we build first?

- [ ] A) MCP bridge for developers (proves JITD concept, 3-6 months)
- [ ] B) Native app for users (complete vision, 6-12 months)
- [ ] C) MCP bridge first, then wrap in app (9-18 months total)

**Your vote and reasoning?**

This single decision unlocks the roadmap for everything else.
