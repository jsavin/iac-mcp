# Product Reframe: What We're Really Building

## The Evolution of Our Thinking

### Where We Started
"Let's build an MCP server that exposes AppleScript capabilities to Claude Desktop."

**Problems with this:**
- Developer-focused (CLI, npm, terminal)
- Limited to Claude Desktop users
- Technical users only
- macOS-only without vision
- Just another tool for programmers

### Where We Are Now
"Let's build **Frontier for the AI age** - a native application that empowers non-technical people to create AI-powered workflows that orchestrate any apps on their computer."

**Why this is better:**
- **Accessible**: Visual interface, not terminal
- **Empowering**: For everyone, not just developers
- **Revolutionary**: Democratizes AI automation
- **Sustainable business**: People will pay for this
- **Clear vision**: We know who we're building for

## Key Realizations

### 1. The Target User is NOT a Developer
**Wrong mental model:**
> "Developers using Claude Desktop will install our MCP server via npm and add it to their config file."

**Right mental model:**
> "A marketing manager wants to automate her weekly report. She opens our app, describes what she wants, and AI builds the workflow. She never touches a config file or terminal."

### 2. The Competition is NOT Other MCP Servers
**Wrong competitive set:**
- Other MCP servers (filesystem, postgres, etc.)
- Developer automation tools
- CLI utilities

**Right competitive set:**
- **Zapier/Make** (but we're better: work with ANY app, local processing)
- **Keyboard Maestro** (but we're better: AI-powered, easier to use)
- **Apple Shortcuts** (but we're better: more powerful, AI-assisted)
- **The "do nothing" alternative** (hiring someone or manual work)

### 3. The Distribution is NOT npm
**Wrong distribution:**
```bash
npm install -g iac-mcp
# Edit config file
# Restart Claude Desktop
```

**Right distribution:**
1. Download from website or Mac App Store
2. Double-click to install
3. Open app
4. Grant permissions when prompted
5. Start building workflows

### 4. The Business Model is NOT Free/Open Source
**Wrong model:**
- Free MCP server on npm
- Maybe someday monetize something?
- Hope for sponsorships?

**Right model:**
- **Premium Mac app**: $49-99 one-time or $29/year
- **Freemium**: Free tier, Pro tier $9.99/month
- **Clear value prop**: Saves users hours every week
- **Sustainable**: Real revenue from day one

### 5. The Value Prop is NOT "Better AppleScript"
**Wrong pitch:**
> "An MCP server that lets LLMs execute AppleScript on your Mac."

**Right pitch:**
> "Automate anything on your Mac by describing it in plain English. AI orchestrates your apps to build workflows that used to require a programmer."

## What This Changes

### Technical Priorities

#### Old Priorities
1. MCP protocol implementation
2. SDEF parsing
3. AppleScript execution
4. Command-line configuration

#### New Priorities
1. **Native macOS UI** (Swift/SwiftUI or Electron)
2. **Visual workflow builder** (canvas, drag-drop, or conversational)
3. **AI workflow assistance** (natural language → workflow generation)
4. **Permission system UI** (native dialogs, always allow checkboxes)
5. **MCP protocol** (still needed, but behind the scenes)
6. **JITD engine** (still core, but invisible to users)

### User Experience

#### Old UX
```
Developer:
1. Reads documentation
2. npm install iac-mcp
3. Edits ~/.config/claude/config.json
4. Restarts Claude Desktop
5. Asks Claude to execute AppleScript
6. Debugs when it fails
```

#### New UX
```
Regular User:
1. Downloads app
2. Opens app
3. Types: "Every Monday, gather my meeting notes from Notes app,
    organize by project, and create weekly summary in Notion"
4. AI: "I found Notes and Notion. Here's the workflow: [shows visual]"
5. User: "Looks good!"
6. Workflow runs automatically every Monday
```

### Marketing & Positioning

#### Old Positioning
- **Audience**: Developers using Claude Desktop
- **Message**: "Extend Claude with AppleScript capabilities"
- **Channel**: GitHub, npm, developer forums
- **Price**: Free

#### New Positioning
- **Audience**: Knowledge workers, content creators, designers, marketers
- **Message**: "Automate anything on your Mac. Just describe it."
- **Channel**: Product Hunt, Mac app sites, productivity communities, YouTube demos
- **Price**: $49-99 or $9.99/month (clearly worth it)

## The Minimum Viable Product

### What MVP Must Have

#### 1. Native Mac App (Not CLI)
- Status bar icon or dock app
- Native macOS permissions dialogs
- Works without terminal/command line

#### 2. AI Workflow Creation
- Chat interface: "What do you want to automate?"
- AI suggests workflow steps
- User approves/modifies
- Saves for future use

#### 3. Core App Support (~10 apps)
- Finder (file operations)
- Safari (browser automation)
- Mail (email)
- Notes (note management)
- Calendar (events)
- Reminders
- Photos
- Music
- Messages
- TextEdit

#### 4. Permission System
- Clear permission prompts
- "Always allow" checkbox
- Audit log (what ran when)

#### 5. Workflow Management
- Save workflows
- Run workflows manually
- Edit workflows
- Share workflows (export/import)

### What MVP Does NOT Need

❌ Windows/Linux support (Phase 2)
❌ All 500+ Mac apps (add incrementally)
❌ Scheduled execution (can add later)
❌ Visual workflow canvas (conversational is fine for v1)
❌ Community marketplace (build after users exist)
❌ Advanced scripting (keep it AI-driven)
❌ Mobile app (desktop first)

## Success Criteria for MVP

### Must Prove
1. **Non-technical users can create workflows** (without coding)
2. **AI workflow generation works** (high success rate)
3. **Users find it valuable** (would pay $49+)
4. **JITD works reliably** (apps discovered correctly)
5. **Permission system feels safe** (users trust it)

### Metrics
- 50 beta users complete onboarding
- Average user creates 3+ workflows in first week
- 80%+ of AI-suggested workflows work first try
- 70%+ would pay $49 (survey after beta)
- Zero security incidents

## What We Build First

### Phase 0: Technical Validation (2-4 weeks)
**Goal:** Prove JITD concept works

- ✅ Parse Finder SDEF file
- ✅ Generate MCP tools from capabilities
- ✅ Execute AppleEvent via JXA
- ✅ Test with Claude Desktop manually
- ✅ Validate: Can we control Finder via generated tools?

### Phase 1: Core Engine (4-6 weeks)
**Goal:** Working MCP backend

- JITD engine (discovery, parsing, tool generation)
- Platform adapter (macOS AppleEvents/JXA)
- Permission system (rules, prompts, audit)
- Cache management
- MCP server implementation

### Phase 2: Native App Shell (4-6 weeks)
**Goal:** Basic Mac app that works

- SwiftUI or Electron shell
- AI chat interface
- System tray/status bar
- Permission dialogs (native macOS)
- Workflow storage

### Phase 3: AI Workflow Builder (4-6 weeks)
**Goal:** Users can create workflows conversationally

- Natural language → workflow translation
- Claude integration (API or local)
- Workflow preview and editing
- Execution with live feedback
- Error handling and recovery

### Phase 4: Polish & Beta (4-6 weeks)
**Goal:** Ready for real users

- Onboarding flow
- Example workflows
- Documentation
- Error messages and help
- Performance optimization
- Beta testing with 50 users

**Total: ~4-6 months to beta-ready MVP**

## Pricing Strategy for MVP

### Option A: Free Beta → Paid Launch
- Beta: Free while we validate
- Launch: $49 one-time (early adopter price)
- Later: $79-99 regular price

### Option B: Freemium from Day 1
- Free: 3 apps (Finder, Safari, Mail), 5 workflows
- Pro: All apps, unlimited workflows, $9.99/month or $79/year
- Start building paid users immediately

### Option C: Paid Beta (Risky but Validates Willingness)
- $29 early access price
- Locks in lifetime updates
- Proves people will pay
- Builds committed user base

**Recommendation: Option A** (free beta, paid launch)
- Removes friction for early adoption
- Gathers feedback without payment pressure
- Validates pricing before committing
- Can adjust pricing based on perceived value

## Repository & Project Name

### Current Name: `osa-mcp`
**Problems:**
- Too technical (OSA = Open Scripting Architecture)
- Platform-specific (Mac-only implication)
- Describes implementation, not benefit

### Better Names

**Product-Focused:**
- `workflow-ai` (clear what it does)
- `automate-ai` (clear benefit)
- `workflow-builder` (describes tool)

**Brand-Focused:**
- `frontier-ai` (honors Frontier legacy)
- `conductor` (orchestrates apps)
- `weave` (weaves apps together)
- `chorus` (apps work in harmony)
- `bridge` (bridges AI and apps)

**Fun/Memorable:**
- `launchpad` (launches workflows)
- `compass` (guides automation)
- `catalyst` (enables reactions)

### Recommendation
Keep `osa-mcp` for now (it's just the repo name).

Choose product name later when brand matters:
- After MVP proves concept
- When we understand positioning better
- Based on user feedback about what resonates

## Updated CLAUDE.md Needed

Our current CLAUDE.md talks about:
- Building an MCP server
- npm commands
- SDEF parsing

It should talk about:
- Building a native Mac app
- Visual workflow builder
- AI-powered automation
- User-centric design

**Action item:** Update CLAUDE.md after we align on this vision.

## The Path Forward

1. **Align on vision** (this document)
2. **Validate technical feasibility** (Phase 0)
3. **Choose: Electron vs native Swift** (big decision!)
4. **Build core engine** (Phase 1)
5. **Build app shell** (Phase 2)
6. **Integrate AI** (Phase 3)
7. **Beta test** (Phase 4)
8. **Launch** and change the world

## Questions to Resolve

1. **Electron vs SwiftUI?**
   - Electron: Faster development, reuse TypeScript/Node code
   - Swift: Better performance, smaller binary, more "native" feel

2. **Which AI model?**
   - Claude API (requires internet, costs money)
   - Local LLM (privacy, offline, but less capable)
   - Hybrid (user's choice)

3. **How visual should workflows be?**
   - Pure conversational (chat only)
   - Visual canvas with nodes/edges
   - Outline view (like Frontier!)
   - Mix of all three

4. **Freemium or paid from start?**
   - Affects development (need free tier limits)
   - Affects marketing (free gets more users)
   - Affects validation (paid proves value)

5. **Mac App Store or direct distribution?**
   - App Store: Discovery, trust, easy updates
   - Direct: Faster iteration, no Apple review delays, no 30% cut

These are the **real questions** we need to answer, not "should we use AppleScript or JXA?"

---

**The bottom line:** We're not building an MCP server for developers. We're building Frontier for the AI age - a tool that democratizes automation for everyone.
