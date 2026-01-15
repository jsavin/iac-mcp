# Project Vision: The AI-to-Native-Apps Bridge

## Executive Summary

This project builds a **universal bridge layer** that connects AI/LLMs to native applications on users' computers, enabling AI-powered automation across the rich ecosystem of native apps that everyone else ignores.

## The Three-Sentence Version

1. **AI companies are web-centric** and treat native apps as edge cases, missing the vast ecosystem of creative, productivity, and specialized tools people actually use daily.
2. **This project bridges AI to native apps** using Just-In-Time Discovery (JITD) to dynamically discover and orchestrate any installed application without pre-built integrations.
3. **Together with modernized Frontier**, it forms a complete platform for AI-augmented local computing that gives users control and enables revolutionary workflows combining online AI with local native apps.

## The Core Philosophy: Interoperability Above All

**Make everything work with everything else.**

- Universal interoperability (any app + any AI + any platform)
- Local-first (user control, privacy, no cloud lock-in)
- AI as augmentation (enhance, don't replace)
- Native apps as first-class citizens (not legacy, not edge cases)
- Open architecture (no vendor lock-in, user ownership)

## What We're Building

### This Project: IAC MCP Bridge
**The bridge layer between AI and native applications**

**Core Technology:**
- Just-In-Time Discovery (JITD) of installed app capabilities
- Platform adapters (macOS AppleEvents/JXA, Windows COM/PowerShell, Linux D-Bus)
- Universal tool generation from discovered capabilities
- MCP protocol integration for AI/LLM access
- Permission and safety system

**What it enables:**
- Claude (or any LLM) can discover what apps you have installed
- AI understands what each app can do by reading capability definitions
- AI can orchestrate workflows across any combination of apps
- No pre-built integrations required
- Works with apps the day they're installed

### The Complementary Project: Modernized Frontier
**The foundation layer for local computing workflows** (separate effort)

**Core Technology:**
- 40-year-old Frontier codebase modernized for 64-bit
- Thread-safe, multi-user capable
- Object database for central storage
- UserTalk scripting environment
- Outliner-based development

**What it enables:**
- Structured storage for workflow state and data
- Scripting and automation foundation
- Multi-user collaboration on workflows
- The proven workflow orchestration layer

### Together: The Complete Platform

```
    Online AI Services (Claude, GPT, local models)
                    ↕
         IAC MCP Bridge (this project)
                    ↕
    Native Apps (creative, productivity, specialized)
                    ↕
         Modernized Frontier (foundation)
```

## The Market Gap

### What Everyone Else Misses

**Anthropic / OpenAI:**
- Web-centric, developer-focused
- Native apps = occasional edge cases (Office, IDEs)
- Don't understand the richness of native app ecosystems

**Microsoft / Apple:**
- Platform-locked, own ecosystem only
- Won't enable cross-platform interoperability
- Too focused on their own BS

**Zapier / Automation Tools:**
- Pre-built integrations only
- Web services focused
- Limited native app support
- Can't dynamically discover new apps

**Indie App Developers:**
- Isolated silos
- Many anti-AI (threatened livelihoods)
- Won't embrace interoperability

### Why We Can Build This

**Unique position:**
- Deep understanding of native app ecosystems (decades of Mac development)
- IAC expertise (AppleEvents, scripting, cross-app communication)
- Current with AI/LLM tech (MCP, Claude, modern approaches)
- Commitment to interoperability (not vendor lock-in)
- Not beholden to any platform vendor
- Not threatened by AI
- **ALL ABOUT INTEROP**

## The User Value Proposition

### For Regular Users
"Use AI with the apps you already love. Don't abandon great native tools for web services. Control your computing experience."

**Examples:**
- "Gather research from browser tabs, organize in note app, draft in writing app" - AI orchestrates it all
- "Every morning, compile newsletter from RSS, email, Twitter - automatically"
- "Batch process Figma exports, optimize for web, update portfolio site"
- "Pull data from spreadsheets, generate charts, create presentation"

**Key difference:** Works with ANY app you have installed, not just pre-integrated ones.

### For App Developers
"Get AI integration and cross-app workflows without building it yourself. Focus on your core UX."

### For AI Companies
"Access rich native app capabilities for real-world grounding. But through open bridge, not proprietary control."

### For the Ecosystem
"Native apps + AI = new possibilities that weren't possible before."

## The Strategic Phases

### Phase 1: Build the Bridge (Current Project)
**Goal:** Prove AI can discover and orchestrate any native app
**Timeline:** 6-12 months to v1.0
**Deliverable:** Working MCP server with JITD for macOS

**Success metric:**
Developers using Claude Desktop can control any Mac app without pre-configuration.

### Phase 2: Build User Interface
**Goal:** Make accessible to non-developers
**Timeline:** 6-12 months after Phase 1
**Deliverable:** Native app with visual/conversational workflow builder

**Success metric:**
Non-technical users create and run AI-powered workflows daily.

### Phase 3: Frontier Integration
**Goal:** Complete platform for AI-augmented local computing
**Timeline:** When both projects mature
**Deliverable:** Bridge ↔ Frontier integration

**Success metric:**
Power users build complex workflows combining AI + apps + Frontier.

### Phase 4: Ecosystem Growth
**Goal:** Industry standard for AI-native app integration
**Timeline:** 2+ years
**Deliverable:** Community, marketplace, enterprise, cross-platform

**Success metric:**
100K+ active users, sustainable business, thriving ecosystem.

## Key Technical Decisions

### Architectural Principles
- **Platform-agnostic core:** Universal abstractions work across macOS/Windows/Linux
- **JITD over pre-configuration:** Discover apps dynamically, don't hard-code integrations
- **Tools over code generation:** LLM calls typed tools, not writing AppleScript strings
- **Local-first:** Runs on user's machine, data stays private
- **Layered architecture:** Clean separation (discovery, tools, execution, platform)

### Open Questions Requiring Discussion
1. **Phase 1 or Phase 2 first?** (MCP bridge for developers vs native app for users)
2. **Electron vs Swift?** (If building native app)
3. **Frontier integration timing?** (Design for it now or prove concept first?)
4. **Business model?** (One-time purchase, subscription, freemium, or start free for developers?)
5. **Project naming?** (osa-mcp is too technical, need product name eventually)

## Success Metrics

### Technical Validation
- Discovery time < 10 seconds for full system scan
- Tool execution success rate > 95%
- Works with 100+ Mac apps reliably
- Memory usage < 200MB with full cache

### User Validation
- Users create workflows they couldn't before
- Average 5+ hours/week time savings
- 70%+ retention after 3 months
- Real workflows shared in community

### Business Validation
- Users willing to pay $49+ (or $9.99/month)
- Sustainable revenue without VC funding
- Profitable unit economics
- Path to 10K+ paying customers

## Why This Will Work

1. **Real need:** People love their native apps, want AI, don't want cloud services
2. **Technical feasibility:** JITD possible, LLMs capable, platforms support IAC
3. **Market timing:** AI just got good enough (2023+), privacy concerns rising
4. **No competition:** No one else building universal IAC for AI
5. **Strategic position:** Not competing with AI/apps/platforms - bridging them
6. **Frontier legacy:** Proven non-programmers will learn powerful tools
7. **Unique expertise:** Right person with right skills at right time

## The Mission

**Give users control of their computing experience in the AI age.**

Just as they had in the '90s and '00s with Frontier, HyperCard, and powerful local tools.

Stop forcing people to sign up for a gazillion .io cloud services.

Make AI work with the rich ecosystem of native apps everyone else ignores.

Enable interoperability: **Everything works with everything else.**

---

## Document Structure

This vision is documented across several files:

- **VISION.md** (this file) - High-level overview
- **ideas/the-complete-vision.md** - Complete detailed vision
- **ideas/frontier-vision.md** - Frontier legacy and democratization angle
- **ideas/product-reframe.md** - Evolution from MCP server to complete product
- **ideas/jitd-concept.md** - Technical foundation: Just-In-Time Discovery
- **ideas/universal-iac-vision.md** - Cross-platform IAC architecture
- **ideas/tool-explosion-solutions.md** - Handling thousands of tools
- **ideas/architecture-overview.md** - System design and components

Read `ideas/the-complete-vision.md` for the full story.
