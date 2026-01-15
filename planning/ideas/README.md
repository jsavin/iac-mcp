# Ideas & Brainstorming

This directory captures the conceptual foundation and key ideas for the IAC MCP project.

## What's Here

These documents represent our thinking about the **what** and **why** of the project:

### Core Concepts
- **jitd-concept.md** - Just-In-Time Discovery: the fundamental insight that makes this work
- **universal-iac-vision.md** - The big picture: universal IAC layer across all platforms
- **tool-explosion-solutions.md** - How to handle tens of thousands of potential tools
- **architecture-overview.md** - System design and component breakdown

## Relationship to Other Planning Docs

```
planning/
├── ideas/              ← You are here (conceptual, exploratory)
│   ├── Core concepts
│   ├── Big vision
│   └── Architecture ideas
│
├── technical/          ← Practical implementation details
│   ├── How to parse SDEF files
│   ├── Caching strategy
│   └── Permission system
│
├── architecture/       ← Concrete architectural decisions
│   └── Distribution model (Node.js vs app)
│
└── business/          ← Business model and monetization
    └── (TBD)
```

## Key Insights from Brainstorming

### 1. JITD Over Code Generation
**Instead of:** LLM writes AppleScript code → execute string → hope it works
**We do:** Discover capabilities → generate typed tools → LLM calls tools → validated execution

**Why it matters:**
- Type safety
- Better error messages
- Platform abstraction
- No syntax errors

### 2. Universal IAC, Not Just macOS
**Initial thought:** Build an AppleScript MCP server for macOS
**Actual vision:** Universal application automation layer across macOS, Windows, Linux, and eventually web/cloud

**Why it matters:**
- 14x larger market (Windows)
- Future-proof architecture
- Real moat against competitors
- Enables cross-platform workflows

### 3. Tools as First-Class Citizens
**Pattern:** Applications expose capabilities → We expose as tools
**Not:** Applications have scripting languages → We execute scripts

**Why it matters:**
- Tools are the native MCP primitive
- Better LLM integration
- Cleaner abstraction
- Easier to extend

### 4. The Tool Explosion is Real
**Reality:** System-wide could have 10,000-50,000 tools
**Solution:** Multi-tier strategy (eager, lazy, on-demand)

**Why it matters:**
- Can't register everything upfront
- Need smart discovery mechanisms
- Performance and UX concerns
- This is a first-order design constraint

## Evolution of Thinking

### Phase 1: AppleScript Executor
> "Let's build an MCP server that executes AppleScript"
- Too narrow
- LLM writes code (error-prone)
- Platform lock-in

### Phase 2: Dynamic Tool Generation
> "What if we parse SDEF and generate tools?"
- Better abstraction
- Type-safe
- But still macOS-only

### Phase 3: Universal IAC with JITD
> "Platform-agnostic application automation with just-in-time tool discovery"
- Scales to any platform
- Future-proof
- Real business potential
- **This is where we landed**

## Open Questions

These remain unanswered and will need research/prototyping:

1. **MCP Protocol Limits**
   - How many tools can MCP handle?
   - Can tools be registered dynamically after startup?
   - Performance implications of large tool counts?

2. **LLM Behavior**
   - Will LLMs use discovery tools effectively?
   - Do they prefer many specific tools or few generic ones?
   - How does tool count affect success rate?

3. **Type Mapping**
   - Can we reliably map AppleScript types to JSON?
   - What about complex object specifiers?
   - How to handle platform-specific types?

4. **Cross-Platform Normalization**
   - Can we create truly universal tools (e.g., `file_manager_list_folder`)?
   - Or is it better to have platform-specific tools?
   - How much abstraction is too much?

5. **Business Validation**
   - Will users pay for this?
   - What's the right pricing model?
   - Enterprise vs consumer focus?

## Next Steps

To move from ideas to implementation:

1. **Prototype JITD on macOS**
   - Parse a single SDEF file
   - Generate tools for Finder
   - Test with real LLM (Claude Desktop)
   - Validate the concept works

2. **Test Tool Explosion Solutions**
   - Try registering 1000+ tools
   - Measure performance
   - Test lazy discovery UX
   - Find optimal strategy

3. **Design Platform Adapter Interface**
   - Define clean abstraction
   - Prototype macOS adapter
   - Validate extensibility to Windows

4. **Research AppleEvents vs JXA**
   - Which is more reliable?
   - Performance comparison
   - Type mapping challenges
   - Make concrete choice

5. **Build Permission System**
   - Design UX for confirmations
   - Implement safety rules
   - Test with destructive operations
   - Prove it's safe enough for real use

## Reading Guide

**If you're new to the project**, start with:
1. `jitd-concept.md` - Understand the core insight
2. `universal-iac-vision.md` - See the big picture
3. `architecture-overview.md` - Understand the system design

**If you're implementing**, focus on:
1. `architecture-overview.md` - System structure
2. `tool-explosion-solutions.md` - Practical constraints
3. Then move to `planning/technical/` for implementation details

**If you're evaluating the business**, read:
1. `universal-iac-vision.md` - Market opportunity
2. `planning/architecture/04-distribution-model.md` - Go-to-market
3. `planning/business/` (once created) - Business model

## The Complete Vision

**Read [the-complete-vision.md](the-complete-vision.md) for the full story.**

This project is **one half of a two-project strategy:**
1. **IAC MCP Bridge** (this project) - Bridge AI to native apps
2. **Modernized Frontier** (separate effort) - Foundation for local computing workflows

Together they form a complete platform for AI-augmented local computing.

**Core insight:** AI companies are web-centric and miss the vast world of native apps. This bridges that gap using Just-In-Time Discovery (JITD) to work with any installed application.

**Philosophy:** Interoperability above all. Make everything work with everything else.

## Status

🔵 **Vision Phase** - Core vision documented and aligned. Ready to discuss implementation strategy.

## Contributing Ideas

When adding new ideas here:
- Focus on the "why" not just the "what"
- Explain trade-offs and alternatives
- Leave questions open when unsure
- Link to related ideas in other docs
- Date your additions
- Mark speculative ideas clearly
