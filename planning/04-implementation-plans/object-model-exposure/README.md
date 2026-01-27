# Object Model Exposure - Making App Data Queryable

**Status:** Planning
**Priority:** High
**Confidence:** 90% feasible

---

## Problem Statement

### The Gap We Discovered

Currently, iac-mcp only exposes **commands** as MCP tools (e.g., `calendar_create_event`, `finder_open`). The **object model** (classes, properties, relationships) is invisible to the LLM.

**What this means in practice:**

User: "Figure out my availability by checking Calendar.app"

**Current behavior:**
- LLM sees: `calendar_create_event`, `calendar_delete_event`
- LLM **cannot** see: Calendar objects, Event objects, properties (startDate, endDate, summary)
- LLM falls back to raw AppleScript via `osascript` command-line tool
- Result: Clunky, inefficient, defeats the JITD philosophy

**What we want:**
- LLM sees: Calendar class, Event class, query_calendar_objects tool
- LLM knows: Events have startDate, endDate, summary properties
- LLM calls: `query_calendar_objects({ objectType: "event", filter: "today" })`
- Result: Natural, efficient, self-describing interface

### Why This Matters for JITD Vision

Our core vision is **self-describing interfaces** - apps should expose their full capabilities without manual API building. Right now, we're only halfway there:

✅ Commands auto-discovered and exposed
❌ Object model invisible, forcing manual scripting workarounds

This gap undermines the JITD value proposition.

---

## Solution Approach

### Core Idea: Parse SDEF Classes → Generate Types + Resources + Query Tools

**SDEF files already contain the object model** in their `<class>` sections. We just need to:

1. **Parse class definitions** from SDEF (classes, properties, inheritance, enumerations)
2. **Generate TypeScript types** for the object model (calendars, events, etc.)
3. **Expose as MCP resources** (queryable endpoints like `calendar://Calendar/events`)
4. **Add generic query tools** that work across all apps

**This maintains JITD philosophy**: Zero manual schema building per app.

### Architecture Overview

```
SDEF File (input)
    ↓
┌─────────────────────────────────────────┐
│ Parse Commands → MCP Tools              │ ✅ Already works
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Parse Classes → TypeScript Types (NEW)  │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Generate MCP Resources (NEW)            │
│   - calendar://Calendar/calendars       │
│   - calendar://Calendar/events          │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Generate Query Tools (NEW)              │
│   - query_calendar_objects()            │
│   - get_calendar_properties()           │
└─────────────────────────────────────────┘
```

### Progressive Discovery Strategy

**Hybrid approach (recommended):**

1. **On ListTools request**: Show command tools + generic `query_app_objects` tool
2. **First query call for an app**: Parse classes, generate types, cache them
3. **Subsequent calls**: Use cached schema, execute directly

**Benefits:**
- Scalable (only pays cost for used apps)
- Signals capability upfront (LLM knows it can query)
- Preserves progressive discovery philosophy

---

## Implementation Phases

### Phase 1: Calendar.app Proof of Concept (Weeks 1-2)

**Goal:** Prove the concept with simplest SDEF structure

**Tasks:**
- Parse Calendar.app SDEF classes (6 classes, no inheritance)
- Generate TypeScript types (auto-generated to file)
- Implement simple query tool (predefined filters: "today", "this week")
- Test with Claude Desktop: "What meetings do I have today?"

**Success criteria:**
- ✅ LLM can query events without raw AppleScript
- ✅ TypeScript types accurately reflect Calendar object model
- ✅ Query execution via JXA works reliably

### Phase 2: Generalize (Weeks 3-4)

**Goal:** Expand to complex apps, refine type mappings

**Tasks:**
- Test with Finder.app (31 classes, 4-level inheritance)
- Test with Mail.app (26 classes, union types, complex relationships)
- Refine type mapper (handle edge cases discovered)
- Generate MCP resources for all three apps
- Document patterns and edge cases

**Success criteria:**
- ✅ Works across apps with varying complexity
- ✅ Type generation handles inheritance, unions, lists
- ✅ 85%+ of SDEF classes map correctly

### Phase 3: Security & Performance (Weeks 5-6)

**Goal:** Production-ready implementation

**Tasks:**
- JXA filter validation (prevent code injection)
- Permission system integration (query approval flow)
- Performance optimization (pagination, result limits)
- Error handling (malformed queries, timeout)
- Documentation and examples

**Success criteria:**
- ✅ No security vulnerabilities (validated filters)
- ✅ Queries complete in <5s (with pagination if needed)
- ✅ Graceful degradation (apps without class definitions)

---

## Key Questions & Decisions

### Progressive Discovery
- **Decision:** Use hybrid strategy (expose generic tool upfront, lazy-load schemas)
- **Rationale:** Balances scalability with LLM awareness

### TypeScript Type Mapping
- **Decision:** Generate interfaces (not classes), all properties optional
- **Rationale:** SDEF doesn't clearly mark required/optional - safer to assume optional

### Query Tool Design
- **Phase 1:** Predefined safe queries ("today", "this week", "all")
- **Phase 2+:** Consider JXA filter expressions (requires security validation)

### Resource Exposure
- **Decision:** Generate MCP resources for each class (e.g., `calendar://Calendar/events`)
- **Rationale:** Provides discoverable endpoints for LLM to explore

---

## Risks & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| **SDEF class coverage inconsistent** | Medium | Medium | Test top 10 apps early, graceful degradation |
| **JXA query security** | High | High | Start with predefined queries, validate expressions in Phase 3 |
| **Performance at scale** | Medium | Medium | Pagination, result limits, server-side filtering |
| **Type generation accuracy** | Low | Low | Types are hints, not runtime enforcement - iterate and improve |

---

## Research Findings

**Complete analysis in:** `01-research-findings.md`

**TL;DR:**
- ✅ Analyzed 64 classes across Finder (31), Mail (26), Calendar (7)
- ✅ 95% consistency in property type mapping
- ✅ Standard inheritance patterns (TypeScript `extends` works)
- ✅ Predictable enumeration structures
- ⚠️ Union types, specifier types, list syntax variations (manageable)

**Confidence:** 90% that auto-generation will work for 85-95% of real-world SDEF files.

---

## Documentation Structure

| Document | Purpose | Status |
|----------|---------|--------|
| **README.md** (this file) | Overview, problem, solution, phases | ✅ Complete |
| **01-research-findings.md** | SDEF class analysis (Explore agent output) | 🔄 In progress |
| **02-design.md** | Architecture, type mapping, query tool design | 📝 Planned |
| **03-phase1-calendar-poc.md** | Calendar.app proof of concept plan | 📝 Planned |
| **04-phase2-generalization.md** | Expand to other apps | 📝 Planned |
| **05-phase3-security.md** | JXA security, permissions, performance | 📝 Planned |
| **decisions.md** | Key decisions made during implementation | 📝 Planned |

---

## Next Steps

1. ✅ Research complete (SDEF class analysis done)
2. 🔄 Write planning documents (in progress)
3. 📝 Get user approval on approach
4. 📝 Start Phase 1 implementation (Calendar POC)

---

## Related Documents

- **[JITD Concept](../../01-vision-and-strategy/ideas/jitd-concept.md)** - Just-In-Time Discovery philosophy
- **[VISION.md](../../01-vision-and-strategy/VISION.md)** - Overall project vision
- **[CODE-QUALITY.md](../../../CODE-QUALITY.md)** - 100% test coverage required
