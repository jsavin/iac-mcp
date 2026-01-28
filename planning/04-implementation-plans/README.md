# Implementation Plans

This directory contains active and upcoming implementation work, organized by initiative.

## Current Initiatives

### Stateful Query System ⭐ **NEW - CRITICAL PATH**
Status: **Ready for Implementation**

Enable Claude to query objects and read properties from scriptable apps. **This is the highest priority feature** - it unblocks the core use case (e.g., "What's my most recent email?").

**Main Plan:** [stateful-query-system.md](./stateful-query-system.md)

**Phases:**
1. **[Phase 1: Core Stateful Queries](./stateful-query-phase1.md)** (3-4 days) - **START HERE**
   - Three MCP tools: `query_object`, `get_properties`, `get_elements`
   - Stateful references with 15+ minute TTL
   - Ready for /doit workflow
2. **[Phase 2: Filtering & Advanced Queries](./stateful-query-phase2.md)** (2-3 days)
3. **[Phase 3: Property Setters](./stateful-query-phase3.md)** (1-2 days)
4. **[Phase 4: Sophisticated GC & Optimization](./stateful-query-phase4.md)** (2-3 days)

**Total Effort:** 8-10 days across 4 phases

---

### MVP Phase
Status: **In Progress** (Weeks 3-4)

Core MCP server implementation with JITD discovery engine:
- **WEEK-3-EXECUTION-LAYER.md** - Tool execution pipeline, JXA marshaling, result parsing
- **WEEK-4-INTEGRATION-PLAN.md** - End-to-end validation, Claude Desktop integration testing
- **MVP-IMPLEMENTATION.md** - MVP scope and requirements

Target: Working proof-of-concept with Finder, Shortcuts, and a few additional apps.

### SDEF Parser Improvements
Status: **Planning** (Future work)

Improve parser success rate from 25% to 80%+, unlocking major apps (Safari, Chrome, Office, System Events).

See: **sdef-parser-improvements/**
- **PHASE-1-TYPE-INFERENCE.md** - Add lenient parsing mode with type inference (50-60% success)
- **PHASE-2-MULTI-TYPE-SUPPORT.md** - Handle union types for complex apps
- **PHASE-3-EXTERNAL-ENTITIES.md** - Support XInclude external entities (security-critical)
- **PHASE-4-VALIDATION-METRICS.md** - Comprehensive coverage analysis and metrics
- **README.md** - Overview with expert reviews (System Architect, Security Reviewer, macOS Automation Expert)

## Planning for New Initiatives

When starting a new major initiative:

1. Create a new subdirectory: `initiative-name/`
2. Create `README.md` with overview and status
3. Create phase/sprint documents as needed
4. Update this index

Example structure:
```
windows-automation/
├── README.md          (overview, roadmap, status)
├── PHASE-1-COM-API.md (architecture & implementation)
└── ...
```

## Related Documents

- **Strategic Vision**: [01-vision-and-strategy/](../01-vision-and-strategy/)
- **Technical Architecture**: [03-technical-architecture/](../03-technical-architecture/)
- **Business Planning**: [02-business-operations/](../02-business-operations/)
- **Getting Started**: [00-getting-started/](../00-getting-started/)
