# Implementation Plans

This directory contains active and upcoming implementation work, organized by initiative.

## Current Initiatives

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
