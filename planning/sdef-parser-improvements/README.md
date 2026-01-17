# SDEF Parser Improvements

> **Status**: Planning
> **Created**: 2026-01-17
> **Priority**: High - Blocks 75% of potential app integrations

## Executive Summary

The current SDEF parser has a **25% success rate** (13/52 files) due to strict validation rules that reject real-world SDEF variations. Apple's own Script Editor handles these files gracefully, indicating our parser is over-engineered for perfect compliance rather than practical interoperability.

**Opportunity**: Fixing 4-5 key patterns could unlock **75% more tools** (39+ apps including System Events, Microsoft Office, Safari/Chrome, and major developer tools).

## Current State

| Metric | Value |
|--------|-------|
| Total SDEF files on system | 52 |
| Successfully parsed | 13 (25%) |
| Generating usable tools | 4-6 (8-12%) |
| Tools generated | 34 |

### Apps Currently Working

- Amphetamine (2 tools)
- BeardedSpice (3 tools)
- Viscosity (5 tools)
- Shortcuts/Shortcuts Events (24+ tools)
- Spotify (1 tool)
- Downcast (1 tool)

### Apps Blocked by Parser Issues

**High Value (Major Apps)**:
- Safari - web automation
- Google Chrome / Brave / Vivaldi - web automation
- Microsoft Office (Excel, Word, PowerPoint, Outlook) - enterprise automation
- System Events - system-wide automation (100+ commands)
- Finder - file management
- Xcode - developer tools

**Medium Value**:
- BBEdit - text editing
- Acorn - image editing
- Keynote/Pages/Numbers - Apple productivity
- Fantastical - calendar
- QuickTime Player - media

## Root Cause Analysis

| Issue | % of Failures | Affected Apps | Solution |
|-------|---------------|---------------|----------|
| Missing `type` attributes | 60% | Safari, Chrome, Office, Xcode | Infer type as `text` or use name heuristics |
| Child `<type>` elements | 20% | System Events (100+ commands) | Parse child elements, create union types |
| External XML entities | 15% | Pages, Numbers, Keynote | Whitelist trusted Apple paths |
| Non-standard formats | 5% | Microsoft Office | Generic fallbacks |

## Architecture Decision

**Recommended Approach: Strict + Lenient Mode**

```typescript
class SDEFParser {
  constructor(options?: {
    mode?: 'strict' | 'lenient';  // Default: lenient
    onWarning?: (warning: ParseWarning) => void;
  });
}
```

- **Strict mode**: Current behavior (fail fast, throw errors) - use in tests
- **Lenient mode**: Infer defaults, collect warnings, continue parsing - use in production

## Implementation Phases

| Phase | Goal | Model | Effort | Target Success Rate |
|-------|------|-------|--------|---------------------|
| [Phase 1](./PHASE-1-TYPE-INFERENCE.md) | Type inference for missing attributes | Sonnet | 2-3 days | 40% |
| [Phase 2](./PHASE-2-MULTI-TYPE-SUPPORT.md) | Multi-type/union support | Sonnet | 1-2 days | 60% |
| [Phase 3](./PHASE-3-EXTERNAL-ENTITIES.md) | External entity resolution | Sonnet | 3-5 days | 80% |
| [Phase 4](./PHASE-4-VALIDATION-METRICS.md) | Validation & metrics | Haiku | Ongoing | 85%+ |

## Files to Modify

- `src/jitd/discovery/parse-sdef.ts` - Main parser logic
- `src/types/sdef.ts` - Type definitions
- `src/jitd/tool-generator/type-mapper.ts` - Type mapping
- `src/jitd/discovery/entity-resolver.ts` - New file (Phase 3)
- `tests/unit/parse-sdef.test.ts` - Unit tests

## Success Metrics

| Phase | Target Success Rate | Apps Unlocked |
|-------|---------------------|---------------|
| Current | 25% | 4-6 |
| Phase 1 | 40% | +10-15 (Safari, Chrome, etc.) |
| Phase 2 | 60% | +10 (System Events) |
| Phase 3 | 80% | +5-10 (Apple iWork) |
| Phase 4 | 85%+ | Remaining edge cases |

## References

- [SDEF DTD Specification](file:///System/Library/DTDs/sdef.dtd)
- [AppleScript Language Guide](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/)
- Current parser: `src/jitd/discovery/parse-sdef.ts`
- Type definitions: `src/types/sdef.ts`
