# Phase 4 Quick Reference

> **TL;DR**: Implement metrics collection, run coverage analysis, document findings.
> **Time**: 8-12 hours | **Agent**: 80% Haiku, 20% Sonnet | **Risk**: Low

---

## What We're Building

1. **ParserMetricsCollector** class - Track parse success/failure
2. **Enhanced coverage script** - Analyze all system SDEFs
3. **Comprehensive docs** - TROUBLESHOOTING.md, SDEF-SUPPORT.md
4. **CI integration** (optional) - Automated coverage tracking

---

## Quick Start

### Setup
```bash
cd /Users/jake/dev/jsavin/iac-mcp
git worktree add ../iac-mcp-phase-4-metrics -b feature/phase-4-parser-metrics
cd ../iac-mcp-phase-4-metrics
npm install
```

### Implementation Sequence

**Day 1 Morning** (4-5 hrs, Haiku):
1. Create `src/jitd/discovery/parser-metrics.ts` (interfaces + class)
2. Write unit tests `tests/unit/parser-metrics.test.ts`
3. Integrate with SDEFParser (optional param)

**Day 1 Afternoon** (2-3 hrs, Haiku):
4. Enhance `scripts/analyze-sdef-coverage.ts` (use metrics collector)
5. Write integration tests `tests/integration/sdef-coverage.test.ts`
6. Add npm scripts to `package.json`

**Day 2** (2-3 hrs, Sonnet):
7. Run baseline coverage analysis
8. Create `docs/TROUBLESHOOTING.md` and `docs/SDEF-SUPPORT.md`
9. Document findings in `planning/DECISIONS.md`

---

## Key APIs

### ParserMetricsCollector
```typescript
const collector = new ParserMetricsCollector();

collector.recordAttempt({
  sdefPath: '/path/to/app.sdef',
  appName: 'MyApp',
  success: true,
  commandCount: 10,
  toolCount: 10,
  parseTimeMs: 150,
});

const metrics = collector.getMetrics();
// { successfulParses: 43, failedParses: 9, parseSuccessRate: 82.7, ... }

console.log(collector.generateMarkdownReport());
```

### Coverage Script
```bash
npm run sdef:coverage                 # Full analysis
npm run sdef:coverage -- --json       # JSON output
npm run sdef:coverage -- --verbose    # Show errors
npm run sdef:coverage -- --apps-only  # Fast scan
```

---

## Success Criteria

- [ ] **100% test coverage** for all new code
- [ ] **ParserMetricsCollector** working and tested
- [ ] **Coverage script** enhanced and documented
- [ ] **Baseline metrics** captured (≥80% success rate target)
- [ ] **Documentation** complete (TROUBLESHOOTING + SDEF-SUPPORT)

---

## Edge Cases to Handle

1. **Permission denied** → Skip gracefully, warn user
2. **Malformed SDEF** → Classify error, continue scanning
3. **Large files** → Enforce 10MB limit (existing)
4. **Timeouts** → 5s per file max
5. **Empty/invalid files** → Detect early, fail fast

---

## Testing Strategy

**Unit Tests** (100% coverage):
- `ParserMetricsCollector`: All methods, edge cases, error classification

**Integration Tests** (critical paths):
- Coverage script with fixtures
- CLI flags (--json, --verbose, --apps-only)
- Error handling (permission denied, malformed files)

**Fixtures Needed**:
```
tests/fixtures/sdef/
├── valid/               # Clean SDEF files
├── edge-cases/          # Type inference, union types
└── invalid/             # Malformed, empty, wrong format
```

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Tests fail after integration | Make metrics collector truly optional (no-op if not provided) |
| Coverage script times out | Add aggressive 5s timeout per file |
| Permission prompts on system files | Document Full Disk Access requirement |
| Success rate < 80% | Document findings, defer fixes to Phase 5 |

---

## Deliverables Checklist

**Code**:
- [ ] `src/jitd/discovery/parser-metrics.ts` (~400 lines)
- [ ] `tests/unit/parser-metrics.test.ts` (~500 lines)
- [ ] `tests/integration/sdef-coverage.test.ts` (~300 lines)
- [ ] Enhanced `scripts/analyze-sdef-coverage.ts`

**Documentation**:
- [ ] `docs/TROUBLESHOOTING.md`
- [ ] `docs/SDEF-SUPPORT.md`
- [ ] `docs/baseline-metrics.md`
- [ ] Updated `README.md`

**Metrics**:
- [ ] Baseline coverage report generated
- [ ] Error patterns identified
- [ ] Recommendations for Phase 5 documented

---

## Agent Assignment

| Phase | Agent | Hours | Why |
|-------|-------|-------|-----|
| 4A: Metrics collector | Haiku | 4-5 | Straightforward class implementation |
| 4B: Coverage script | Haiku | 2-3 | Integration work, testing |
| 4C: Documentation | Sonnet | 2-3 | Analysis, judgment, user-facing docs |
| 4D: CI integration | Haiku | 1-2 | Standard GitHub Actions |

**Tip**: Use Haiku for implementation/testing, Sonnet for analysis/documentation.

---

## Exit Criteria

Before marking Phase 4 complete:

1. ✅ All tests pass (1,322+ tests)
2. ✅ 100% coverage maintained
3. ✅ `npm run sdef:coverage` works end-to-end
4. ✅ Baseline metrics captured and documented
5. ✅ Troubleshooting docs complete
6. ✅ PR created and ready for review

**Next**: Create PR, get approval, merge to master, proceed to Phase 5 (if needed based on metrics).

---

## Time Estimates

| Task | Est. | Actual |
|------|------|--------|
| Metrics collector + tests | 4-5h | ___ |
| Coverage script + tests | 2-3h | ___ |
| Documentation + analysis | 2-3h | ___ |
| CI integration (optional) | 1-2h | ___ |
| **Total** | **8-12h** | ___ |

**Note**: Track actual time to improve future estimates.

---

## Quick Links

- **Full Plan**: [PHASE-4-DETAILED-EXECUTION-PLAN.md](./PHASE-4-DETAILED-EXECUTION-PLAN.md)
- **High-Level Overview**: [PHASE-4-VALIDATION-METRICS.md](./PHASE-4-VALIDATION-METRICS.md)
- **Code Quality Standards**: [CODE-QUALITY.md](../../../CODE-QUALITY.md)
- **Project Instructions**: [CLAUDE.md](../../../CLAUDE.md)

---

**Status**: Ready for execution
**Last Updated**: 2026-01-21
