# Phase 4 Execution Roadmap

> **Visual guide** to implementing Phase 4: Parser Validation & Metrics
> **Navigate**: Each box is clickable in detailed plan (§7)

---

## Timeline Overview

```
Day 1 Morning (4-5h)  →  Day 1 Afternoon (2-3h)  →  Day 2 (2-3h)  →  Optional (1-2h)
     Phase 4A                  Phase 4B                 Phase 4C          Phase 4D
```

---

## Phase 4A: Metrics Collection Infrastructure

**Goal**: Build standalone metrics collector

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 4A (4-5 hours, Haiku)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 1: Type Definitions (30 min)                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Create src/jitd/discovery/parser-metrics.ts             │  │
│  │ - ParseAttempt interface                                │  │
│  │ - ParserMetrics interface                               │  │
│  │ - ErrorType, WarningCode types                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 2: Core Implementation (90 min)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ ParserMetricsCollector class                            │  │
│  │ - recordAttempt()                                       │  │
│  │ - getMetrics()                                          │  │
│  │ - classifyError()                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 3: Unit Tests Part 1 (60 min)                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ tests/unit/parser-metrics.test.ts                       │  │
│  │ - Test recordAttempt()                                  │  │
│  │ - Test getMetrics()                                     │  │
│  │ - Test aggregation logic                                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 4: Report Generation (60 min)                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Add to parser-metrics.ts                                │  │
│  │ - generateMarkdownReport()                              │  │
│  │ - toJSON()                                              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 5: Unit Tests Part 2 (60 min)                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Complete tests/unit/parser-metrics.test.ts              │  │
│  │ - Test report generation                                │  │
│  │ - Test edge cases                                       │  │
│  │ - Verify 100% coverage                                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 6: SDEFParser Integration (60 min)                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Modify src/jitd/discovery/parse-sdef.ts                │  │
│  │ - Add optional metricsCollector param                   │  │
│  │ - Record parse attempts in parse()                      │  │
│  │ - Non-breaking change                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 7: Update SDEFParser Tests (30 min)                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Modify tests/unit/sdef-parser.test.ts                  │  │
│  │ - Test metrics integration                              │  │
│  │ - Verify existing tests pass                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ✅ Deliverable: ParserMetricsCollector ready for use          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 4B: Coverage Script Enhancement

**Goal**: Integrate metrics with coverage script

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 4B (2-3 hours, Haiku)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 8: Review Existing Script (30 min)                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Read scripts/analyze-sdef-coverage.ts                   │  │
│  │ - Understand current implementation                     │  │
│  │ - Identify integration points                           │  │
│  │ - Plan refactoring approach                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 9: Integrate Metrics Collector (60 min)                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Refactor scripts/analyze-sdef-coverage.ts               │  │
│  │ - Replace inline metrics with ParserMetricsCollector    │  │
│  │ - Simplify aggregation logic                            │  │
│  │ - Use collector.generateMarkdownReport()                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 10: CLI Enhancements (30 min)                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Add CLI flags to analyze-sdef-coverage.ts               │  │
│  │ - --json: JSON output                                   │  │
│  │ - --verbose: Detailed errors                            │  │
│  │ - --apps-only: Fast scan                                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 11: Integration Tests (90 min)                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Create tests/integration/sdef-coverage.test.ts          │  │
│  │ - Test with fixtures                                    │  │
│  │ - Test all CLI flags                                    │  │
│  │ - Test error handling                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 12: Performance Optimizations (30 min)                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Add timeout handling to analyze-sdef-coverage.ts        │  │
│  │ - 5s per file timeout                                   │  │
│  │ - Parallel parsing (if needed)                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 13: Package.json Scripts (30 min)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Add to package.json                                     │  │
│  │ - sdef:coverage                                         │  │
│  │ - sdef:coverage:json                                    │  │
│  │ - sdef:coverage:fast                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ✅ Deliverable: npm run sdef:coverage works end-to-end         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 4C: Documentation & Analysis

**Goal**: Document findings and limitations

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 4C (2-3 hours, Sonnet)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 14: Baseline Coverage Analysis (30 min, Haiku)           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Run: npm run sdef:coverage                              │  │
│  │ - Capture output to docs/baseline-metrics.md            │  │
│  │ - Record success rate, error patterns                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 15: Analyze Results (60 min, Sonnet)                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Review baseline metrics                                 │  │
│  │ - Identify common failure patterns                      │  │
│  │ - Categorize errors by root cause                       │  │
│  │ - Assess strategic implications                         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 16: Create TROUBLESHOOTING.md (90 min, Sonnet)           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Create docs/TROUBLESHOOTING.md                          │  │
│  │ - Known limitations                                     │  │
│  │ - Common errors & solutions                             │  │
│  │ - Workarounds                                           │  │
│  │ - How to report issues                                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 17: Create SDEF-SUPPORT.md (60 min, Sonnet)              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Create docs/SDEF-SUPPORT.md                             │  │
│  │ - Support matrix (apps tested)                          │  │
│  │ - Success rate by app category                          │  │
│  │ - Known unsupported patterns                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 18: Update Strategic Docs (30 min, Sonnet)               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Update planning/DECISIONS.md                            │  │
│  │ - Document findings                                     │  │
│  │ - Recommendations for Phase 5+                          │  │
│  │ - Strategic implications                                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 19: Update README (30 min, Haiku)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Add "Validation & Metrics" section to README.md         │  │
│  │ - Coverage command examples                             │  │
│  │ - Link to troubleshooting docs                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ✅ Deliverable: Comprehensive documentation published          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 4D: CI/CD Integration (Optional)

**Goal**: Automate coverage tracking

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 4D (1-2 hours, Haiku)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 20: GitHub Actions Workflow (60 min)                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Create .github/workflows/sdef-coverage.yml              │  │
│  │ - Run on PR and main branch                             │  │
│  │ - Save coverage metrics as artifact                     │  │
│  │ - Comment on PR with results                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  Step 21: Coverage Comparison (30 min)                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Create scripts/compare-coverage.ts                      │  │
│  │ - Compare current vs baseline                           │  │
│  │ - Detect regressions                                    │  │
│  │ - Format PR comment                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ✅ Deliverable: Automated coverage tracking in CI              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Dependency Graph

```
Phase 4A (Metrics Collector)
    ↓
Phase 4B (Coverage Script)
    ↓
Phase 4C (Documentation)
    ↓ (optional)
Phase 4D (CI Integration)
```

**Critical Path**: 4A → 4B → 4C
**Optional**: 4D (can be done later)

---

## Parallel Work Opportunities

While waiting for reviews or tests to run:

```
┌─────────────────────┐   ┌─────────────────────┐
│ Unit Tests Running  │   │ Write Documentation │
│     (2-3 min)       │   │    (5-10 min)       │
└─────────────────────┘   └─────────────────────┘
         ↓                         ↓
    Review output           Create examples
         ↓                         ↓
    Fix failures            Update README
```

**Tip**: Don't sit idle while tests run. Write docs, create examples, or review existing code.

---

## Quality Gates

Each phase must pass these gates before proceeding:

### After Phase 4A
- [ ] `npm test` passes (all existing + new tests)
- [ ] `npm run test:coverage` shows 100% for parser-metrics.ts
- [ ] `npm run lint` passes with no errors
- [ ] Manual smoke test: Metrics collector works standalone

### After Phase 4B
- [ ] `npm run sdef:coverage` completes without errors
- [ ] `npm run sdef:coverage -- --json` outputs valid JSON
- [ ] All CLI flags work as expected
- [ ] Integration tests pass

### After Phase 4C
- [ ] Baseline metrics captured and documented
- [ ] TROUBLESHOOTING.md covers all error types
- [ ] SDEF-SUPPORT.md provides clear support matrix
- [ ] README updated with coverage examples

### Before PR
- [ ] All quality gates passed
- [ ] 100% test coverage maintained
- [ ] Documentation complete and proofread
- [ ] `npm run build` succeeds
- [ ] Git commit history is clean and descriptive

---

## Rollback Points

If something goes wrong, revert to these safe states:

| Rollback Point | Command | State |
|----------------|---------|-------|
| Before Phase 4A | `git reset --hard HEAD~7` | Pre-metrics code |
| Before Phase 4B | `git reset --hard HEAD~6` | Metrics done, script unchanged |
| Before Phase 4C | `git reset --hard HEAD~5` | Code done, no docs |

**Tip**: Create git tags at each phase completion for easy rollback.

```bash
git tag phase-4a-complete
git tag phase-4b-complete
git tag phase-4c-complete
```

---

## Success Indicators

You'll know Phase 4 is successful when:

1. ✅ **Metrics work**: `collector.getMetrics()` returns accurate data
2. ✅ **Script works**: `npm run sdef:coverage` generates report
3. ✅ **Tests pass**: 1,322+ tests, 100% coverage
4. ✅ **Docs help**: Users can troubleshoot common issues
5. ✅ **Baseline captured**: You know exact success rate and error patterns

**Red Flags** (stop and reassess):
- ❌ Test coverage drops below 100%
- ❌ Existing tests start failing
- ❌ Coverage script takes > 60 seconds
- ❌ Success rate < 25% (indicates major issues)

---

## Estimated vs Actual Tracking

Use this table to track progress:

| Phase | Estimated | Started | Completed | Actual | Delta |
|-------|-----------|---------|-----------|--------|-------|
| 4A    | 4-5h      | ___     | ___       | ___    | ___   |
| 4B    | 2-3h      | ___     | ___       | ___    | ___   |
| 4C    | 2-3h      | ___     | ___       | ___    | ___   |
| 4D    | 1-2h      | ___     | ___       | ___    | ___   |
| Total | 8-12h     | ___     | ___       | ___    | ___   |

**Post-Phase Learning**: Document what took longer/shorter than expected to improve future estimates.

---

## Next Steps After Phase 4

Once Phase 4 is complete:

1. **Review baseline metrics** - What's the success rate?
2. **Prioritize Phase 5** - Based on error patterns
3. **Celebrate** - You've built production-grade validation infrastructure!
4. **Share results** - Update stakeholders with findings

**Possible Phase 5 Focus**:
- If success rate < 70%: Parser robustness improvements
- If MISSING_TYPE is #1 error: Enhanced type inference
- If XML_PARSE_ERROR is common: Error recovery mechanisms

**Data-driven decision making** starts after Phase 4!

---

**Quick Links**:
- [Detailed Execution Plan](./PHASE-4-DETAILED-EXECUTION-PLAN.md)
- [Quick Reference](./PHASE-4-QUICK-REFERENCE.md)
- [High-Level Phase 4 Overview](./PHASE-4-VALIDATION-METRICS.md)

**Status**: Ready for execution
**Last Updated**: 2026-01-21
