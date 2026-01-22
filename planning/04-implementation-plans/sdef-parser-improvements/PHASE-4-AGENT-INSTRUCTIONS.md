# Phase 4 Agent-Specific Instructions

> **For AI Agents**: Detailed instructions for implementing Phase 4
> **Human Partner**: Use this to kick off work with Haiku/Sonnet agents

---

## Overview

Phase 4 is divided into clearly defined sub-tasks. Each task specifies:
- Which agent (Haiku/Sonnet) should handle it
- Exact deliverables expected
- Success criteria
- How to verify completion

---

## Agent Selection Guide

### Use Haiku For:
- ✅ Implementing well-defined interfaces
- ✅ Writing unit and integration tests
- ✅ Refactoring existing code
- ✅ Adding CLI flags and options
- ✅ Setting up CI/CD workflows
- ✅ Standard documentation updates

### Use Sonnet For:
- ✅ Analyzing data and identifying patterns
- ✅ Making strategic recommendations
- ✅ Writing user-facing documentation (troubleshooting, guides)
- ✅ Architectural decisions requiring judgment
- ✅ Complex problem diagnosis

---

## Phase 4A: Metrics Collector (Haiku)

### Task 4A.1: Type Definitions (30 min)

**Prompt for Haiku**:
```
Create type definitions for the SDEF parser metrics system.

CONTEXT:
- Project: iac-mcp SDEF parser (macOS automation)
- Current state: 1,322 passing tests, Phase 3 complete
- Goal: Track parse success/failure rates

DELIVERABLES:
1. Create file: src/jitd/discovery/parser-metrics.ts
2. Define interfaces:
   - ParseAttempt (single parse result)
   - ParserMetrics (aggregated metrics)
   - ErrorType (union type for error categories)
   - WarningCode (union type for warning codes)
   - ReportOptions (report generation config)

REQUIREMENTS:
- Follow existing type patterns in src/types/sdef.ts
- Use JSDoc comments for all public interfaces
- Include examples in comments

REFERENCE:
See detailed spec in PHASE-4-DETAILED-EXECUTION-PLAN.md §3.1

SUCCESS CRITERIA:
- File compiles with no TypeScript errors
- npm run build succeeds
- Types are exported and importable
```

### Task 4A.2: Core Implementation (90 min)

**Prompt for Haiku**:
```
Implement the ParserMetricsCollector class.

CONTEXT:
- Types are defined in src/jitd/discovery/parser-metrics.ts
- This class will be used by SDEFParser and coverage script

DELIVERABLES:
1. Implement ParserMetricsCollector class with:
   - recordAttempt(attempt: ParseAttempt): void
   - getMetrics(): ParserMetrics
   - reset(): void
   - getAttempts(): ReadonlyArray<ParseAttempt>
   - private classifyError(error: string): ErrorType

REQUIREMENTS:
- Follow DRY principle (no code duplication)
- Efficient aggregation (no N^2 algorithms)
- Immutable public APIs (return copies, not internal state)
- Error classification based on error message patterns

REFERENCE:
See detailed spec in PHASE-4-DETAILED-EXECUTION-PLAN.md §3.2

SUCCESS CRITERIA:
- npm run build succeeds
- npm run lint passes
- Class is instantiable and methods are callable
- No runtime errors in basic smoke test
```

### Task 4A.3: Unit Tests Part 1 (60 min)

**Prompt for Haiku**:
```
Write comprehensive unit tests for ParserMetricsCollector.

CONTEXT:
- Class implemented in src/jitd/discovery/parser-metrics.ts
- Project requires 100% test coverage (non-negotiable)

DELIVERABLES:
1. Create file: tests/unit/parser-metrics.test.ts
2. Test suites for:
   - recordAttempt() - happy path, edge cases
   - getMetrics() - aggregation logic, calculations
   - classifyError() - all error types
   - reset() - state clearing

REQUIREMENTS:
- 100% code coverage for tested methods
- Test all branches and edge cases
- Use descriptive test names ("should aggregate warnings by code")
- Follow existing test patterns in tests/unit/sdef-parser.test.ts

REFERENCE:
See test structure in PHASE-4-DETAILED-EXECUTION-PLAN.md §5.1

SUCCESS CRITERIA:
- npm test passes
- npm run test:coverage shows 100% for parser-metrics.ts
- All edge cases covered (empty arrays, null values, etc.)
```

### Task 4A.4: Report Generation (60 min)

**Prompt for Haiku**:
```
Add report generation methods to ParserMetricsCollector.

CONTEXT:
- Core class implemented and tested
- Need to generate human-readable reports

DELIVERABLES:
1. Add methods to ParserMetricsCollector:
   - generateMarkdownReport(options?: ReportOptions): string
   - toJSON(): string

REQUIREMENTS:
- Markdown format: Tables, headers, sorted lists
- JSON format: Valid JSON with all metrics
- Support ReportOptions (verbose, limit, includePerformance)
- Format numbers with appropriate precision

REFERENCE:
See example report in PHASE-4-DETAILED-EXECUTION-PLAN.md §11.1

SUCCESS CRITERIA:
- generateMarkdownReport() produces valid markdown
- toJSON() produces parseable JSON
- Reports include all key metrics
- Formatting is clean and readable
```

### Task 4A.5: Unit Tests Part 2 (60 min)

**Prompt for Haiku**:
```
Complete unit test coverage for ParserMetricsCollector.

CONTEXT:
- Report generation methods added
- Need 100% coverage including new methods

DELIVERABLES:
1. Add tests to tests/unit/parser-metrics.test.ts:
   - generateMarkdownReport() - format, options, content
   - toJSON() - valid JSON, completeness
   - Edge cases (empty metrics, large numbers)

REQUIREMENTS:
- Verify report format (tables, headers present)
- Test all ReportOptions combinations
- Validate JSON parseability
- Achieve 100% coverage

SUCCESS CRITERIA:
- npm run test:coverage shows 100% for parser-metrics.ts
- All tests pass
- No untested code paths remain
```

### Task 4A.6: SDEFParser Integration (60 min)

**Prompt for Haiku**:
```
Integrate ParserMetricsCollector with SDEFParser.

CONTEXT:
- SDEFParser in src/jitd/discovery/parse-sdef.ts
- Must be non-breaking change (optional metrics)

DELIVERABLES:
1. Modify SDEFParser:
   - Add optional metricsCollector to SDEFParserOptions
   - Record parse attempts in parse() method (try/catch)
   - Pass warnings, parse time, file stats to collector

REQUIREMENTS:
- Non-breaking: metrics collection is optional
- No-op if metricsCollector not provided
- Capture: success/failure, warnings, timing, file path
- Maintain existing behavior

REFERENCE:
See integration spec in PHASE-4-DETAILED-EXECUTION-PLAN.md §2.1

SUCCESS CRITERIA:
- All existing SDEFParser tests still pass
- npm run build succeeds
- Parser works with and without metrics collector
```

### Task 4A.7: Update SDEFParser Tests (30 min)

**Prompt for Haiku**:
```
Add tests for SDEFParser metrics integration.

CONTEXT:
- SDEFParser now supports optional metrics collection
- Need tests to verify integration works

DELIVERABLES:
1. Add tests to tests/unit/sdef-parser.test.ts:
   - Parser works without metrics collector (backward compat)
   - Parser records successful parse attempts
   - Parser records failed parse attempts
   - Warnings are captured in metrics

REQUIREMENTS:
- Existing tests must all pass
- New tests verify metrics integration only
- Don't duplicate existing parser tests

SUCCESS CRITERIA:
- npm test passes (all 1,322+ tests)
- New tests verify metrics are recorded correctly
- 100% coverage maintained
```

---

## Phase 4B: Coverage Script (Haiku)

### Task 4B.1: Review Existing Script (30 min)

**Prompt for Haiku**:
```
Review and document the existing coverage script.

CONTEXT:
- scripts/analyze-sdef-coverage.ts already exists (~600 lines)
- Need to understand it before refactoring

DELIVERABLES:
1. Read scripts/analyze-sdef-coverage.ts
2. Document in a comment:
   - Current architecture
   - Integration points for ParserMetricsCollector
   - Code to be replaced vs kept

REQUIREMENTS:
- Thorough code review
- Identify inline metrics logic (to be replaced)
- Identify SDEF discovery logic (to be kept)

SUCCESS CRITERIA:
- Clear understanding of refactoring scope
- Integration plan documented
- Ready to proceed with refactor
```

### Task 4B.2: Integrate Metrics Collector (60 min)

**Prompt for Haiku**:
```
Refactor coverage script to use ParserMetricsCollector.

CONTEXT:
- Script has inline metrics logic (lines ~565-590)
- Should use ParserMetricsCollector instead

DELIVERABLES:
1. Refactor scripts/analyze-sdef-coverage.ts:
   - Replace inline metrics with ParserMetricsCollector
   - Use collector.generateMarkdownReport()
   - Simplify aggregation code

REQUIREMENTS:
- Keep SDEF discovery logic unchanged
- Remove duplicated metrics code
- Maintain existing output format
- Script still runs standalone

SUCCESS CRITERIA:
- npm run tsx scripts/analyze-sdef-coverage.ts works
- Output format unchanged (or improved)
- Code is simpler and cleaner
```

### Task 4B.3: CLI Enhancements (30 min)

**Prompt for Haiku**:
```
Add CLI flags to coverage script.

CONTEXT:
- Script needs --json, --verbose, --apps-only flags
- Use process.argv parsing

DELIVERABLES:
1. Add to scripts/analyze-sdef-coverage.ts:
   - --json: Output JSON instead of markdown
   - --verbose: Show detailed error messages
   - --apps-only: Only scan /Applications (faster)

REQUIREMENTS:
- Use process.argv.includes() for flag detection
- Flags can be combined
- Default: markdown output, not verbose, all locations

SUCCESS CRITERIA:
- All flags work independently and in combination
- Help text available (--help flag)
- Default behavior unchanged (backward compat)
```

### Task 4B.4: Integration Tests (90 min)

**Prompt for Haiku**:
```
Write integration tests for coverage script.

CONTEXT:
- Script is end-to-end executable
- Need tests using fixtures, not real system files

DELIVERABLES:
1. Create tests/integration/sdef-coverage.test.ts
2. Test suites:
   - Basic execution (parse fixtures)
   - CLI flags (--json, --verbose, --apps-only)
   - Error handling (malformed files, permission denied)
   - Performance (timeout, large files)

REQUIREMENTS:
- Use test fixtures in tests/fixtures/sdef/
- Mock file system for permission tests
- Tests complete in < 5 seconds
- Don't scan real system (too slow for CI)

REFERENCE:
See test structure in PHASE-4-DETAILED-EXECUTION-PLAN.md §5.2

SUCCESS CRITERIA:
- npm run test:integration passes
- All CLI flags tested
- Error scenarios handled gracefully
```

### Task 4B.5: Performance Optimizations (30 min)

**Prompt for Haiku**:
```
Add timeout handling to coverage script.

CONTEXT:
- Parser could hang on malformed SDEF files
- Need 5-second timeout per file

DELIVERABLES:
1. Add to scripts/analyze-sdef-coverage.ts:
   - Timeout wrapper for parseSdef()
   - Record TIMEOUT errors in metrics
   - Continue to next file after timeout

REQUIREMENTS:
- Use Promise.race with timeout promise
- 5 second timeout per file
- Graceful degradation (log and continue)

SUCCESS CRITERIA:
- Script doesn't hang on slow/malformed files
- Timeout errors recorded in metrics
- Total scan time < 30 seconds for typical system
```

### Task 4B.6: Package.json Scripts (30 min)

**Prompt for Haiku**:
```
Add npm scripts for coverage commands.

CONTEXT:
- Need easy-to-remember commands for users

DELIVERABLES:
1. Add to package.json "scripts":
   - sdef:coverage (full scan)
   - sdef:coverage:json (JSON output)
   - sdef:coverage:fast (apps only)

REQUIREMENTS:
- Use tsx to run TypeScript directly
- Scripts work from project root
- Include in README examples

SUCCESS CRITERIA:
- npm run sdef:coverage works
- npm run sdef:coverage:json outputs JSON
- npm run sdef:coverage:fast is faster than full scan
```

---

## Phase 4C: Documentation (Sonnet)

### Task 4C.1: Baseline Analysis (30 min, Haiku)

**Prompt for Haiku**:
```
Run baseline coverage analysis and save results.

CONTEXT:
- Coverage script now complete
- Need baseline metrics for documentation

DELIVERABLES:
1. Execute: npm run sdef:coverage
2. Save output to: docs/baseline-metrics.md
3. Note key statistics:
   - Success rate
   - Top error types
   - Top apps by tool count

REQUIREMENTS:
- Run on development machine
- Full scan (not --apps-only)
- Capture complete output

SUCCESS CRITERIA:
- docs/baseline-metrics.md exists
- Contains complete coverage report
- Key statistics noted
```

### Task 4C.2: Results Analysis (60 min, Sonnet)

**Prompt for Sonnet**:
```
Analyze baseline coverage metrics and identify patterns.

CONTEXT:
- Baseline metrics in docs/baseline-metrics.md
- Need strategic analysis for documentation

DELIVERABLES:
1. Analyze baseline metrics:
   - What's the overall success rate?
   - What are the top 3 error types?
   - Are there patterns (e.g., all Microsoft apps fail)?
   - What's causing failures (parser issues vs app issues)?

2. Create analysis document:
   - Key findings
   - Root cause analysis
   - Recommendations for Phase 5+
   - User impact assessment

REQUIREMENTS:
- Strategic thinking and pattern recognition
- Consider both technical and user perspectives
- Prioritize improvements by impact

SUCCESS CRITERIA:
- Clear understanding of parser capabilities
- Actionable recommendations for next phase
- User impact well understood
```

### Task 4C.3: TROUBLESHOOTING.md (90 min, Sonnet)

**Prompt for Sonnet**:
```
Create comprehensive troubleshooting documentation.

CONTEXT:
- Users will encounter parse failures
- Need clear guidance for common issues

DELIVERABLES:
1. Create docs/TROUBLESHOOTING.md with sections:
   - Overview (what this doc covers)
   - Common Errors (each error type from baseline)
   - Known Limitations (unsupported patterns)
   - Workarounds (how to work around limitations)
   - Reporting Issues (how to get help)

REQUIREMENTS:
- User-facing language (not technical jargon)
- Concrete examples for each error
- Clear workarounds where possible
- Honest about limitations

REFERENCE:
See error types in baseline metrics
Consider user perspective and frustration points

SUCCESS CRITERIA:
- Users can diagnose common issues independently
- Each error type has clear explanation
- Workarounds provided where available
- Tone is helpful, not defensive
```

### Task 4C.4: SDEF-SUPPORT.md (60 min, Sonnet)

**Prompt for Sonnet**:
```
Create SDEF support matrix documentation.

CONTEXT:
- Users want to know which apps are supported
- Need clear support matrix

DELIVERABLES:
1. Create docs/SDEF-SUPPORT.md with:
   - Support Overview (high-level summary)
   - Supported Apps Table (name, version, tools count)
   - Unsupported Apps Table (name, reason)
   - App Categories (which types work best)
   - Testing Methodology (how we validated)

REQUIREMENTS:
- Based on baseline metrics
- Include success rate by app category
- Explain why some apps fail
- Set realistic expectations

SUCCESS CRITERIA:
- Users can quickly check if their app is supported
- Support matrix is clear and comprehensive
- Expectations are set appropriately
```

### Task 4C.5: Update DECISIONS.md (30 min, Sonnet)

**Prompt for Sonnet**:
```
Document Phase 4 findings in strategic decision log.

CONTEXT:
- planning/DECISIONS.md tracks all key decisions
- Need to document Phase 4 outcomes

DELIVERABLES:
1. Add to planning/DECISIONS.md:
   - Phase 4 completion summary
   - Key findings (success rate, error patterns)
   - Recommendations for Phase 5
   - Strategic implications

REQUIREMENTS:
- Concise (1-2 paragraphs)
- Focus on decisions and implications
- Include specific metrics

SUCCESS CRITERIA:
- DECISIONS.md updated
- Future readers understand Phase 4 outcomes
- Phase 5 priorities are clear
```

### Task 4C.6: Update README (30 min, Haiku)

**Prompt for Haiku**:
```
Add "Validation & Metrics" section to README.

CONTEXT:
- README needs coverage command documentation
- Users should know how to check parser capabilities

DELIVERABLES:
1. Add section to README.md after "Development":
   - Validation & Metrics heading
   - Coverage command examples
   - Link to TROUBLESHOOTING.md
   - Link to SDEF-SUPPORT.md

REQUIREMENTS:
- Clear examples of common usage
- Brief explanation of what metrics show
- Links to detailed docs

SUCCESS CRITERIA:
- README includes coverage commands
- Examples are copy-pasteable
- Links work
```

---

## Phase 4D: CI Integration (Haiku, Optional)

### Task 4D.1: GitHub Actions Workflow (60 min)

**Prompt for Haiku**:
```
Create GitHub Actions workflow for coverage tracking.

CONTEXT:
- Want automated coverage runs on PRs
- Track regressions over time

DELIVERABLES:
1. Create .github/workflows/sdef-coverage.yml:
   - Run on: pull_request, push to main
   - Steps: checkout, install, run coverage
   - Save coverage report as artifact
   - Comment on PR with summary

REQUIREMENTS:
- Use existing project setup (Node.js, npm)
- Timeout: 10 minutes max
- Save JSON output for comparison

SUCCESS CRITERIA:
- Workflow runs successfully
- Coverage report generated
- Artifacts saved
- PR comment posted
```

### Task 4D.2: Coverage Comparison (30 min)

**Prompt for Haiku**:
```
Create script to compare coverage metrics.

CONTEXT:
- Need to detect regressions (success rate drops)
- Compare current run to baseline

DELIVERABLES:
1. Create scripts/compare-coverage.ts:
   - Load baseline metrics (from artifact or file)
   - Load current metrics (from current run)
   - Calculate deltas (success rate, error counts)
   - Format PR comment with results

REQUIREMENTS:
- Clear delta presentation (+2%, -1 error, etc.)
- Highlight regressions in red
- Improvements in green

SUCCESS CRITERIA:
- Script produces formatted comparison
- PR comment is informative
- Regressions are obvious
```

---

## Verification Checklist

After each phase, verify:

### Phase 4A Complete
```bash
# All tests pass
npm test

# 100% coverage
npm run test:coverage | grep "All files"
# Should show: 100 | 100 | 100 | 100

# Lint passes
npm run lint

# Build succeeds
npm run build

# Manual smoke test
node -e "
const { ParserMetricsCollector } = require('./dist/jitd/discovery/parser-metrics.js');
const c = new ParserMetricsCollector();
c.recordAttempt({
  sdefPath: '/test.sdef',
  appName: 'Test',
  success: true,
  commandCount: 5,
  toolCount: 5,
  parseTimeMs: 100,
  warnings: [],
  fileSizeBytes: 1024
});
console.log(c.getMetrics());
"
```

### Phase 4B Complete
```bash
# Coverage script works
npm run sdef:coverage

# JSON output works
npm run sdef:coverage -- --json | jq .

# Fast scan works
npm run sdef:coverage -- --apps-only

# Integration tests pass
npm run test:integration

# Script completes in reasonable time
time npm run sdef:coverage -- --apps-only
# Should be < 10 seconds
```

### Phase 4C Complete
```bash
# All docs exist
ls docs/TROUBLESHOOTING.md
ls docs/SDEF-SUPPORT.md
ls docs/baseline-metrics.md

# Links work (check manually in docs)

# README updated
grep "Validation & Metrics" README.md
```

### Phase 4D Complete
```bash
# Workflow file exists
ls .github/workflows/sdef-coverage.yml

# Workflow is valid YAML
yamllint .github/workflows/sdef-coverage.yml

# Comparison script exists
ls scripts/compare-coverage.ts
```

---

## Common Issues & Solutions

### Issue: Tests Fail After Integration

**Symptom**: Existing SDEFParser tests fail after adding metrics integration

**Solution**:
1. Verify metrics collector is optional (no-op if not provided)
2. Check that parse behavior hasn't changed
3. Look for unintended side effects in parse() method
4. Rollback integration, make smaller incremental change

### Issue: Coverage Script Times Out

**Symptom**: Script runs > 60 seconds or hangs

**Solution**:
1. Add 5-second timeout per file (Promise.race)
2. Skip slow files after timeout
3. Log which files are slow for investigation
4. Consider parallel parsing (Promise.all with concurrency limit)

### Issue: 100% Coverage Not Achievable

**Symptom**: Coverage stuck at 95-99%, can't reach 100%

**Solution**:
1. Run `npm run test:coverage` and check HTML report
2. Identify uncovered lines (usually edge cases or error paths)
3. Add specific tests for uncovered branches
4. If truly unreachable code, add istanbul ignore comment (last resort)

### Issue: Baseline Metrics Show < 50% Success

**Symptom**: Success rate is much lower than expected

**Solution**:
1. This is a finding, not a failure!
2. Document the reality honestly
3. Analyze top error types
4. Recommend Phase 5 priorities based on data
5. Proceed with Phase 4 documentation

---

## Time Tracking Template

Copy this to track actual time spent:

```markdown
## Phase 4 Time Tracking

### Phase 4A (Estimate: 4-5h)
- [ ] Task 4A.1: Type Definitions (30m) - Actual: ___
- [ ] Task 4A.2: Core Implementation (90m) - Actual: ___
- [ ] Task 4A.3: Unit Tests Part 1 (60m) - Actual: ___
- [ ] Task 4A.4: Report Generation (60m) - Actual: ___
- [ ] Task 4A.5: Unit Tests Part 2 (60m) - Actual: ___
- [ ] Task 4A.6: SDEFParser Integration (60m) - Actual: ___
- [ ] Task 4A.7: Update Tests (30m) - Actual: ___
**Phase 4A Total**: Estimate 5h, Actual: ___

### Phase 4B (Estimate: 2-3h)
- [ ] Task 4B.1: Review Script (30m) - Actual: ___
- [ ] Task 4B.2: Integrate Collector (60m) - Actual: ___
- [ ] Task 4B.3: CLI Enhancements (30m) - Actual: ___
- [ ] Task 4B.4: Integration Tests (90m) - Actual: ___
- [ ] Task 4B.5: Performance (30m) - Actual: ___
- [ ] Task 4B.6: Package Scripts (30m) - Actual: ___
**Phase 4B Total**: Estimate 3h, Actual: ___

### Phase 4C (Estimate: 2-3h)
- [ ] Task 4C.1: Baseline Analysis (30m) - Actual: ___
- [ ] Task 4C.2: Results Analysis (60m) - Actual: ___
- [ ] Task 4C.3: TROUBLESHOOTING (90m) - Actual: ___
- [ ] Task 4C.4: SDEF-SUPPORT (60m) - Actual: ___
- [ ] Task 4C.5: Update DECISIONS (30m) - Actual: ___
- [ ] Task 4C.6: Update README (30m) - Actual: ___
**Phase 4C Total**: Estimate 3h, Actual: ___

### Phase 4D (Estimate: 1-2h, Optional)
- [ ] Task 4D.1: GitHub Actions (60m) - Actual: ___
- [ ] Task 4D.2: Coverage Comparison (30m) - Actual: ___
**Phase 4D Total**: Estimate 1.5h, Actual: ___

**Grand Total**: Estimate 10-12h, Actual: ___
```

---

## Final Pre-Flight Checklist

Before starting Phase 4, confirm:

- [ ] Read PHASE-4-DETAILED-EXECUTION-PLAN.md completely
- [ ] Understand the goal (metrics collection + validation)
- [ ] Git worktree created for Phase 4 work
- [ ] Current tests passing (1,322+)
- [ ] Have 8-12 hours available for focused work
- [ ] Haiku agent available for implementation
- [ ] Sonnet agent available for analysis/docs
- [ ] Clear on success criteria (100% coverage, baseline metrics)

**Ready to start? Begin with Task 4A.1 above.**

---

**Document Purpose**: Agent-executable instructions for Phase 4
**Target Audience**: AI agents (Haiku/Sonnet) + human partner
**Last Updated**: 2026-01-21
