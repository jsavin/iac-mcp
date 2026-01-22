# Phase 4: Parser Validation & Metrics - Detailed Execution Plan

> **Status**: Ready for execution
> **Total Effort**: 8-12 hours (1-1.5 days)
> **Dependencies**: Phase 3 complete (1,322 passing tests)
> **Goal**: Production validation, metrics collection, and systematic documentation of parser capabilities and limitations

---

## Executive Summary

Phase 4 establishes production-grade validation infrastructure for the SDEF parser. Instead of assuming the parser works, we'll **measure** success rates across real SDEF files, identify failure patterns, and document known limitations. This data-driven approach enables:

1. **Quantified success metrics** - Know exactly how many apps are supported
2. **Failure pattern identification** - Understand what needs fixing next
3. **Regression detection** - Track improvements over time
4. **User transparency** - Document what works and what doesn't

**Key Innovation**: The `analyze-sdef-coverage.ts` script already exists but needs integration with a metrics collection system. We'll build on this foundation rather than starting from scratch.

---

## 1. Implementation Phases

### Phase 4A: Metrics Collection Infrastructure (4-5 hours)

**Objective**: Create a standalone metrics collector that can be integrated with existing parser and coverage script.

**Deliverables**:
- `src/jitd/discovery/parser-metrics.ts` - Metrics collection class
- Unit tests with 100% coverage
- TypeScript interfaces for metrics data
- Integration hooks for SDEFParser

**Files Involved**:
- `src/jitd/discovery/parser-metrics.ts` (NEW)
- `tests/unit/parser-metrics.test.ts` (NEW)
- `src/jitd/discovery/parse-sdef.ts` (MODIFY - add metrics hooks)

**Dependencies**: None (standalone implementation)

**Effort**: 4-5 hours
- Implementation: 2 hours
- Unit tests: 2 hours
- Integration with SDEFParser: 1 hour

**Agent Recommendation**: **Haiku**
- Straightforward class implementation
- Well-defined interfaces already exist
- No complex architectural decisions
- Pattern: Collect data → Aggregate → Generate report

---

### Phase 4B: Coverage Script Enhancement (2-3 hours)

**Objective**: Enhance existing `scripts/analyze-sdef-coverage.ts` to use new metrics collector.

**Deliverables**:
- Enhanced coverage script with metrics integration
- CLI output formatting
- JSON export option
- Performance optimizations (timeout handling)

**Files Involved**:
- `scripts/analyze-sdef-coverage.ts` (MODIFY)
- `tests/integration/sdef-coverage.test.ts` (NEW)

**Dependencies**: Phase 4A complete (requires `ParserMetricsCollector`)

**Effort**: 2-3 hours
- Script integration: 1 hour
- Integration tests: 1 hour
- CLI enhancements: 0.5-1 hour

**Agent Recommendation**: **Haiku**
- Integration work with existing code
- No novel patterns required
- Straightforward testing approach
- Script already 90% complete

---

### Phase 4C: Documentation & Known Limitations (2-3 hours)

**Objective**: Run comprehensive coverage analysis and document findings in user-facing documentation.

**Deliverables**:
- `docs/TROUBLESHOOTING.md` - Limitations and workarounds
- `docs/SDEF-SUPPORT.md` - Comprehensive support matrix
- Baseline metrics report
- Recommendations for Phase 5+

**Files Involved**:
- `docs/TROUBLESHOOTING.md` (NEW)
- `docs/SDEF-SUPPORT.md` (NEW)
- `planning/DECISIONS.md` (UPDATE - document findings)

**Dependencies**: Phase 4B complete (requires working coverage script)

**Effort**: 2-3 hours
- Run coverage analysis: 0.5 hour
- Document limitations: 1-1.5 hours
- Create support matrix: 1 hour

**Agent Recommendation**: **Sonnet**
- Requires analysis and judgment
- Writing user-facing documentation
- Strategic recommendations for next phases
- Architectural implications of findings

---

### Phase 4D: CI/CD Integration (1-2 hours)

**Objective**: Add automated coverage checks to CI pipeline for regression detection.

**Deliverables**:
- GitHub Actions workflow for coverage reporting
- Automated success rate tracking
- PR comments with coverage deltas
- Historical metrics storage

**Files Involved**:
- `.github/workflows/sdef-coverage.yml` (NEW)
- `scripts/compare-coverage.ts` (NEW - optional)

**Dependencies**: Phase 4B complete

**Effort**: 1-2 hours
- GitHub Actions setup: 0.5-1 hour
- Coverage comparison script: 0.5-1 hour

**Agent Recommendation**: **Haiku**
- Standard GitHub Actions patterns
- Simple bash/script integration
- No complex logic required

---

## 2. Detailed Integration Requirements

### 2.1 ParserMetricsCollector Integration with SDEFParser

**Current State**:
```typescript
// src/jitd/discovery/parse-sdef.ts (line 111)
export class SDEFParser {
  private parser: XMLParser;
  private parseCache: Map<string, SDEFDictionary>;
  private readonly mode: 'strict' | 'lenient';
  private readonly onWarning?: (warning: ParseWarning) => void;
  private currentSuite?: string;
  private currentCommand?: string;
  private entityResolver?: EntityResolver;
}
```

**Integration Points**:

1. **Add optional metrics collector to constructor**:
   ```typescript
   constructor(options?: SDEFParserOptions & {
     metricsCollector?: ParserMetricsCollector
   })
   ```

2. **Record parse attempts in `parse()` method**:
   ```typescript
   async parse(sdefPath: string): Promise<SDEFDictionary> {
     const startTime = Date.now();
     const warnings: ParseWarning[] = [];

     try {
       // ... existing parse logic ...

       this.metricsCollector?.recordAttempt({
         sdefPath,
         success: true,
         warnings,
         commandCount,
         classCount,
         parseTimeMs: Date.now() - startTime,
       });

       return dictionary;
     } catch (error) {
       this.metricsCollector?.recordAttempt({
         sdefPath,
         success: false,
         error: error.message,
         parseTimeMs: Date.now() - startTime,
       });
       throw error;
     }
   }
   ```

3. **Capture warnings during parsing**:
   - Already supported via `onWarning` callback
   - Collect warnings array and pass to metrics

**Non-Breaking Change**: Metrics collection is completely optional. Existing code works unchanged.

---

### 2.2 Coverage Script SDEF File Discovery

**File Location Strategy**:

```typescript
// Prioritized search paths
const SDEF_SEARCH_PATHS = [
  '/Applications/**/*.sdef',                    // User apps (highest priority)
  '/System/Applications/**/*.sdef',              // System apps
  '/System/Library/CoreServices/**/*.sdef',      // Core services
  '~/Applications/**/*.sdef',                    // User-specific apps
];

// Performance optimization: Use glob with concurrency limit
async function findSdefFiles(appsOnly: boolean): Promise<string[]> {
  const patterns = appsOnly
    ? ['/Applications/**/*.sdef']
    : SDEF_SEARCH_PATHS;

  // Parallel glob with deduplication
  const results = await Promise.all(
    patterns.map(pattern => glob(pattern, { nodir: true }))
  );

  return [...new Set(results.flat())]; // Deduplicate
}
```

**Sample Discovery**:
- `/Applications`: ~5-20 SDEF files (user-installed apps)
- `/System/Applications`: ~10-30 SDEF files (Apple apps)
- `/System/Library/CoreServices`: ~5-10 SDEF files (Finder, System Events)
- **Total expected**: 20-60 SDEF files on typical macOS system

---

### 2.3 Metrics Export and Display

**Report Generation Flow**:

```
ParseAttempt[] → ParserMetricsCollector → Metrics Aggregation → Report Generation
                                             ↓
                                  [Markdown, JSON, HTML]
```

**Output Formats**:

1. **CLI/Markdown** (default):
   ```markdown
   # SDEF Parser Coverage Report

   ## Summary
   | Metric | Value |
   |--------|-------|
   | Total SDEF files | 45 |
   | Successfully parsed | 38 (84.4%) |
   | Failed to parse | 7 |
   | Total tools generated | 1,247 |

   ## Top Apps by Tool Count
   1. System Events: 127 tools
   2. Finder: 45 tools
   3. Safari: 32 tools
   ```

2. **JSON** (for CI/automation):
   ```json
   {
     "generatedAt": "2026-01-21T01:35:50Z",
     "metrics": {
       "totalSdefFiles": 45,
       "successfulParses": 38,
       "parseSuccessRate": 84.4,
       "errorsByType": {
         "MISSING_TYPE": 3,
         "XML_PARSE_ERROR": 2
       }
     },
     "attempts": [...]
   }
   ```

3. **HTML** (optional, future):
   - Interactive dashboard
   - Filterable tables
   - Trend graphs

---

### 2.4 Test Strategy for Metrics Collection

**Unit Tests** (`tests/unit/parser-metrics.test.ts`):
```typescript
describe('ParserMetricsCollector', () => {
  describe('recordAttempt', () => {
    it('should record successful parse attempt', () => {
      const collector = new ParserMetricsCollector();
      collector.recordAttempt({
        sdefPath: '/test.sdef',
        appName: 'TestApp',
        success: true,
        warnings: [],
        commandCount: 5,
        classCount: 3,
        toolCount: 5,
        parseTimeMs: 100,
      });

      const metrics = collector.getMetrics();
      expect(metrics.successfulParses).toBe(1);
      expect(metrics.totalCommands).toBe(5);
    });

    it('should aggregate warnings by code', () => { /* ... */ });
    it('should classify errors by type', () => { /* ... */ });
    it('should calculate success rate correctly', () => { /* ... */ });
  });

  describe('generateReport', () => {
    it('should format markdown report', () => { /* ... */ });
    it('should include error breakdown', () => { /* ... */ });
    it('should show top apps by tool count', () => { /* ... */ });
  });
});
```

**Integration Tests** (`tests/integration/sdef-coverage.test.ts`):
```typescript
describe('SDEF Coverage Script', () => {
  it('should parse all fixture SDEF files', async () => {
    // Use test fixtures only (fast)
    const result = await runCoverageScript({
      paths: ['tests/fixtures/sdef/**/*.sdef']
    });

    expect(result.metrics.successfulParses).toBeGreaterThan(0);
  });

  it('should generate valid JSON output', async () => {
    const json = await runCoverageScript({ format: 'json' });
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('should handle malformed SDEF files gracefully', async () => {
    // Should not crash, should report errors
    const result = await runCoverageScript({
      paths: ['tests/fixtures/sdef/malformed.sdef']
    });

    expect(result.metrics.failedParses).toBeGreaterThan(0);
  });
});
```

**Coverage Goal**: 100% (per project standards)

**Test Data Requirements**:
- Expand `tests/fixtures/sdef/` with more edge cases:
  - `successful-parse.sdef` - Clean, valid SDEF
  - `malformed-xml.sdef` - Invalid XML
  - `missing-types.sdef` - Type inference cases
  - `xinclude-reference.sdef` - External entity
  - `large-dictionary.sdef` - Performance testing

---

## 3. Type Signatures & API Contracts

### 3.1 Core Interfaces

```typescript
/**
 * Represents a single parse attempt (success or failure)
 */
export interface ParseAttempt {
  /** Absolute path to SDEF file */
  sdefPath: string;

  /** Application path (e.g., /Applications/Safari.app) */
  appPath: string;

  /** Human-readable app name */
  appName: string;

  /** Bundle identifier (e.g., com.apple.Safari) */
  bundleId: string | null;

  /** Whether parsing succeeded */
  success: boolean;

  /** Error message if parsing failed */
  error?: string;

  /** Number of commands extracted */
  commandCount: number;

  /** Number of classes extracted */
  classCount: number;

  /** Number of MCP tools generated */
  toolCount: number;

  /** Warnings emitted during parsing */
  warnings: ParseWarning[];

  /** Parse duration in milliseconds */
  parseTimeMs: number;

  /** SDEF file size in bytes */
  fileSizeBytes: number;
}

/**
 * Aggregated metrics across all parse attempts
 */
export interface ParserMetrics {
  // Parse statistics
  totalSdefFiles: number;
  successfulParses: number;
  failedParses: number;
  parseSuccessRate: number; // Percentage (0-100)

  // Content statistics
  totalCommands: number;
  totalClasses: number;
  totalTools: number;

  // App coverage
  appsWithToolsGenerated: number;

  // Error analysis
  errorsByType: Record<ErrorType, number>;

  // Warning analysis
  warningsByCode: Record<WarningCode, number>;

  // Performance metrics
  averageParseTimeMs: number;
  slowestParseMs: number;
  fastestParseMs: number;

  // Lists for detailed analysis
  successfulApps: string[];
  failedApps: Array<{ app: string; error: string }>;
}

/**
 * Error classification types
 */
export type ErrorType =
  | 'MISSING_TYPE'
  | 'MISSING_NAME_OR_CODE'
  | 'INVALID_CODE'
  | 'XML_PARSE_ERROR'
  | 'EXTERNAL_ENTITY'
  | 'FILE_TOO_LARGE'
  | 'FILE_NOT_READABLE'
  | 'INVALID_FORMAT'
  | 'OTHER';

/**
 * Warning code types
 */
export type WarningCode =
  | 'TYPE_INFERRED'
  | 'UNION_TYPE_SIMPLIFIED'
  | 'EXTERNAL_ENTITY_RESOLVED'
  | 'UNKNOWN_TYPE_FALLBACK';
```

---

### 3.2 ParserMetricsCollector Class API

```typescript
export class ParserMetricsCollector {
  private attempts: ParseAttempt[] = [];

  /**
   * Record a single parse attempt
   */
  recordAttempt(attempt: ParseAttempt): void;

  /**
   * Get aggregated metrics for all recorded attempts
   */
  getMetrics(): ParserMetrics;

  /**
   * Generate human-readable markdown report
   */
  generateMarkdownReport(options?: ReportOptions): string;

  /**
   * Export metrics as JSON
   */
  toJSON(): string;

  /**
   * Clear all recorded attempts (for testing)
   */
  reset(): void;

  /**
   * Get all individual parse attempts (for detailed analysis)
   */
  getAttempts(): ReadonlyArray<ParseAttempt>;

  /**
   * Classify error message into error type
   * @internal
   */
  private classifyError(error: string): ErrorType;

  /**
   * Sort apps by metric (e.g., tool count, parse time)
   * @internal
   */
  private sortByMetric(
    metric: 'toolCount' | 'commandCount' | 'parseTimeMs',
    limit?: number
  ): ParseAttempt[];
}

/**
 * Report generation options
 */
export interface ReportOptions {
  /** Include verbose error details */
  verbose?: boolean;

  /** Maximum number of apps to show in lists */
  limit?: number;

  /** Include performance metrics */
  includePerformance?: boolean;
}
```

---

### 3.3 SDEFParser Integration Changes

```typescript
/**
 * Extended options for SDEFParser
 */
export interface SDEFParserOptions {
  mode?: 'strict' | 'lenient';
  onWarning?: (warning: ParseWarning) => void;

  /**
   * Optional metrics collector for tracking parse attempts
   * When provided, all parse attempts will be recorded automatically
   */
  metricsCollector?: ParserMetricsCollector;
}

// Usage example:
const collector = new ParserMetricsCollector();
const parser = new SDEFParser({
  mode: 'lenient',
  metricsCollector: collector,
});

// Parse multiple files
for (const sdefPath of sdefFiles) {
  try {
    await parser.parse(sdefPath);
  } catch (error) {
    // Error already recorded by metrics collector
  }
}

// Generate report
console.log(collector.generateMarkdownReport());
```

---

## 4. Edge Cases & Constraints

### 4.1 File Access Errors

**Edge Case**: SDEF file exists but cannot be read due to permissions.

**Handling**:
```typescript
async function parseSdef(sdefPath: string): Promise<ParseAttempt> {
  try {
    // Check file accessibility first
    await fs.access(sdefPath, fs.constants.R_OK);
  } catch (error) {
    return {
      sdefPath,
      success: false,
      error: 'FILE_NOT_READABLE: Permission denied',
      commandCount: 0,
      toolCount: 0,
      parseTimeMs: 0,
    };
  }

  // Proceed with parsing...
}
```

**Test Case**: Create fixture with restricted permissions (chmod 000).

---

### 4.2 Partial Parse Success

**Edge Case**: Parser extracts some commands but fails on others (e.g., malformed command in otherwise valid SDEF).

**Current Behavior**: Parser throws error on first failure (all-or-nothing).

**Desired Behavior**:
- In `lenient` mode: Continue parsing, emit warnings, return partial dictionary
- In `strict` mode: Fail fast (current behavior)

**Implementation** (Phase 5+ enhancement):
```typescript
// Collect partial results in lenient mode
const commands: SDEFCommand[] = [];
for (const commandXml of commandElements) {
  try {
    commands.push(parseCommand(commandXml));
  } catch (error) {
    if (this.mode === 'strict') throw error;
    this.emitWarning({
      code: 'COMMAND_PARSE_FAILED',
      message: `Failed to parse command: ${error.message}`,
      location: { element: 'command', name: '(unknown)' },
    });
  }
}
```

**Metrics Impact**: Add `partialParses` field to track SDEFs with warnings but no errors.

---

### 4.3 System Permission Prompts

**Edge Case**: Parsing certain system SDEF files triggers macOS security prompts.

**Example**: Accessing `/System/Library/CoreServices/` may require Full Disk Access.

**Handling**:
1. **Document requirement** in README/docs
2. **Graceful degradation**: Skip files that trigger permission errors
3. **User warning**: "Some system apps skipped due to permissions. Grant Full Disk Access for complete scan."

**Implementation**:
```typescript
const skippedPaths: string[] = [];

for (const sdefPath of systemPaths) {
  try {
    await stat(sdefPath); // Test accessibility
    attempts.push(await parseSdef(sdefPath));
  } catch (error) {
    if (error.code === 'EACCES') {
      skippedPaths.push(sdefPath);
      continue;
    }
    throw error;
  }
}

if (skippedPaths.length > 0) {
  console.warn(
    `Skipped ${skippedPaths.length} system files due to permissions. ` +
    `Grant Full Disk Access for complete coverage.`
  );
}
```

---

### 4.4 Invalid SDEF Format Detection

**Edge Case**: File has `.sdef` extension but contains non-XML or invalid XML.

**Example**: Empty file, binary file, HTML file renamed to `.sdef`.

**Handling**:
```typescript
// Early validation before XML parsing
function validateSdefFormat(content: string): void {
  if (content.trim().length === 0) {
    throw new Error('INVALID_FORMAT: Empty SDEF file');
  }

  if (!content.includes('<dictionary')) {
    throw new Error('INVALID_FORMAT: Missing <dictionary> root element');
  }

  // Check for common non-XML content
  if (content.startsWith('<!DOCTYPE html')) {
    throw new Error('INVALID_FORMAT: File appears to be HTML, not SDEF');
  }
}
```

**Test Cases**:
- Empty SDEF file
- HTML file with `.sdef` extension
- Binary file with `.sdef` extension
- Truncated XML file

---

### 4.5 Performance Constraints

**Constraint**: Parsing all SDEF files on system should complete in < 30 seconds.

**Timeout Strategy**:
```typescript
const PARSE_TIMEOUT_MS = 5000; // 5 seconds per file

async function parseSdefWithTimeout(
  sdefPath: string,
  parser: SDEFParser
): Promise<ParseAttempt> {
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error('TIMEOUT: Parse exceeded 5 seconds')),
               PARSE_TIMEOUT_MS);
  });

  try {
    return await Promise.race([
      parseSdef(sdefPath, parser),
      timeoutPromise,
    ]);
  } catch (error) {
    if (error.message.includes('TIMEOUT')) {
      return {
        sdefPath,
        success: false,
        error: 'TIMEOUT: File too complex or parser hung',
        parseTimeMs: PARSE_TIMEOUT_MS,
        // ... other fields
      };
    }
    throw error;
  }
}
```

**Performance Metrics**: Track parse times to identify outliers.

---

### 4.6 Large File Handling

**Constraint**: Already enforced in parser - MAX_FILE_SIZE = 10MB.

**Edge Case**: Large SDEF file (e.g., Microsoft Office apps).

**Current Behavior**: Parser throws 'FILE_TOO_LARGE' error.

**Metrics Tracking**:
```typescript
if (fileSizeBytes > MAX_FILE_SIZE) {
  return {
    success: false,
    error: `FILE_TOO_LARGE: ${(fileSizeBytes / 1024 / 1024).toFixed(1)}MB exceeds 10MB limit`,
    fileSizeBytes,
  };
}
```

**Future Enhancement** (Phase 5+): Streaming XML parser for large files.

---

## 5. Testing Strategy

### 5.1 Unit Test Coverage

**Target**: 100% coverage for `ParserMetricsCollector`

**Test Structure**:
```
tests/unit/parser-metrics.test.ts
├── ParserMetricsCollector
│   ├── constructor
│   │   └── should initialize with empty attempts array
│   ├── recordAttempt
│   │   ├── should record successful parse attempt
│   │   ├── should record failed parse attempt
│   │   ├── should accumulate multiple attempts
│   │   └── should handle partial data (missing optional fields)
│   ├── getMetrics
│   │   ├── should calculate success rate correctly
│   │   ├── should aggregate commands and classes
│   │   ├── should aggregate tools generated
│   │   ├── should classify errors by type
│   │   ├── should classify warnings by code
│   │   ├── should calculate performance metrics
│   │   └── should handle empty attempts gracefully
│   ├── generateMarkdownReport
│   │   ├── should format summary table
│   │   ├── should include error breakdown
│   │   ├── should show top apps by tool count
│   │   ├── should list failed apps with errors
│   │   ├── should respect verbose option
│   │   └── should respect limit option
│   ├── toJSON
│   │   ├── should export valid JSON
│   │   ├── should include all metrics
│   │   └── should include attempts array
│   ├── reset
│   │   └── should clear all recorded attempts
│   └── classifyError (private - test via recordAttempt)
│       ├── should detect MISSING_TYPE errors
│       ├── should detect XML_PARSE_ERROR errors
│       ├── should detect EXTERNAL_ENTITY errors
│       └── should classify unknown errors as OTHER
```

**Example Test**:
```typescript
describe('ParserMetricsCollector', () => {
  describe('getMetrics', () => {
    it('should calculate success rate correctly', () => {
      const collector = new ParserMetricsCollector();

      // Record 3 successful, 1 failed = 75% success rate
      collector.recordAttempt({ success: true, /* ... */ });
      collector.recordAttempt({ success: true, /* ... */ });
      collector.recordAttempt({ success: true, /* ... */ });
      collector.recordAttempt({ success: false, error: 'XML_PARSE_ERROR', /* ... */ });

      const metrics = collector.getMetrics();
      expect(metrics.successfulParses).toBe(3);
      expect(metrics.failedParses).toBe(1);
      expect(metrics.parseSuccessRate).toBeCloseTo(75.0, 1);
    });
  });
});
```

---

### 5.2 Integration Test Coverage

**Target**: Verify end-to-end coverage script behavior

**Test Structure**:
```
tests/integration/sdef-coverage.test.ts
├── SDEF Coverage Script
│   ├── should parse all fixture SDEF files
│   ├── should generate markdown report
│   ├── should generate JSON report with --json flag
│   ├── should handle malformed SDEF files gracefully
│   ├── should respect --apps-only flag
│   ├── should complete within timeout (< 30s for fixtures)
│   ├── should handle permission denied errors
│   └── should exit with error if success rate < threshold
```

**Fixture Requirements**:
```
tests/fixtures/sdef/
├── valid/
│   ├── finder-minimal.sdef       # Small valid SDEF
│   ├── safari-commands.sdef       # Commands with parameters
│   └── mail-classes.sdef          # Classes with properties
├── edge-cases/
│   ├── missing-types.sdef         # Type inference needed
│   ├── xinclude-reference.sdef    # External entity
│   └── union-types.sdef           # Multi-type support
└── invalid/
    ├── empty.sdef                 # Empty file
    ├── malformed-xml.sdef         # Invalid XML syntax
    └── wrong-format.sdef          # HTML file renamed
```

---

### 5.3 Test Execution Strategy

**Development Cycle**:
1. Write failing test
2. Implement feature
3. Run unit tests (`npm run test:unit`)
4. Run integration tests (`npm run test:integration`)
5. Check coverage (`npm run test:coverage`)
6. Iterate until 100% coverage

**CI/CD**:
```yaml
# .github/workflows/test.yml (existing)
- name: Run tests with coverage
  run: npm run test:coverage

- name: Upload coverage reports
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage/lcov.info
```

---

## 6. Success Criteria (Detailed)

### 6.1 Functional Requirements

✅ **Metrics Collection**:
- [ ] `ParserMetricsCollector` class implemented
- [ ] Records both successful and failed parse attempts
- [ ] Aggregates errors by type
- [ ] Aggregates warnings by code
- [ ] Calculates performance metrics (avg, min, max parse time)
- [ ] Generates markdown reports
- [ ] Exports JSON format

✅ **Coverage Script**:
- [ ] Finds all SDEF files in standard locations
- [ ] Parses each file with timeout protection
- [ ] Handles permission errors gracefully
- [ ] Outputs formatted report to stdout
- [ ] Supports `--json`, `--verbose`, `--apps-only` flags
- [ ] Exits with error code if success rate < 25%

✅ **Documentation**:
- [ ] `docs/TROUBLESHOOTING.md` documents known limitations
- [ ] `docs/SDEF-SUPPORT.md` provides support matrix
- [ ] Baseline metrics report generated and saved
- [ ] Recommendations for future phases documented

---

### 6.2 Quality Requirements

✅ **Test Coverage**: 100% for all new code
- [ ] Unit tests: `parser-metrics.test.ts` (100% coverage)
- [ ] Integration tests: `sdef-coverage.test.ts` (all critical paths)
- [ ] Edge case coverage (all scenarios in §4)

✅ **Code Quality**:
- [ ] Zero duplication (jscpd passes)
- [ ] TypeScript strict mode enabled
- [ ] All linting rules pass
- [ ] No TODO/FIXME comments (convert to issues)

✅ **Documentation**:
- [ ] All public APIs have JSDoc comments
- [ ] README updated with coverage command
- [ ] Examples provided for common use cases

---

### 6.3 Performance Requirements

✅ **Execution Speed**:
- [ ] Parse 50 SDEF files in < 30 seconds (avg 0.6s per file)
- [ ] Individual file timeout: 5 seconds max
- [ ] Memory usage: < 500MB during full scan

✅ **Scalability**:
- [ ] Handles 100+ SDEF files without issues
- [ ] Cache size limited to prevent memory leaks
- [ ] Graceful degradation on low-memory systems

---

### 6.4 Success Metrics Targets

Based on existing Phase 1-3 improvements, expected results:

| Metric | Target | Rationale |
|--------|--------|-----------|
| Parse Success Rate | **≥ 80%** | Phase 1-3 fixes handle most common issues |
| Apps with Tools Generated | **≥ 75%** | Some apps have SDEF but no useful commands |
| Average Parse Time | **< 1 second** | Fast XML parsing with caching |
| Error Classification Coverage | **100%** | All errors mapped to known types |
| Warning Classification Coverage | **100%** | All warnings tracked for analysis |

**Baseline Report**: After Phase 4 implementation, generate baseline report and track improvements over time.

---

### 6.5 CLI Command Implementation

**Required Commands**:

```bash
# Full coverage analysis (default)
npm run sdef:coverage

# JSON output for automation
npm run sdef:coverage -- --json

# Verbose error details
npm run sdef:coverage -- --verbose

# Fast scan (user apps only)
npm run sdef:coverage -- --apps-only

# Combined flags
npm run sdef:coverage -- --json --verbose
```

**package.json Script**:
```json
{
  "scripts": {
    "sdef:coverage": "tsx scripts/analyze-sdef-coverage.ts",
    "sdef:coverage:json": "npm run sdef:coverage -- --json",
    "sdef:coverage:fast": "npm run sdef:coverage -- --apps-only"
  }
}
```

---

## 7. Implementation Order (Specific Steps)

### Step-by-Step Execution Sequence

#### **Week 1, Day 1 (Morning): Phase 4A Start**

**Step 1** (30 min, Haiku): Create type definitions
- File: `src/jitd/discovery/parser-metrics.ts`
- Task: Define interfaces (`ParseAttempt`, `ParserMetrics`, `ErrorType`, `WarningCode`)
- Deliverable: Type-only file compiles successfully

**Step 2** (90 min, Haiku): Implement `ParserMetricsCollector` class
- File: `src/jitd/discovery/parser-metrics.ts`
- Task: Implement `recordAttempt()`, `getMetrics()`, `classifyError()`
- Deliverable: Core logic complete (no report generation yet)

**Step 3** (60 min, Haiku): Write unit tests (Part 1)
- File: `tests/unit/parser-metrics.test.ts`
- Task: Test `recordAttempt()` and `getMetrics()` methods
- Deliverable: Core functionality tested

#### **Week 1, Day 1 (Afternoon): Phase 4A Complete**

**Step 4** (60 min, Haiku): Implement report generation
- File: `src/jitd/discovery/parser-metrics.ts`
- Task: Implement `generateMarkdownReport()` and `toJSON()`
- Deliverable: Reports formatted correctly

**Step 5** (60 min, Haiku): Write unit tests (Part 2)
- File: `tests/unit/parser-metrics.test.ts`
- Task: Test report generation, edge cases, error classification
- Deliverable: 100% coverage for `ParserMetricsCollector`

**Step 6** (60 min, Haiku): Integrate with SDEFParser
- File: `src/jitd/discovery/parse-sdef.ts`
- Task: Add optional `metricsCollector` parameter, record parse attempts
- Deliverable: Non-breaking integration complete

**Step 7** (30 min, Haiku): Update SDEFParser tests
- File: `tests/unit/sdef-parser.test.ts`
- Task: Add tests for metrics integration
- Deliverable: Existing tests still pass, new tests added

**✅ Phase 4A Complete**: Metrics collection infrastructure ready

---

#### **Week 1, Day 2 (Morning): Phase 4B Start**

**Step 8** (30 min, Haiku): Review existing coverage script
- File: `scripts/analyze-sdef-coverage.ts`
- Task: Understand current implementation, identify integration points
- Deliverable: Integration plan documented

**Step 9** (60 min, Haiku): Refactor coverage script to use metrics collector
- File: `scripts/analyze-sdef-coverage.ts`
- Task: Replace inline metrics logic with `ParserMetricsCollector`
- Deliverable: Script simplified, uses new collector

**Step 10** (30 min, Haiku): Add CLI flags and output formatting
- File: `scripts/analyze-sdef-coverage.ts`
- Task: Implement `--json`, `--verbose`, `--apps-only` flags
- Deliverable: CLI interface complete

#### **Week 1, Day 2 (Afternoon): Phase 4B Complete**

**Step 11** (90 min, Haiku): Write integration tests
- File: `tests/integration/sdef-coverage.test.ts`
- Task: Test script with fixtures, test all CLI flags
- Deliverable: Integration tests pass

**Step 12** (30 min, Haiku): Add performance optimizations
- File: `scripts/analyze-sdef-coverage.ts`
- Task: Add timeout handling, parallel parsing (if needed)
- Deliverable: Script completes in < 30s for typical system

**Step 13** (30 min, Haiku): Update package.json scripts
- File: `package.json`
- Task: Add npm scripts for coverage commands
- Deliverable: `npm run sdef:coverage` works

**✅ Phase 4B Complete**: Coverage script enhanced and tested

---

#### **Week 1, Day 3 (Morning): Phase 4C Start**

**Step 14** (30 min, Haiku): Run baseline coverage analysis
- Task: Execute `npm run sdef:coverage` on development machine
- Deliverable: Baseline metrics captured (save output to `docs/baseline-metrics.md`)

**Step 15** (60 min, Sonnet): Analyze results and identify patterns
- Task: Review baseline metrics, identify common failure patterns
- Deliverable: Analysis document with findings and recommendations

**Step 16** (90 min, Sonnet): Create TROUBLESHOOTING.md
- File: `docs/TROUBLESHOOTING.md`
- Task: Document known limitations, common errors, workarounds
- Deliverable: User-facing troubleshooting guide

#### **Week 1, Day 3 (Afternoon): Phase 4C Complete**

**Step 17** (60 min, Sonnet): Create SDEF-SUPPORT.md
- File: `docs/SDEF-SUPPORT.md`
- Task: Document support matrix (apps tested, success rate, limitations)
- Deliverable: Comprehensive support documentation

**Step 18** (30 min, Sonnet): Update planning/DECISIONS.md
- File: `planning/DECISIONS.md`
- Task: Document findings, recommendations for Phase 5+
- Deliverable: Strategic decisions captured

**Step 19** (30 min, Haiku): Update README with coverage command
- File: `README.md`
- Task: Add "Validation & Metrics" section with examples
- Deliverable: User-facing documentation updated

**✅ Phase 4C Complete**: Documentation comprehensive and actionable

---

#### **Week 1, Day 3 (Optional): Phase 4D**

**Step 20** (60 min, Haiku): Create GitHub Actions workflow
- File: `.github/workflows/sdef-coverage.yml`
- Task: Set up automated coverage runs on PR and main branch
- Deliverable: CI workflow runs coverage analysis

**Step 21** (30 min, Haiku): Add coverage comparison script
- File: `scripts/compare-coverage.ts`
- Task: Compare current metrics to baseline, detect regressions
- Deliverable: PR comments show coverage deltas

**✅ Phase 4D Complete**: CI/CD integration for continuous validation

---

### Agent Assignment Summary

| Step | Agent | Rationale |
|------|-------|-----------|
| 1-7 | **Haiku** | Straightforward implementation, well-defined interfaces |
| 8-13 | **Haiku** | Integration work, testing, CLI implementation |
| 14 | **Haiku** | Script execution (no analysis) |
| 15-18 | **Sonnet** | Requires analysis, judgment, strategic thinking |
| 19-21 | **Haiku** | Standard documentation updates, CI setup |

**Haiku Tasks**: 16 steps (80% of work)
**Sonnet Tasks**: 4 steps (20% of work)

**Rationale**: Most work is straightforward implementation and testing. Only analysis, strategic documentation, and recommendations require Sonnet's advanced reasoning.

---

## 8. Known Unknowns

### 8.1 Assumptions Requiring Validation

**Assumption 1**: SDEF files are reliably located in standard paths
- **Validation**: Run discovery on multiple Mac systems, check for edge cases
- **Risk**: Low (standard Apple convention)

**Assumption 2**: Parse failures are classifiable into discrete error types
- **Validation**: Analyze baseline metrics, review unclassified errors
- **Risk**: Medium (may find new error patterns)

**Assumption 3**: 80% success rate is achievable with Phase 1-3 improvements
- **Validation**: Baseline metrics will confirm or refute
- **Risk**: Medium (may need additional parser improvements)

**Assumption 4**: Performance target (< 30s for 50 files) is realistic
- **Validation**: Benchmark on typical hardware
- **Risk**: Low (XML parsing is fast)

---

### 8.2 Implementation Decisions Needing Review

**Decision 1**: Should metrics collector be optional or always-on in SDEFParser?
- **Current Plan**: Optional (non-breaking change)
- **Alternative**: Always collect metrics, disable in production via flag
- **Trade-off**: Simplicity vs. observability

**Decision 2**: Should coverage script fail CI if success rate < 80%?
- **Current Plan**: Fail if < 25% (catastrophic failure only)
- **Alternative**: Fail if < baseline - 5% (detect regressions)
- **Trade-off**: Stability vs. quality enforcement

**Decision 3**: Should we support streaming/progressive parsing for large files?
- **Current Plan**: Enforce 10MB limit, error on larger files
- **Alternative**: Implement streaming parser for Phase 5+
- **Trade-off**: Complexity vs. coverage

---

### 8.3 Risky Areas Requiring Special Attention

**Risk 1**: Permission prompts on macOS Catalina+
- **Mitigation**: Document Full Disk Access requirement, graceful degradation
- **Testing**: Test on fresh macOS install without permissions granted

**Risk 2**: Parser hangs on malformed XML
- **Mitigation**: 5-second timeout per file
- **Testing**: Create fixtures with deeply nested elements, infinite loops

**Risk 3**: Memory exhaustion with 100+ SDEF files
- **Mitigation**: Cache size limits, streaming where possible
- **Testing**: Stress test with 200+ fixture files

**Risk 4**: False positives in error classification
- **Mitigation**: Conservative classification (use 'OTHER' when uncertain)
- **Testing**: Manual review of baseline metrics, adjust classification logic

---

## 9. Risk Assessment

### 9.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Parser hangs on malformed SDEF | Medium | High | Implement timeout (5s per file) |
| Permission denied on system files | High | Low | Graceful degradation, user warning |
| Memory exhaustion (large scan) | Low | Medium | Cache limits, streaming |
| False error classification | Medium | Low | Conservative classification, manual review |
| Integration breaks existing code | Low | High | Non-breaking API, extensive tests |

---

### 9.2 Schedule Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Unit tests take longer than estimated | Medium | Low | Timebox testing, defer edge cases to Phase 5 |
| Baseline metrics reveal major issues | Low | High | Document as Phase 5 work, proceed with Phase 4 |
| Documentation requires deeper analysis | Medium | Low | Use Sonnet for analysis, defer deep dives |

---

### 9.3 Dependency Risks

| Dependency | Risk | Mitigation |
|------------|------|------------|
| fast-xml-parser library | Security vulnerability | Pin version, monitor advisories |
| glob library | Breaking changes | Pin version, test thoroughly |
| macOS API changes | Access restrictions tightened | Test on latest macOS, document requirements |

---

### 9.4 Recovery Strategies

**Scenario 1**: Metrics collection breaks existing parser
- **Detection**: Unit tests fail after integration
- **Recovery**: Revert integration, make metrics truly optional (no-op if not provided)
- **Time Lost**: 1-2 hours

**Scenario 2**: Coverage script times out or crashes
- **Detection**: Script runs > 60 seconds or exits with error
- **Recovery**: Add more aggressive timeouts, reduce scan scope
- **Time Lost**: 2-3 hours

**Scenario 3**: Baseline metrics show < 50% success rate
- **Detection**: First coverage run shows poor results
- **Recovery**: Document findings, prioritize Phase 5 fixes, proceed with Phase 4 infrastructure
- **Time Lost**: 0 hours (expected outcome, not a failure)

**Scenario 4**: 100% test coverage not achievable in timeframe
- **Detection**: Day 2 afternoon, still < 90% coverage
- **Recovery**: Focus on critical paths, defer edge case coverage to Phase 5
- **Time Lost**: Defer 1-2 hours of work to Phase 5

---

## 10. Post-Phase 4 Outcomes

### 10.1 Expected Deliverables

**Code**:
- ✅ `src/jitd/discovery/parser-metrics.ts` (300-400 lines)
- ✅ `tests/unit/parser-metrics.test.ts` (400-500 lines)
- ✅ `tests/integration/sdef-coverage.test.ts` (200-300 lines)
- ✅ Enhanced `scripts/analyze-sdef-coverage.ts`
- ✅ Optional: `.github/workflows/sdef-coverage.yml`

**Documentation**:
- ✅ `docs/TROUBLESHOOTING.md` (comprehensive limitations guide)
- ✅ `docs/SDEF-SUPPORT.md` (support matrix)
- ✅ `docs/baseline-metrics.md` (initial coverage report)
- ✅ Updated `README.md` (coverage commands)
- ✅ Updated `planning/DECISIONS.md` (findings and recommendations)

**Metrics**:
- ✅ Baseline success rate measured
- ✅ Error patterns identified and classified
- ✅ Performance benchmarks established
- ✅ Recommendations for Phase 5+ documented

---

### 10.2 Next Phase Recommendations

Based on baseline metrics, Phase 5+ priorities will be identified:

**Potential Phase 5 Focus Areas**:
1. **Top Error Type**: If `MISSING_TYPE` is #1 → Enhance type inference
2. **Parser Robustness**: If `XML_PARSE_ERROR` is common → Improve error recovery
3. **Coverage Expansion**: If < 70% apps supported → Add fallback mechanisms
4. **Performance**: If avg parse time > 1s → Optimize hot paths

**Data-Driven Decision Making**: Phase 4 provides the metrics to prioritize effectively.

---

## 11. Appendix

### 11.1 Example Baseline Metrics Report

```markdown
# SDEF Parser Coverage Report
Generated: 2026-01-21T10:30:00Z

## Summary

| Metric | Value |
|--------|-------|
| Total SDEF files | 52 |
| Successfully parsed | 43 (82.7%) |
| Failed to parse | 9 |
| Total commands found | 1,247 |
| Total classes found | 423 |
| Total tools generated | 1,189 |
| Apps with tools | 41 |

## Performance

| Metric | Value |
|--------|-------|
| Average parse time | 0.8s |
| Slowest parse | 3.2s (Microsoft Word) |
| Fastest parse | 0.1s (TextEdit) |
| Total scan time | 28.4s |

## Error Breakdown

| Error Type | Count | Percentage |
|------------|-------|------------|
| MISSING_TYPE | 4 | 44.4% |
| XML_PARSE_ERROR | 3 | 33.3% |
| EXTERNAL_ENTITY | 2 | 22.2% |

## Top Apps by Tool Count

1. System Events: 127 tools
2. Finder: 45 tools
3. Safari: 32 tools
4. Mail: 28 tools
5. Notes: 24 tools

## Failed Apps

| App | Error Type | Details |
|-----|------------|---------|
| Microsoft Word | XML_PARSE_ERROR | Malformed XML at line 1542 |
| Adobe Photoshop | EXTERNAL_ENTITY | XInclude reference to external file |
| Custom App | MISSING_TYPE | 12 parameters missing type attribute |

## Recommendations

- **Phase 5**: Enhance type inference to fix 4 apps with MISSING_TYPE errors
- **Parser Robustness**: Investigate 3 XML_PARSE_ERROR cases for resilience improvements
- **External Entities**: Validate XInclude resolution for 2 remaining failures
```

---

### 11.2 Sample Test Fixtures Needed

Create these fixtures in `tests/fixtures/sdef/`:

**Valid SDEFs**:
```
valid/
  finder-minimal.sdef          # 5 commands, 2 classes
  safari-complex.sdef          # 20 commands, 10 classes, enumerations
  mail-standard.sdef           # Standard structure, no edge cases
```

**Edge Cases**:
```
edge-cases/
  missing-types.sdef           # Parameters without type attribute
  union-types.sdef             # type="file | text" patterns
  xinclude-external.sdef       # xi:include references
  large-dictionary.sdef        # 100+ commands (performance test)
```

**Invalid/Error Cases**:
```
invalid/
  empty.sdef                   # Zero bytes
  malformed-xml.sdef           # Unclosed tags, invalid syntax
  missing-root.sdef            # No <dictionary> element
  html-renamed.sdef            # HTML file with .sdef extension
  binary-file.sdef             # Non-text file
```

**Generation Script**:
```typescript
// scripts/generate-test-fixtures.ts
// Generate synthetic SDEF files for testing
```

---

### 11.3 CLI Usage Examples

```bash
# Basic coverage analysis (markdown output)
npm run sdef:coverage

# JSON output for automation/CI
npm run sdef:coverage -- --json > coverage-report.json

# Verbose mode (show detailed errors)
npm run sdef:coverage -- --verbose

# Fast scan (user apps only, skip system apps)
npm run sdef:coverage -- --apps-only

# Combined: JSON + verbose
npm run sdef:coverage -- --json --verbose

# Compare current run to baseline
npm run sdef:coverage:compare

# Generate HTML report (future)
npm run sdef:coverage -- --html --output=coverage.html
```

---

## 12. Final Checklist

### Before Starting Phase 4

- [ ] Phase 3 complete (1,322 tests passing)
- [ ] Git worktree created: `iac-mcp-phase-4-metrics`
- [ ] Branch created: `feature/phase-4-parser-metrics`
- [ ] This execution plan reviewed and understood
- [ ] Agent selection confirmed (Haiku for Steps 1-13, Sonnet for Steps 15-18)

### During Implementation

- [ ] Follow step-by-step sequence (§7)
- [ ] Run tests after each step
- [ ] Check coverage after each major milestone
- [ ] Commit frequently with descriptive messages
- [ ] Update checklist as steps complete

### Before Marking Phase 4 Complete

- [ ] All 19-21 steps complete
- [ ] 100% test coverage achieved
- [ ] All success criteria met (§6)
- [ ] Documentation complete and reviewed
- [ ] Baseline metrics captured
- [ ] `npm run sdef:coverage` works end-to-end
- [ ] Code review passed (user or self-review)
- [ ] PR created and merged

---

## 13. Conclusion

Phase 4 transforms the SDEF parser from "probably works" to **"measurably reliable"**. By implementing metrics collection, running comprehensive coverage analysis, and documenting findings, we establish:

1. **Baseline metrics** for tracking improvements
2. **Failure pattern visibility** for prioritizing future work
3. **User transparency** through comprehensive documentation
4. **Regression detection** via CI/CD integration

**Next Steps**: Review this plan, confirm approach, and proceed with implementation starting at Step 1.

---

**Document Version**: 1.0
**Author**: System Architect (Claude Sonnet 4.5)
**Date**: 2026-01-21
**Reviewers**: Project Lead
**Status**: Ready for Execution
