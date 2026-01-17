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

## Architecture Review Notes

**Review Date:** 2026-01-16
**Reviewer:** System Architect Agent

### 1. Strict/Lenient Mode Design

**Assessment:** STRONGLY APPROVED with refinements

**Strengths:**
- Correctly separates concerns: strict for tests, lenient for production
- Aligns with Postel's Law ("Be conservative in what you send, liberal in what you accept")
- Warning system provides visibility without blocking functionality
- Matches industry patterns (ESLint, TypeScript, etc.)

**Refinements Needed:**

1. **Add explicit validation pass option**
   ```typescript
   interface SDEFParserOptions {
     mode?: 'strict' | 'lenient';  // Parsing strategy
     validate?: 'none' | 'warn' | 'error';  // Post-parse validation
     onWarning?: (warning: ParseWarning) => void;
   }
   ```
   Rationale: Separates parsing tolerance from validation strictness. Enables "parse everything, then validate" workflow.

2. **Warning categorization by severity**
   ```typescript
   interface ParseWarning {
     severity: 'info' | 'warning' | 'error';  // NEW
     code: string;
     message: string;
     // ... rest
   }
   ```
   Rationale: Enables filtering by severity, progressive enhancement of validation rules.

3. **Mode inheritance in tool generation**
   ```typescript
   // In tool-generator/generator.ts
   class ToolGenerator {
     constructor(
       private sdefParser: SDEFParser,
       options?: { inheritParserMode?: boolean }  // NEW
     )
   }
   ```
   Rationale: If parser uses lenient mode, tool generator should match. Prevents "parse succeeds, tool generation fails" scenarios.

**Concerns Addressed:**
- Q: "Should we have a 'permissive' mode beyond lenient?"
- A: NO. Two modes are sufficient. Add severity levels to warnings instead.
- Q: "Should strict mode be default?"
- A: NO. Lenient default is correct for JITD use case (discover installed apps). Reserve strict for CI/tests.

### 2. Phase Ordering

**Assessment:** APPROVED with one optimization

**Current Order:**
1. Type inference (Phase 1)
2. Multi-type support (Phase 2)
3. External entities (Phase 3)
4. Validation/metrics (Phase 4)

**Recommended Change: Swap Phases 2 and 3**

**Revised Order:**
1. Type inference (Phase 1) - 60% of failures, highest ROI
2. External entities (Phase 2) - 15% of failures, unblocks Apple iWork
3. Multi-type support (Phase 3) - 20% of failures, System Events
4. Validation/metrics (Phase 4) - Ongoing

**Rationale:**
- External entity resolution (Phase 3) is infrastructure-level
- Once built, it benefits both type inference AND multi-type parsing
- Multi-type support needs union types, which may appear in included files
- Phase 2 (entities) is security-critical and should be reviewed early
- Enables parallelization: One developer can work on Phase 1 while another reviews Phase 2 security

**Alternative:** Keep current order if single developer and want incremental wins. Phase 2 is simpler than Phase 3.

**Decision:** KEEP CURRENT ORDER for solo development. Swap only if adding contributors.

### 3. Architectural Patterns

**Recommended Patterns:**

#### 3.1 Strategy Pattern for Type Inference

```typescript
// src/jitd/discovery/type-inference/strategy.ts

interface TypeInferenceStrategy {
  canInfer(context: InferenceContext): boolean;
  infer(context: InferenceContext): SDEFType;
  priority: number;  // Higher = try first
}

class ChildTypeElementStrategy implements TypeInferenceStrategy {
  priority = 100;  // Highest
  canInfer(ctx: InferenceContext): boolean {
    return ctx.element.type !== undefined;
  }
  infer(ctx: InferenceContext): SDEFType {
    // Parse child <type> elements
  }
}

class NameHeuristicStrategy implements TypeInferenceStrategy {
  priority = 50;
  canInfer(ctx: InferenceContext): boolean {
    return true;  // Always can try
  }
  infer(ctx: InferenceContext): SDEFType {
    // Pattern matching on name
  }
}

class DefaultTextStrategy implements TypeInferenceStrategy {
  priority = 1;  // Lowest (fallback)
  canInfer(): boolean { return true; }
  infer(): SDEFType {
    return { kind: 'primitive', type: 'text' };
  }
}

class TypeInferenceEngine {
  constructor(private strategies: TypeInferenceStrategy[]) {
    // Sort by priority
    this.strategies.sort((a, b) => b.priority - a.priority);
  }

  inferType(context: InferenceContext): SDEFType {
    for (const strategy of this.strategies) {
      if (strategy.canInfer(context)) {
        return strategy.infer(context);
      }
    }
    throw new Error('No inference strategy matched (should never happen)');
  }
}
```

**Benefits:**
- Easily add new inference strategies (ML-based, corpus analysis, etc.)
- Clear priority ordering (explicit > heuristic > default)
- Testable in isolation
- Supports future "learn from usage" features

#### 3.2 Visitor Pattern for Warning Collection

```typescript
// src/jitd/discovery/visitors/warning-collector.ts

interface SDEFVisitor {
  visitDictionary?(dict: SDEFDictionary): void;
  visitSuite?(suite: SDEFSuite): void;
  visitCommand?(cmd: SDEFCommand): void;
  visitParameter?(param: SDEFParameter): void;
  // ... other visit methods
}

class WarningCollectorVisitor implements SDEFVisitor {
  private warnings: ParseWarning[] = [];

  visitParameter(param: SDEFParameter): void {
    if (param.type.kind === 'class' && param.inferredFromName) {
      this.warnings.push({
        code: 'INFERRED_TYPE',
        severity: 'warning',
        message: `Type inferred from name pattern`,
        location: { element: 'parameter', name: param.name }
      });
    }
  }

  getWarnings(): ParseWarning[] {
    return this.warnings;
  }
}

// In parser
class SDEFParser {
  parse(content: string, visitors?: SDEFVisitor[]): SDEFDictionary {
    const result = this.parseContent(content);

    // Run visitors
    visitors?.forEach(v => this.acceptVisitor(result, v));

    return result;
  }
}
```

**Benefits:**
- Separates warning collection from parsing logic
- Supports multiple concurrent visitors (metrics, validation, etc.)
- Can be disabled in production for performance
- Extensible for future analysis passes

#### 3.3 Builder Pattern for Entity Resolution

```typescript
// src/jitd/discovery/entity-resolver.ts

class EntityResolverBuilder {
  private trustedPaths: string[] = DEFAULT_TRUSTED_PATHS;
  private maxDepth = 3;
  private cacheEnabled = true;
  private allowList: Set<string> = new Set();
  private denyList: Set<string> = new Set();

  addTrustedPath(path: string): this {
    this.trustedPaths.push(path);
    return this;
  }

  setMaxDepth(depth: number): this {
    this.maxDepth = depth;
    return this;
  }

  allowEntity(href: string): this {
    this.allowList.add(href);
    return this;
  }

  denyEntity(href: string): this {
    this.denyList.add(href);
    return this;
  }

  build(): EntityResolver {
    return new EntityResolver({
      trustedPaths: this.trustedPaths,
      maxDepth: this.maxDepth,
      cacheEnabled: this.cacheEnabled,
      allowList: this.allowList,
      denyList: this.denyList,
    });
  }
}

// Usage in tests
const resolver = new EntityResolverBuilder()
  .addTrustedPath('/test/fixtures/')
  .setMaxDepth(1)
  .allowEntity('test-entity.sdef')
  .build();
```

**Benefits:**
- Explicit, testable configuration
- Security policies as code
- Easy to create test doubles with restricted permissions

#### 3.4 Chain of Responsibility for Type Parsing

Already partially implemented, but formalize:

```typescript
// src/jitd/discovery/type-parsing-chain.ts

abstract class TypeParser {
  protected next?: TypeParser;

  setNext(parser: TypeParser): TypeParser {
    this.next = parser;
    return parser;
  }

  abstract canParse(typeStr: string): boolean;
  abstract doParse(typeStr: string): SDEFType;

  parse(typeStr: string): SDEFType {
    if (this.canParse(typeStr)) {
      return this.doParse(typeStr);
    }
    if (this.next) {
      return this.next.parse(typeStr);
    }
    throw new Error(`No parser found for type: ${typeStr}`);
  }
}

class PrimitiveTypeParser extends TypeParser {
  canParse(typeStr: string): boolean {
    return ['text', 'integer', 'real', 'boolean'].includes(typeStr);
  }
  doParse(typeStr: string): SDEFType {
    return { kind: 'primitive', type: typeStr as any };
  }
}

class ListTypeParser extends TypeParser {
  canParse(typeStr: string): boolean {
    return /^list(?:\s+of\s+)?/.test(typeStr);
  }
  doParse(typeStr: string): SDEFType {
    // Extract item type and recurse
  }
}

// Build chain
const typeParser = new PrimitiveTypeParser();
typeParser
  .setNext(new FileTypeParser())
  .setNext(new ListTypeParser())
  .setNext(new RecordTypeParser())
  .setNext(new ClassReferenceParser());
```

**Benefits:**
- Clear separation of type parsing rules
- Easy to add new type formats
- Testable in isolation

### 4. JITD Architecture Fit

**Assessment:** EXCELLENT FIT with architectural implications

**Current JITD Flow:**
```
Discovery → Parsing → Tool Generation → Execution
    ↓          ↓            ↓              ↓
find-sdef  parse-sdef   generator.ts   (future)
```

**Impact of Lenient Parsing:**

**Positive:**
- Dramatically increases discoverable apps (25% → 80%+)
- Aligns with JITD philosophy: "discover what's there, make it work"
- Warning system provides data for future improvements

**Architectural Debt:**
- Tool generator must handle inferred types (may produce suboptimal JSON Schema)
- JXA executor must handle type coercion (string → intended type)
- Need telemetry to track inference accuracy

**Recommendations:**

1. **Add telemetry layer**
   ```typescript
   interface ParserTelemetry {
     sdefPath: string;
     parseMode: 'strict' | 'lenient';
     warnings: ParseWarning[];
     inferredTypes: Array<{
       element: string;
       inferredType: SDEFType;
       actualUsage?: SDEFType;  // Populated post-execution
     }>;
   }
   ```
   Track inference accuracy to improve heuristics over time.

2. **Staged rollout in tool generator**
   ```typescript
   class ToolGenerator {
     generateTools(sdef: SDEFDictionary, options?: {
       skipCommandsWithInferredTypes?: boolean;  // Safety valve
       warnOnInferredTypes?: boolean;
     })
   }
   ```
   Initially, skip commands with inferred types (conservative). Enable gradually.

3. **Type coercion layer in executor**
   ```typescript
   // Future: src/jitd/executor/type-coercion.ts
   class TypeCoercer {
     coerce(value: any, expectedType: SDEFType): any {
       // Handle string → integer, etc.
       // Log coercion warnings
     }
   }
   ```

4. **JITD cache invalidation**
   Current cache uses file path as key. Add parser version:
   ```typescript
   interface CachedSDEF {
     path: string;
     parserVersion: string;  // NEW
     parseMode: 'strict' | 'lenient';  // NEW
     content: SDEFDictionary;
   }
   ```
   Invalidate cache when parser improves (prevents stale inferences).

### 5. Cross-Platform Extensibility

**Assessment:** EXCELLENT with abstraction layer

**Current Implementation:** macOS-specific (SDEF files)

**Future Platforms:**
- **Windows:** COM Type Libraries (.tlb), VBA Object Models
- **Linux:** D-Bus introspection XML

**Abstraction Recommendation:**

```typescript
// src/jitd/discovery/capability-parser.ts

interface PlatformCapabilityParser {
  readonly platform: 'macos' | 'windows' | 'linux';

  findCapabilityFiles(appPath: string): Promise<string[]>;

  parseCapabilities(
    filePath: string,
    options?: ParserOptions
  ): Promise<AppCapabilities>;
}

interface AppCapabilities {
  appName: string;
  appVersion?: string;
  platform: string;
  commands: CapabilityCommand[];
  classes: CapabilityClass[];
  enumerations: CapabilityEnumeration[];
}

// Platform-specific implementations
class MacOSSDEFParser implements PlatformCapabilityParser {
  platform = 'macos' as const;

  async parseCapabilities(sdefPath: string): Promise<AppCapabilities> {
    const sdef = await this.sdefParser.parse(sdefPath);
    return this.convertSDEFToCapabilities(sdef);
  }
}

class WindowsCOMParser implements PlatformCapabilityParser {
  platform = 'windows' as const;
  // Parse .tlb files, extract COM interfaces
}

class LinuxDBusParser implements PlatformCapabilityParser {
  platform = 'linux' as const;
  // Parse D-Bus XML introspection
}

// Factory
class CapabilityParserFactory {
  static create(platform: string): PlatformCapabilityParser {
    switch (platform) {
      case 'macos': return new MacOSSDEFParser();
      case 'windows': return new WindowsCOMParser();
      case 'linux': return new LinuxDBusParser();
      default: throw new Error(`Unsupported platform: ${platform}`);
    }
  }
}
```

**Benefits:**
- SDEF improvements (lenient parsing, type inference) inform other platforms
- Shared warning/telemetry infrastructure
- Platform-specific quirks isolated
- Easy to add new platforms

**Migration Path:**
1. Extract `SDEFParser` → `MacOSSDEFParser`
2. Create `AppCapabilities` interface (platform-agnostic)
3. Refactor tool generator to use `AppCapabilities` instead of `SDEFDictionary`
4. Add Windows/Linux parsers when funded

**Timing:** Do this abstraction in Phase 4 (after SDEF improvements stabilize).

### 6. Warning Collection Architecture

**Assessment:** CENTRALIZED with per-phase granularity

**Recommendation: Centralized Warning System**

```typescript
// src/jitd/discovery/warning-system.ts

class WarningSystem {
  private warnings: ParseWarning[] = [];
  private handlers: WarningHandler[] = [];

  addHandler(handler: WarningHandler): void {
    this.handlers.push(handler);
  }

  warn(warning: ParseWarning): void {
    this.warnings.push(warning);
    this.handlers.forEach(h => h.handle(warning));
  }

  getWarnings(filter?: WarningFilter): ParseWarning[] {
    if (!filter) return this.warnings;
    return this.warnings.filter(w => this.matchesFilter(w, filter));
  }

  clear(): void {
    this.warnings = [];
  }
}

interface WarningHandler {
  handle(warning: ParseWarning): void;
}

class LoggingWarningHandler implements WarningHandler {
  handle(warning: ParseWarning): void {
    console.warn(`[${warning.severity}] ${warning.code}: ${warning.message}`);
  }
}

class TelemetryWarningHandler implements WarningHandler {
  handle(warning: ParseWarning): void {
    // Send to metrics service
  }
}

// Usage
const warningSystem = new WarningSystem();
warningSystem.addHandler(new LoggingWarningHandler());
if (process.env.TELEMETRY_ENABLED) {
  warningSystem.addHandler(new TelemetryWarningHandler());
}

const parser = new SDEFParser({
  mode: 'lenient',
  onWarning: (w) => warningSystem.warn(w)
});
```

**Rationale:**
- Single source of truth for warnings
- Easy to add new handlers (logging, telemetry, testing)
- Supports filtering by phase, severity, code
- Can be disabled in production for performance

**Per-Phase Granularity:**
Add phase context to warnings:

```typescript
interface ParseWarning {
  phase: 'parsing' | 'type-inference' | 'entity-resolution' | 'validation';
  code: string;
  severity: 'info' | 'warning' | 'error';
  message: string;
  location: WarningLocation;
  inferredValue?: string;
}
```

Enables phase-specific analysis: "Type inference warnings increased 20% → investigate".

### 7. Additional Recommendations

#### 7.1 Error Handling Consistency

Current parser throws errors. With lenient mode, establish hierarchy:

```typescript
class SDEFParseError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly recoverable: boolean
  ) {
    super(message);
  }
}

// Lenient mode
if (mode === 'lenient' && error.recoverable) {
  warn({ code: error.code, message: error.message });
  // Continue parsing
} else {
  throw error;
}
```

#### 7.2 Performance Monitoring

Add performance metrics to identify bottlenecks:

```typescript
interface ParseMetrics {
  totalTimeMs: number;
  phases: {
    xmlParsing: number;
    typeInference: number;
    entityResolution: number;
    validation: number;
  };
}
```

Large SDEFs (System Events = 109KB) may have performance implications.

#### 7.3 Security Review Checklist for Phase 3

Beyond what's in PHASE-3 document, add:

- File descriptor exhaustion (limit concurrent entity reads)
- TOCTOU attacks (validate after resolution)
- Zip slip variants (macOS .app bundles are directories, but be careful)
- Entity expansion attacks (even XInclude can nest deeply)

#### 7.4 Versioning Strategy

SDEF format may evolve. Add version detection:

```typescript
interface SDEFMetadata {
  version?: string;  // From XML or DTD reference
  generator?: string;  // Some SDEFs include generator info
}
```

Warn if parsing newer SDEF versions with old parser.

### 8. Implementation Priority Adjustments

**Original plan is solid.** Suggested micro-optimizations:

**Phase 1 (Type Inference):**
- Extract strategy pattern early (day 0.5) → easier to add strategies
- Add name heuristics incrementally (don't block on comprehensive list)
- Test with Safari first (highest value app)

**Phase 2 (Multi-Type):**
- Consider deferring full union type support
- Initial implementation: use first type only, log others as warning
- Enables faster success metrics, refine later

**Phase 3 (External Entities):**
- Build security tests FIRST (TDD for security)
- Consider using security audit tool (npm audit, Snyk)
- Document threat model explicitly

**Phase 4 (Validation/Metrics):**
- Start metrics collection in Phase 1 (don't wait)
- Embed telemetry from day one
- Creates feedback loop for Phase 2/3 improvements

### 9. Risk Assessment

**HIGH RISKS:**

1. **Type inference accuracy** (Phase 1)
   - Mitigation: Conservative defaults, extensive testing, telemetry
   - Fallback: Disable tool generation for inferred types

2. **Security vulnerabilities** (Phase 3)
   - Mitigation: Security-first design, external audit, fuzzing
   - Fallback: Disable entity resolution until audited

3. **Performance regression** (All phases)
   - Mitigation: Benchmark before/after, cache aggressively
   - Fallback: Lazy parsing (parse on first use, not discovery)

**MEDIUM RISKS:**

4. **Breaking existing tools** (All phases)
   - Mitigation: 100% test coverage, regression suite
   - Fallback: Versioned parser (v1 = strict, v2 = lenient)

5. **Warning noise** (All phases)
   - Mitigation: Severity levels, filtering, aggregation
   - Fallback: Silent mode for production, verbose for dev

**LOW RISKS:**

6. **Cache invalidation bugs**
   - Mitigation: Include parser version in cache key
   - Fallback: Clear cache on parser update

### 10. Success Criteria Refinement

**Quantitative:**
- 80%+ parse success rate (GOOD)
- <5% tool generation failures on parsed SDEFs (ADD)
- <100ms parse time for 90th percentile SDEFs (ADD)
- Zero security vulnerabilities in Phase 3 (CRITICAL)

**Qualitative:**
- Safari, Chrome, Office, System Events all working (GOOD)
- Clear warning messages that guide debugging (ADD)
- Documentation explains limitations (GOOD)

### 11. Long-Term Architectural Vision

**Beyond Phase 4:**

1. **Machine Learning Type Inference**
   - Collect corpus of (parameter name, actual type) pairs
   - Train simple classifier to improve heuristics
   - Feedback loop from JXA execution errors

2. **Collaborative Filtering**
   - Share anonymized SDEF metadata across installs
   - "Users with Safari SDEF also have Chrome SDEF"
   - Improve inference based on crowd wisdom

3. **Developer Overrides**
   - Allow users to provide custom type hints
   - Store in `~/.iac-mcp/type-overrides.json`
   - Useful for broken SDEFs (app developer's fault)

4. **SDEF Linter**
   - Help app developers fix their SDEFs
   - Generate reports: "Your SDEF is missing types in 5 places"
   - Builds goodwill with indie developer community

### Summary of Recommendations

**APPROVED AS-IS:**
- Strict/lenient mode design (with refinements above)
- Phase ordering (current sequence is correct for solo dev)
- Warning collection approach (centralized)

**ADOPT THESE PATTERNS:**
- Strategy pattern for type inference
- Visitor pattern for warning collection
- Builder pattern for entity resolver
- Chain of responsibility for type parsing

**ARCHITECTURAL ADDITIONS:**
- Telemetry layer for inference accuracy
- Platform abstraction layer (Phase 4+)
- Versioned caching
- Performance monitoring

**PHASE ADJUSTMENTS:**
- Start metrics collection in Phase 1 (don't wait)
- TDD for security in Phase 3
- Consider staged rollout of inferred types in tool generator

**RISKS TO WATCH:**
- Type inference accuracy (mitigate with telemetry)
- Security in entity resolution (audit before shipping)
- Performance regression (benchmark continuously)

This is a well-designed improvement plan that correctly prioritizes practical interoperability over perfect compliance. The strict/lenient mode is architecturally sound, and the phased approach manages risk effectively. Recommended patterns will improve maintainability and extensibility for the long-term JITD vision.

The plan aligns excellently with the project's core philosophy: "Make everything work with everything else." Lenient parsing embodies this principle by meeting apps where they are, not where we wish they were.
