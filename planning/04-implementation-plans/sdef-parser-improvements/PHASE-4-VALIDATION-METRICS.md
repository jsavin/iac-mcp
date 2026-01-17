# Phase 4: Validation & Metrics

> **Model**: Haiku
> **Effort**: Ongoing
> **Goal**: Production hardening and monitoring

## Problem

Need visibility into parser success rates and remaining failure patterns to:
- Track improvement progress
- Identify remaining issues
- Guide future development

## Tasks

### 1. Add parser metrics (0.5 day)

```typescript
// src/jitd/discovery/parser-metrics.ts

export interface ParserMetrics {
  totalFiles: number;
  successfulParses: number;
  failedParses: number;
  partialParses: number;  // Parsed with warnings
  warningsByCode: Record<string, number>;
  failuresByReason: Record<string, number>;
  toolsGenerated: number;
  appsWithTools: number;
}

export interface ParseAttempt {
  sdefPath: string;
  appName: string;
  success: boolean;
  warnings: ParseWarning[];
  error?: string;
  toolCount: number;
  parseTimeMs: number;
}

export class ParserMetricsCollector {
  private attempts: ParseAttempt[] = [];

  record(attempt: ParseAttempt): void {
    this.attempts.push(attempt);
  }

  getMetrics(): ParserMetrics {
    const successful = this.attempts.filter(a => a.success);
    const failed = this.attempts.filter(a => !a.success);
    const withWarnings = successful.filter(a => a.warnings.length > 0);

    // Aggregate warnings by code
    const warningsByCode: Record<string, number> = {};
    for (const attempt of successful) {
      for (const warning of attempt.warnings) {
        warningsByCode[warning.code] = (warningsByCode[warning.code] || 0) + 1;
      }
    }

    // Aggregate failures by reason
    const failuresByReason: Record<string, number> = {};
    for (const attempt of failed) {
      const reason = this.classifyError(attempt.error || 'Unknown');
      failuresByReason[reason] = (failuresByReason[reason] || 0) + 1;
    }

    return {
      totalFiles: this.attempts.length,
      successfulParses: successful.length,
      failedParses: failed.length,
      partialParses: withWarnings.length,
      warningsByCode,
      failuresByReason,
      toolsGenerated: this.attempts.reduce((sum, a) => sum + a.toolCount, 0),
      appsWithTools: successful.filter(a => a.toolCount > 0).length,
    };
  }

  private classifyError(error: string): string {
    if (error.includes('type')) return 'MISSING_TYPE';
    if (error.includes('xi:include')) return 'EXTERNAL_ENTITY';
    if (error.includes('XML')) return 'MALFORMED_XML';
    if (error.includes('name')) return 'MISSING_NAME';
    return 'OTHER';
  }

  generateReport(): string {
    const metrics = this.getMetrics();
    const successRate = (metrics.successfulParses / metrics.totalFiles * 100).toFixed(1);

    return `
# SDEF Parser Metrics Report

## Summary

| Metric | Value |
|--------|-------|
| Total SDEF files | ${metrics.totalFiles} |
| Successfully parsed | ${metrics.successfulParses} (${successRate}%) |
| Failed to parse | ${metrics.failedParses} |
| Parsed with warnings | ${metrics.partialParses} |
| Total tools generated | ${metrics.toolsGenerated} |
| Apps with tools | ${metrics.appsWithTools} |

## Warnings by Type

${Object.entries(metrics.warningsByCode)
  .sort(([,a], [,b]) => b - a)
  .map(([code, count]) => `- ${code}: ${count}`)
  .join('\n')}

## Failures by Reason

${Object.entries(metrics.failuresByReason)
  .sort(([,a], [,b]) => b - a)
  .map(([reason, count]) => `- ${reason}: ${count}`)
  .join('\n')}
`;
  }
}
```

### 2. Run against all SDEFs (0.5 day)

Create a script to parse all SDEF files on the system:

```typescript
// scripts/analyze-sdef-coverage.ts

import { glob } from 'glob';
import { SDEFParser } from '../src/jitd/discovery/parse-sdef.js';
import { ParserMetricsCollector } from '../src/jitd/discovery/parser-metrics.js';

async function analyzeSDEFCoverage() {
  const collector = new ParserMetricsCollector();
  const parser = new SDEFParser({ mode: 'lenient' });

  // Find all SDEF files
  const sdefPaths = await glob([
    '/Applications/**/*.sdef',
    '/System/Applications/**/*.sdef',
    '/System/Library/CoreServices/**/*.sdef',
    '~/Applications/**/*.sdef',
  ]);

  console.log(`Found ${sdefPaths.length} SDEF files\n`);

  for (const sdefPath of sdefPaths) {
    const startTime = Date.now();
    const warnings: ParseWarning[] = [];

    try {
      const content = await fs.readFile(sdefPath, 'utf-8');
      const result = parser.parse(content, {
        onWarning: (w) => warnings.push(w)
      });

      collector.record({
        sdefPath,
        appName: extractAppName(sdefPath),
        success: true,
        warnings,
        toolCount: result.commands.length,
        parseTimeMs: Date.now() - startTime,
      });
    } catch (error) {
      collector.record({
        sdefPath,
        appName: extractAppName(sdefPath),
        success: false,
        warnings,
        error: error.message,
        toolCount: 0,
        parseTimeMs: Date.now() - startTime,
      });
    }
  }

  // Generate report
  console.log(collector.generateReport());
}

analyzeSDEFCoverage();
```

### 3. Document limitations (0.5 day)

Update `docs/TROUBLESHOOTING.md` with:
- Known unsupported patterns
- Common errors and solutions
- How to report issues

## Success Criteria

- [ ] Metrics collected for all SDEFs
- [ ] Known limitations documented
- [ ] 80%+ success rate achieved
- [ ] Report generation automated

## Files to Create/Modify

| File | Changes |
|------|---------|
| `src/jitd/discovery/parser-metrics.ts` | New file |
| `scripts/analyze-sdef-coverage.ts` | New file |
| `docs/TROUBLESHOOTING.md` | Document limitations |

## Metrics Dashboard (Future)

Consider adding a simple CLI dashboard:

```bash
$ npm run sdef:coverage

SDEF Parser Coverage
====================
Success Rate: 82% (43/52)

Top Issues:
  - MISSING_TYPE: 12 files
  - EXTERNAL_ENTITY: 5 files
  - MALFORMED_XML: 2 files

Apps with Most Tools:
  1. System Events: 127 tools
  2. Finder: 45 tools
  3. Safari: 32 tools
```

## Known Limitations

After completing Phases 1-3, document remaining unsupported patterns:

| Pattern | Reason | Workaround |
|---------|--------|------------|
| AETE format | Legacy format, no XML | None (very rare) |
| Custom DTD extensions | Non-standard | Report to maintainer |
| Encrypted SDEF | Security feature | None |

## Maintenance

This phase is ongoing:
- Run coverage analysis after each improvement
- Track metrics over time
- Prioritize fixes based on impact
