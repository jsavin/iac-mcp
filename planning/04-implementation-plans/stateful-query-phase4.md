# Phase 4: Sophisticated GC & Optimization - Implementation Plan

**Parent Plan:** [Stateful Query System](./stateful-query-system.md)
**Status:** Planning (blocked by Phase 1-3)
**Priority:** Medium (post-launch optimization)
**Estimated Effort:** 2-3 days
**Owner:** TBD
**Created:** 2026-01-27

---

## Goal

Production-ready reference management with intelligent garbage collection, performance optimization, and monitoring capabilities.

---

## Success Criteria

- ✅ Memory usage stable under long sessions (8+ hours)
- ✅ Old/invalid references cleaned up automatically
- ✅ Performance benchmarks met (see below)
- ✅ Graceful handling of stale references
- ✅ No performance degradation with 10,000+ references
- ✅ Reference statistics and monitoring available
- ✅ 100% test coverage maintained

---

## Deliverables

### 1. Enhanced ReferenceStore with LRU Eviction

**File:** `src/execution/reference-store.ts` (MODIFY)

**Add:**
- LRU eviction strategy (in addition to TTL)
- Max references per app limits
- Reference validation (check if object still exists)
- Statistics and monitoring

**Configuration:**
```typescript
interface ReferenceStoreConfig {
  ttl: number;              // 15 minutes default
  maxReferences: number;    // 10,000 default
  maxPerApp: number;        // 1,000 default
  cleanupInterval: number;  // 5 minutes default
  validateOnAccess: boolean; // false default (Phase 4: true)
}
```

**New Methods:**
```typescript
class ReferenceStore {
  // Existing methods...

  // Phase 4 additions
  async validate(id: string): Promise<boolean>;  // Check if object still exists
  evictLRU(count: number): string[];  // Evict least recently used
  getByApp(app: string): ObjectReference[];  // Get all refs for app
  clearApp(app: string): void;  // Remove all refs for app
  export(): SerializedReferenceStore;  // For persistence
  import(data: SerializedReferenceStore): void;  // For persistence
}
```

### 2. Reference Validation

**File:** `src/execution/reference-validator.ts` (NEW)

**Class:** `ReferenceValidator`

**Methods:**
```typescript
class ReferenceValidator {
  /**
   * Check if referenced object still exists
   * @returns true if valid, false if stale
   */
  async validate(ref: ObjectReference): Promise<boolean>;

  /**
   * Batch validate multiple references
   * @returns Map of reference ID to validation result
   */
  async validateBatch(refs: ObjectReference[]): Promise<Map<string, boolean>>;
}
```

**Implementation:**
- Build JXA code to check `obj.exists()`
- Execute with short timeout (100ms)
- Handle errors gracefully (app not running, permission denied)

### 3. Manual Cleanup Tool

**File:** `src/jitd/tool-generator/query-tools.ts` (MODIFY)

**Add Tool:**
```typescript
{
  name: "iac_mcp_release_reference",
  description: "Manually release an object reference to free memory. Useful for long-running sessions or when done with an object.",
  inputSchema: {
    type: "object",
    properties: {
      reference: {
        type: "string",
        description: "Object reference ID to release"
      }
    },
    required: ["reference"]
  }
}
```

**Add Tool:**
```typescript
{
  name: "iac_mcp_get_reference_stats",
  description: "Get statistics about current object references (for debugging and monitoring).",
  inputSchema: {
    type: "object",
    properties: {}
  }
}
```

### 4. Performance Optimizations

**File:** `src/execution/query-executor.ts` (MODIFY)

**Add:**
- Batch property reads (multiple properties in one JXA call)
- Property value caching (optional, configurable)
- JXA code caching (reuse compiled code)

**New Methods:**
```typescript
class QueryExecutor {
  /**
   * Get properties from multiple references in one call
   */
  async getPropertiesBatch(
    references: string[],
    properties?: string[]
  ): Promise<Map<string, Record<string, any>>>;

  /**
   * Prefetch properties (cache for later access)
   */
  async prefetchProperties(
    referenceId: string,
    properties: string[]
  ): Promise<void>;
}
```

### 5. Reference Persistence (Optional)

**File:** `src/execution/reference-persistence.ts` (NEW)

**Purpose:** Survive iac-mcp restarts

**Methods:**
```typescript
class ReferencePersistence {
  async save(store: ReferenceStore): Promise<void>;
  async load(): Promise<ReferenceStore>;
  async clear(): Promise<void>;
}
```

**Storage:** JSON file in `~/.iac-mcp/references.json`

**Notes:**
- Only persist canonical references (mail IDs, file paths)
- Validate all references on load
- Clear on major version upgrades

### 6. Monitoring & Metrics

**File:** `src/monitoring/reference-metrics.ts` (NEW)

**Metrics to Track:**
- Total references over time
- References per app
- Hit/miss rate (if caching enabled)
- Average reference age
- Eviction rate
- Validation failures

**Export Format:** JSON for logging/analysis

### 7. Tests

**Unit Tests:**
- `tests/unit/execution/reference-store-lru.test.ts` (NEW)
- `tests/unit/execution/reference-validator.test.ts` (NEW)
- `tests/unit/execution/query-executor-batch.test.ts` (NEW)
- `tests/unit/monitoring/reference-metrics.test.ts` (NEW)

**Integration Tests:**
- `tests/integration/reference-validation.test.ts` (NEW)
- `tests/integration/reference-persistence.test.ts` (NEW)

**Performance Tests:**
- `tests/performance/reference-store-scaling.test.ts` (NEW)
- `tests/performance/query-performance.test.ts` (NEW)
- `tests/performance/memory-leak.test.ts` (NEW)

**Test Cases:**
- ✅ LRU eviction when max references exceeded
- ✅ Per-app limits enforced
- ✅ Validation detects stale references
- ✅ Validation handles app not running
- ✅ Batch operations perform better than sequential
- ✅ Memory usage stable over 8 hours
- ✅ 10,000 references don't degrade performance
- ✅ Persistence survives restart
- ✅ Metrics export correct data

---

## Implementation Tasks

### Task 1: LRU Eviction Strategy (1 day)
- Implement LRU tracking (update on access)
- Add `evictLRU()` method
- Enforce max references limits
- Write unit tests

### Task 2: Reference Validation (0.5 days)
- Implement `ReferenceValidator` class
- Add validation to `get()` and `touch()` (configurable)
- Handle validation errors gracefully
- Write unit tests

### Task 3: Manual Cleanup Tools (0.5 days)
- Add `release_reference` tool
- Add `get_reference_stats` tool
- Write tests

### Task 4: Performance Optimizations (1 day)
- Implement batch property reads
- Add property caching (optional)
- JXA code caching
- Benchmark and measure improvements

### Task 5: Reference Persistence (0.5 days, optional)
- Implement persistence layer
- Save/load on startup/shutdown
- Validate loaded references
- Write tests

### Task 6: Monitoring & Metrics (0.5 days)
- Implement metrics collection
- Add export endpoint
- Write tests

### Task 7: Performance Testing (0.5 days)
- Write scaling tests (10,000 references)
- Write memory leak tests (8+ hour run)
- Write benchmark tests (latency, throughput)
- Validate all performance requirements met

---

## Performance Requirements

### Response Times (90th percentile)
- ✅ `query_object`: < 1 second
- ✅ `get_properties`: < 500ms
- ✅ `get_properties_batch` (10 refs): < 1.5 seconds
- ✅ `get_elements`: < 2 seconds (100 elements)
- ✅ Reference lookup: < 1ms
- ✅ Cleanup: < 100ms (non-blocking)
- ✅ Validation (single): < 200ms
- ✅ Validation (batch 10): < 1 second

### Memory
- ✅ < 50MB for 10,000 references
- ✅ < 10MB for 1,000 references
- ✅ No leaks over 8 hours (< 1% growth)

### Scalability
- ✅ Linear performance up to 10,000 references
- ✅ LRU eviction < 10ms per eviction

---

## LRU Eviction Strategy

### When to Evict
1. **Max total references exceeded** (10,000 default)
2. **Max per-app references exceeded** (1,000 default)
3. **Memory pressure** (optional, OS-dependent)

### What to Evict
1. **Oldest lastAccessedAt** (LRU)
2. **Skip recently created** (< 1 minute old)
3. **Batch evict** (remove 10% at a time to avoid frequent evictions)

### Eviction Process
```typescript
evictLRU(count: number): string[] {
  // 1. Sort by lastAccessedAt (ascending)
  const sorted = Array.from(this.references.values())
    .filter(ref => Date.now() - ref.createdAt > 60_000)  // Skip recent
    .sort((a, b) => a.lastAccessedAt - b.lastAccessedAt);

  // 2. Take oldest N
  const toEvict = sorted.slice(0, count);

  // 3. Remove from store
  for (const ref of toEvict) {
    this.references.delete(ref.id);
  }

  // 4. Return evicted IDs (for logging)
  return toEvict.map(ref => ref.id);
}
```

---

## Reference Validation Strategy

### When to Validate
1. **On access** (if `validateOnAccess: true`)
2. **During cleanup** (batch validate old references)
3. **On explicit user request** (via monitoring tool)

### Validation Logic
```typescript
async validate(ref: ObjectReference): Promise<boolean> {
  const jxaCode = `
    const app = Application("${ref.app}");
    try {
      const obj = ${this.buildObjectPath(ref.specifier, "app")};
      return obj.exists();
    } catch (error) {
      return false;
    }
  `;

  try {
    const result = await this.jxaExecutor.execute(jxaCode, { timeout: 200 });
    return result === true;
  } catch {
    return false;  // Assume invalid if validation fails
  }
}
```

### Handling Invalid References
1. **Automatic removal** (during cleanup)
2. **Clear error message** (on access attempt)
3. **Suggestion to re-query** (in error response)

---

## Reference Persistence Format

**File:** `~/.iac-mcp/references.json`

**Format:**
```json
{
  "version": "1.0",
  "savedAt": "2026-01-27T10:30:00Z",
  "references": [
    {
      "id": "ref_abc123",
      "app": "com.apple.mail",
      "type": "message",
      "specifier": { /* ObjectSpecifier */ },
      "createdAt": 1234567890000,
      "lastAccessedAt": 1234567890000
    }
  ]
}
```

**Loading Process:**
1. Load JSON from file
2. Parse references
3. Validate each reference (check if object still exists)
4. Remove stale references
5. Import valid references into ReferenceStore

**When to Save:**
- On shutdown (graceful)
- Periodically (every 5 minutes)
- On user request (via tool)

---

## Monitoring Dashboard (Example Output)

```json
{
  "statistics": {
    "totalReferences": 347,
    "referencesPerApp": {
      "com.apple.mail": 142,
      "com.apple.finder": 189,
      "com.apple.calendar": 16
    },
    "oldestReference": {
      "id": "ref_abc123",
      "age": "14m 32s",
      "app": "com.apple.mail"
    },
    "newestReference": {
      "id": "ref_xyz789",
      "age": "12s",
      "app": "com.apple.finder"
    },
    "memoryUsage": "3.2 MB",
    "evictionCount": 42,
    "validationFailures": 3
  },
  "health": "good",
  "recommendations": []
}
```

---

## Error Handling

### Max References Exceeded
```json
{
  "error": "max_references_exceeded",
  "maxReferences": 10000,
  "currentCount": 10000,
  "message": "Maximum number of references reached. Older references will be evicted automatically.",
  "suggestion": "Consider releasing unused references with release_reference tool"
}
```

### Validation Failed
```json
{
  "error": "reference_invalid",
  "reference": "ref_abc123",
  "message": "The referenced object no longer exists (validation failed)",
  "suggestion": "Query the object again using query_object"
}
```

---

## Dependencies

**Requires:**
- ✅ Phase 1 complete (core query system)
- ✅ Phase 2 complete (optional but recommended)
- ✅ Phase 3 complete (optional but recommended)

**Blocks:**
- None (this is an optimization phase)

---

## Open Questions

1. **Should we support reference sharing across MCP clients?**
   - Phase 4: No (single client assumed)
   - Future: Consider if multiple clients connect

2. **Should we use WeakRef for automatic GC?**
   - Phase 4: No (explicit LRU + TTL)
   - Future: Investigate if V8 WeakRef is reliable

3. **Should we persist to disk or just in-memory?**
   - Phase 4: Optional (start with in-memory, add persistence if requested)

---

## Migration from Phase 3

**Backwards Compatible:** All Phase 1-3 functionality continues to work.

**New Defaults:**
- `validateOnAccess`: `false` (to avoid performance impact)
- `maxReferences`: `10000`
- `maxPerApp`: `1000`

**User can configure via environment variables:**
```bash
IAC_MCP_REF_TTL=900000  # 15 minutes
IAC_MCP_REF_MAX=10000
IAC_MCP_REF_MAX_PER_APP=1000
IAC_MCP_REF_VALIDATE_ON_ACCESS=false
```

---

**Document Version:** 1.0
**Last Updated:** 2026-01-27
**Status:** Planning (blocked by Phase 1-3)
