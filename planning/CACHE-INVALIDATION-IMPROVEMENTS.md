# Cache Invalidation & Improvements

## Overview

This document outlines improvements to the MCP server's caching strategy to ensure cache consistency, improve performance, and handle app installations/removals correctly.

## Current State

### Per-App Tools Cache (Implemented)
**Location**: `~/.cache/iac-mcp/apps/{bundleId}.json`

**Caches**:
- Parsed SDEF dictionary
- Generated MCP tools
- Object model (classes/enumerations)

**Invalidation triggers**:
- ✅ SDEF file modification time changed
- ✅ Bundle directory modification time changed
- ✅ Cache version string mismatch
- ✅ Bundle path no longer exists (app removed)

**Performance**: <100ms cache hit, 1-3s cache miss

### App Discovery (Not Currently Cached)
**Current behavior**:
- Every `ListTools` call scans filesystem for apps with SDEFs
- Builds metadata in-memory (appName, bundleId, description, toolCount, suiteNames)
- No disk persistence

**Performance**: ~300ms for 50 apps (acceptable but could be better)

## Problems to Solve

### P1: App List Not Cached
**Impact**: Medium
- Filesystem scan on every `ListTools` call (300ms overhead)
- Unnecessary work when app list hasn't changed
- Will worsen as more apps are installed

**User impact**:
- Slower `list_apps()` responses
- Unnecessary disk I/O

### P2: Missing Version Number Detection
**Impact**: Low
- If app updates but bundle mtime unchanged (rare), cache isn't invalidated
- Could serve stale tools for updated apps
- Only affects edge cases (some installers don't update bundle mtime)

**User impact**:
- Rare: Tools may not match updated app version
- Workaround: Manual cache invalidation

### P3: No Cache Statistics/Monitoring
**Impact**: Low
- No visibility into cache performance
- Can't identify frequently-accessed apps
- Can't measure cache hit rate
- Orphaned caches accumulate over time

**User impact**:
- Wasted disk space from orphaned caches
- No way to troubleshoot cache issues

## Proposed Solutions

### Phase 1: App List Cache (Priority: High)

**Goal**: Persist discovered app list to disk, invalidate when apps added/removed

**Implementation**:

```typescript
// ~/.cache/iac-mcp/app-list.json
interface AppListCache {
  version: string;              // Cache format version
  discoveredAt: number;         // Timestamp of last discovery
  applicationsDirMtime: number; // /Applications mtime
  ttl: number;                  // Time-to-live in seconds (300 = 5min)
  apps: Array<{
    appName: string;
    bundlePath: string;
    sdefPath: string;
    bundleId?: string;          // Optional: if already extracted
  }>;
}
```

**Invalidation strategy**:
1. **Primary**: Check `/Applications` directory mtime
   - If changed → full rescan
   - If unchanged → use cache
2. **Secondary**: TTL-based expiration (5 minutes)
   - Handles apps in other locations (~/Applications, /System/Library/CoreServices)
   - Ensures freshness even if mtime unchanged

**Files to create/modify**:
- `src/jitd/cache/app-list-cache.ts` (NEW) - App list cache implementation
- `src/mcp/handlers.ts` (MODIFY) - Use app list cache in ListTools

**Performance improvement**:
- ListTools: 300ms → <50ms (6x faster on cache hit)
- `list_apps`: <50ms (near-instant)

**Trade-offs**:
- ✅ Pro: Significant performance improvement
- ✅ Pro: Reduces filesystem thrashing
- ⚠️ Con: 5-minute lag to detect new apps (acceptable)
- ⚠️ Con: Additional cache file to maintain

### Phase 2: Version Number Tracking (Priority: Medium)

**Goal**: Detect app version changes even when bundle mtime unchanged

**Implementation**:

```typescript
// Add to per-app cache metadata
interface PerAppCacheData {
  // ... existing fields ...
  metadata: {
    bundleMtime: number;
    sdefMtime: number;
    appVersion: string;    // NEW: CFBundleShortVersionString from Info.plist
    cacheVersion: string;
  };
}
```

**Validation logic**:
```typescript
async isValid(cached: PerAppCacheData, bundlePath: string): Promise<boolean> {
  // Existing checks (mtime, path exists)
  // ...

  // NEW: Version check
  const currentVersion = await readVersionFromPlist(bundlePath);
  if (currentVersion && cached.metadata.appVersion !== currentVersion) {
    console.log(`App version changed: ${cached.metadata.appVersion} → ${currentVersion}`);
    return false;
  }

  return true;
}
```

**Files to modify**:
- `src/jitd/cache/per-app-cache.ts` (MODIFY) - Add version tracking
- `src/jitd/discovery/app-tools-loader.ts` (MODIFY) - Extract version when caching

**Performance impact**: Negligible (Info.plist already read for bundle ID)

**Trade-offs**:
- ✅ Pro: More robust invalidation
- ✅ Pro: Catches edge cases with unchanged mtimes
- ⚠️ Con: Extra complexity
- ⚠️ Con: Apps without version numbers (handle gracefully)

### Phase 3: Cache Statistics & Monitoring (Priority: Low)

**Goal**: Provide visibility into cache performance and enable cleanup

**Implementation**:

```typescript
// ~/.cache/iac-mcp/cache-stats.json
interface CacheStats {
  version: string;
  stats: {
    appListCache: {
      hits: number;
      misses: number;
      lastHit: number;
    };
    perAppCache: {
      [bundleId: string]: {
        hits: number;
        misses: number;
        lastAccessed: number;
        size: number;  // bytes
      };
    };
  };
  orphanedCaches: string[];  // Bundle IDs with no corresponding app
}
```

**New MCP tool**: `mcp_cache_stats`
```json
{
  "name": "mcp_cache_stats",
  "description": "Get cache statistics and performance metrics",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {
        "type": "string",
        "enum": ["show", "cleanup_orphaned"]
      }
    }
  }
}
```

**Files to create**:
- `src/jitd/cache/cache-stats.ts` (NEW) - Statistics tracking
- Add tool to handlers

**Use cases**:
- Debug cache issues
- Identify frequently-used apps
- Clean up orphaned caches
- Monitor cache hit rate

**Trade-offs**:
- ✅ Pro: Visibility into cache behavior
- ✅ Pro: Enables troubleshooting
- ⚠️ Con: Additional overhead for stats tracking
- ⚠️ Con: Another file to maintain

## Implementation Priority

### Immediate (Week 1)
1. **Implement `list_apps` tool** - Required for user to discover apps
2. **Phase 1: App List Cache** - Significant performance improvement

### Near-term (Week 2-3)
3. **Phase 2: Version Tracking** - Robustness improvement
4. **Document cache behavior** - User-facing documentation

### Future (Month 2+)
5. **Phase 3: Cache Statistics** - Monitoring and debugging
6. **Cache eviction policy** - LRU or size-based limits
7. **Background cache warming** - Pre-cache popular apps on startup

## Testing Strategy

### Phase 1 Tests
- App list cache save/load
- TTL expiration handling
- /Applications mtime change detection
- Cache invalidation on new app install
- Cache persistence across server restarts

### Phase 2 Tests
- Version change detection
- Graceful handling of missing version
- Version unchanged (cache hit)
- Version changed (cache miss)

### Phase 3 Tests
- Stats tracking accuracy
- Orphaned cache detection
- Cleanup operation
- Stats persistence

## Success Metrics

### Phase 1
- ✅ ListTools <100ms on cache hit (currently 300ms)
- ✅ `list_apps` <50ms response time
- ✅ Cache invalidates within 5 minutes of app install

### Phase 2
- ✅ Detects app version changes reliably
- ✅ No false negatives (missed updates)
- ✅ Minimal false positives (unnecessary invalidations)

### Phase 3
- ✅ Cache hit rate >80% in normal usage
- ✅ Orphaned caches identified correctly
- ✅ Cleanup reduces disk usage

## Open Questions

1. **Cache directory location**: Is `~/.cache/iac-mcp/` the right location?
   - Alternative: `~/Library/Caches/com.iac-mcp/`
   - Recommendation: Stick with `~/.cache` (XDG standard, already implemented)

2. **Cache size limits**: Should we impose size limits?
   - Current: No limits (unbounded growth)
   - Recommendation: Defer until we see real-world usage patterns

3. **Background invalidation**: Should we watch filesystem changes?
   - Current: Check on access (lazy)
   - Alternative: Watch /Applications with FSEvents (proactive)
   - Recommendation: Defer (adds complexity, unclear benefit)

4. **Multi-user handling**: How to handle shared systems?
   - Current: Per-user cache (~/.cache)
   - Acceptable: Each user has their own cache

## Related Issues

- Issue #16: Test coverage for app-metadata-builder (1.81%)
- Issue #17: Test coverage for object-model-extractor (0.72%)
- Issue #18: Test coverage for app-tools-loader error paths (8.33%)

## References

- `src/jitd/cache/per-app-cache.ts` - Current per-app cache implementation
- `src/jitd/discovery/app-metadata-builder.ts` - Metadata building logic
- `src/mcp/handlers.ts` - ListTools handler (current app discovery)
- PR #15 - Original lazy loading implementation

---

**Status**: Planning (not yet implemented)
**Owner**: TBD
**Created**: 2026-01-22
**Last Updated**: 2026-01-22
