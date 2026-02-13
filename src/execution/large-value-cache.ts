import { randomUUID } from 'crypto';

/**
 * Cached large value entry.
 * Stores the full string value along with metadata for paging.
 */
export interface CachedValue {
  value: string;
  propertyName: string;
  sourceRef: string;
  totalLines: number;
  totalChars: number;
  cachedAt: number;
  lastAccessedAt: number;
}

/** Threshold above which string values are auto-cached (50KB) */
export const LARGE_VALUE_THRESHOLD = 50 * 1024;

/** Default maximum number of cached values */
export const DEFAULT_MAX_CACHED_VALUES = 100;

/** Default time-to-live for cached values (15 minutes) */
export const DEFAULT_TTL_MS = 15 * 60 * 1000;

/** Number of preview lines included in the large value marker */
export const PREVIEW_LINES = 50;

/**
 * Cache for large property values that exceed the transport threshold.
 *
 * When a property value exceeds LARGE_VALUE_THRESHOLD, it is stored here
 * and the response contains a preview + cache reference for paging.
 *
 * Uses LRU eviction when maxEntries is exceeded and TTL-based expiry on get().
 */
export class LargeValueCache {
  private entries: Map<string, CachedValue> = new Map();
  private maxEntries: number;
  private ttlMs: number;

  constructor(options?: { maxEntries?: number; ttlMs?: number }) {
    this.maxEntries = options?.maxEntries ?? DEFAULT_MAX_CACHED_VALUES;
    this.ttlMs = options?.ttlMs ?? DEFAULT_TTL_MS;
  }

  /**
   * Store a large value in the cache.
   *
   * @param value - The full string value to cache
   * @param propertyName - The property name that produced this value
   * @param sourceRef - The reference ID of the object that owns the property
   * @returns Cache ID and metadata (totalLines, totalChars, preview) to avoid redundant splitting
   */
  store(value: string, propertyName: string, sourceRef: string): {
    id: string;
    totalLines: number;
    totalChars: number;
    preview: string;
  } {
    // Evict if at capacity
    if (this.entries.size >= this.maxEntries) {
      this.evictLRU();
    }

    const id = `cache_${randomUUID()}`;
    const now = Date.now();
    const lines = value.split('\n');
    const totalLines = lines.length;
    const preview = lines.slice(-PREVIEW_LINES).join('\n');

    this.entries.set(id, {
      value,
      propertyName,
      sourceRef,
      totalLines,
      totalChars: value.length,
      cachedAt: now,
      lastAccessedAt: now,
    });

    return { id, totalLines, totalChars: value.length, preview };
  }

  /**
   * Retrieve a cached value by ID.
   * Updates lastAccessedAt on access. Returns undefined if expired or not found.
   *
   * @param id - Cache ID (format: cache_<uuid>)
   * @returns The cached value or undefined
   */
  get(id: string): CachedValue | undefined {
    const entry = this.entries.get(id);
    if (!entry) return undefined;

    // Check TTL
    if (Date.now() - entry.cachedAt > this.ttlMs) {
      this.entries.delete(id);
      return undefined;
    }

    // Touch for LRU
    entry.lastAccessedAt = Date.now();
    return entry;
  }

  /**
   * Delete a cached value by ID.
   *
   * @param id - Cache ID to delete
   * @returns true if the entry existed and was deleted
   */
  delete(id: string): boolean {
    return this.entries.delete(id);
  }

  /**
   * Clear all cached values.
   */
  clear(): void {
    this.entries.clear();
  }

  /**
   * Get cache statistics.
   *
   * @returns Total entries and total bytes stored
   */
  getStats(): { totalEntries: number; totalBytes: number } {
    let totalBytes = 0;
    for (const entry of this.entries.values()) {
      totalBytes += entry.totalChars;
    }
    return { totalEntries: this.entries.size, totalBytes };
  }

  /**
   * Evict the least recently used entry.
   */
  private evictLRU(): void {
    let oldestKey: string | undefined;
    let oldestTime = Infinity;

    for (const [key, entry] of this.entries) {
      if (entry.lastAccessedAt < oldestTime) {
        oldestTime = entry.lastAccessedAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.entries.delete(oldestKey);
    }
  }
}
