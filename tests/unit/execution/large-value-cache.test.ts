/**
 * Unit Tests for LargeValueCache
 *
 * Tests store/get/delete, TTL expiry, LRU eviction, and stats.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  LargeValueCache,
  LARGE_VALUE_THRESHOLD,
  DEFAULT_MAX_CACHED_VALUES,
  DEFAULT_TTL_MS,
  PREVIEW_LINES,
} from "../../../src/execution/large-value-cache.js";

describe("LargeValueCache", () => {
  let cache: LargeValueCache;

  beforeEach(() => {
    cache = new LargeValueCache();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Constants", () => {
    it("should export correct threshold value (50KB)", () => {
      expect(LARGE_VALUE_THRESHOLD).toBe(50 * 1024);
    });

    it("should export correct default max entries", () => {
      expect(DEFAULT_MAX_CACHED_VALUES).toBe(100);
    });

    it("should export correct default TTL (15 minutes)", () => {
      expect(DEFAULT_TTL_MS).toBe(15 * 60 * 1000);
    });

    it("should export correct preview lines count", () => {
      expect(PREVIEW_LINES).toBe(50);
    });
  });

  describe("store()", () => {
    it("should return a cache ID with cache_ prefix", () => {
      const id = cache.store("hello", "text", "ref_abc");
      expect(id).toMatch(/^cache_/);
    });

    it("should return unique IDs for different values", () => {
      const id1 = cache.store("value1", "text", "ref_abc");
      const id2 = cache.store("value2", "text", "ref_abc");
      expect(id1).not.toBe(id2);
    });

    it("should store metadata correctly", () => {
      const value = "line1\nline2\nline3";
      const id = cache.store(value, "content", "ref_xyz");
      const entry = cache.get(id);
      expect(entry).toBeDefined();
      expect(entry!.value).toBe(value);
      expect(entry!.propertyName).toBe("content");
      expect(entry!.sourceRef).toBe("ref_xyz");
      expect(entry!.totalLines).toBe(3);
      expect(entry!.totalChars).toBe(value.length);
      expect(entry!.cachedAt).toBeGreaterThan(0);
      expect(entry!.lastAccessedAt).toBeGreaterThan(0);
    });

    it("should count lines correctly for single-line value", () => {
      const id = cache.store("no newlines here", "text", "ref_1");
      const entry = cache.get(id);
      expect(entry!.totalLines).toBe(1);
    });

    it("should count lines correctly for value ending with newline", () => {
      const id = cache.store("line1\nline2\n", "text", "ref_1");
      const entry = cache.get(id);
      expect(entry!.totalLines).toBe(3); // split('\n') on "a\nb\n" = ["a","b",""]
    });
  });

  describe("get()", () => {
    it("should return undefined for non-existent ID", () => {
      expect(cache.get("cache_nonexistent")).toBeUndefined();
    });

    it("should return the cached value", () => {
      const id = cache.store("test value", "prop", "ref_1");
      const entry = cache.get(id);
      expect(entry).toBeDefined();
      expect(entry!.value).toBe("test value");
    });

    it("should update lastAccessedAt on get", () => {
      const id = cache.store("value", "prop", "ref_1");
      const entry1 = cache.get(id);
      const firstAccess = entry1!.lastAccessedAt;

      // Advance time slightly
      vi.spyOn(Date, "now").mockReturnValue(firstAccess + 1000);
      const entry2 = cache.get(id);
      expect(entry2!.lastAccessedAt).toBe(firstAccess + 1000);

      vi.restoreAllMocks();
    });

    it("should return undefined for expired entries", () => {
      const id = cache.store("value", "prop", "ref_1");
      const entry = cache.get(id);
      const cachedAt = entry!.cachedAt;

      // Advance time past TTL
      vi.spyOn(Date, "now").mockReturnValue(cachedAt + DEFAULT_TTL_MS + 1);
      expect(cache.get(id)).toBeUndefined();

      vi.restoreAllMocks();
    });

    it("should delete expired entries on access", () => {
      const id = cache.store("value", "prop", "ref_1");
      const entry = cache.get(id);
      const cachedAt = entry!.cachedAt;

      vi.spyOn(Date, "now").mockReturnValue(cachedAt + DEFAULT_TTL_MS + 1);
      cache.get(id); // triggers deletion

      vi.restoreAllMocks();

      // Even with time restored, entry should be gone (was deleted)
      expect(cache.getStats().totalEntries).toBe(0);
    });
  });

  describe("delete()", () => {
    it("should return true when entry exists", () => {
      const id = cache.store("value", "prop", "ref_1");
      expect(cache.delete(id)).toBe(true);
    });

    it("should return false when entry does not exist", () => {
      expect(cache.delete("cache_nonexistent")).toBe(false);
    });

    it("should remove entry from cache", () => {
      const id = cache.store("value", "prop", "ref_1");
      cache.delete(id);
      expect(cache.get(id)).toBeUndefined();
    });
  });

  describe("clear()", () => {
    it("should remove all entries", () => {
      cache.store("v1", "p1", "ref_1");
      cache.store("v2", "p2", "ref_2");
      cache.store("v3", "p3", "ref_3");

      cache.clear();
      expect(cache.getStats().totalEntries).toBe(0);
    });
  });

  describe("getStats()", () => {
    it("should return zero for empty cache", () => {
      const stats = cache.getStats();
      expect(stats.totalEntries).toBe(0);
      expect(stats.totalBytes).toBe(0);
    });

    it("should count entries and bytes", () => {
      cache.store("hello", "p1", "ref_1"); // 5 chars
      cache.store("world!!", "p2", "ref_2"); // 7 chars

      const stats = cache.getStats();
      expect(stats.totalEntries).toBe(2);
      expect(stats.totalBytes).toBe(12);
    });
  });

  describe("LRU Eviction", () => {
    it("should evict the least recently used entry when at capacity", () => {
      const smallCache = new LargeValueCache({ maxEntries: 3 });

      const id1 = smallCache.store("first", "p", "ref_1");
      const id2 = smallCache.store("second", "p", "ref_2");
      const id3 = smallCache.store("third", "p", "ref_3");

      // All three should exist
      expect(smallCache.get(id1)).toBeDefined();
      expect(smallCache.get(id2)).toBeDefined();
      expect(smallCache.get(id3)).toBeDefined();

      // Adding a 4th should evict the LRU one
      // id1 was accessed first, so it's LRU after the gets above...
      // Actually, we just accessed all three via get(). Let's use a fresh approach:
      const freshCache = new LargeValueCache({ maxEntries: 3 });
      const fid1 = freshCache.store("first", "p", "ref_1");
      const fid2 = freshCache.store("second", "p", "ref_2");
      const fid3 = freshCache.store("third", "p", "ref_3");

      // Touch fid2 and fid3 to make fid1 the LRU
      vi.spyOn(Date, "now").mockReturnValue(Date.now() + 1000);
      freshCache.get(fid2);
      freshCache.get(fid3);

      vi.restoreAllMocks();

      // Adding a 4th entry should evict fid1 (the LRU)
      const fid4 = freshCache.store("fourth", "p", "ref_4");

      expect(freshCache.get(fid1)).toBeUndefined(); // evicted
      expect(freshCache.get(fid2)).toBeDefined();
      expect(freshCache.get(fid3)).toBeDefined();
      expect(freshCache.get(fid4)).toBeDefined();
    });
  });

  describe("Custom TTL", () => {
    it("should respect custom TTL", () => {
      const shortTtlCache = new LargeValueCache({ ttlMs: 1000 }); // 1 second
      const id = shortTtlCache.store("value", "p", "ref_1");
      const entry = shortTtlCache.get(id);
      const cachedAt = entry!.cachedAt;

      // Should be available before TTL
      vi.spyOn(Date, "now").mockReturnValue(cachedAt + 500);
      expect(shortTtlCache.get(id)).toBeDefined();

      // Should expire after TTL
      vi.spyOn(Date, "now").mockReturnValue(cachedAt + 1001);
      expect(shortTtlCache.get(id)).toBeUndefined();

      vi.restoreAllMocks();
    });
  });
});
