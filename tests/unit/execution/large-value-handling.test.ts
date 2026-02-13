/**
 * Unit Tests for QueryExecutor Large Value Handling
 *
 * Tests processLargeValues, getCachedValue, and JXA line truncation.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryExecutor } from "../../../src/execution/query-executor.js";
import { ReferenceStore } from "../../../src/execution/reference-store.js";
import { LargeValueCache, LARGE_VALUE_THRESHOLD, PREVIEW_LINES } from "../../../src/execution/large-value-cache.js";

/**
 * Helper: create a mock JXA result object matching ResultParser's expected format
 */
function jxaResult(data: unknown): { exitCode: number; stdout: string; stderr: string } {
  return { exitCode: 0, stdout: JSON.stringify(data), stderr: "" };
}

describe("QueryExecutor Large Value Handling", () => {
  let store: ReferenceStore;
  let cache: LargeValueCache;
  let executor: QueryExecutor;
  let executeFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    store = new ReferenceStore();
    cache = new LargeValueCache();

    executeFn = vi.fn();
    const mockJxaExecutor = { execute: executeFn } as any;

    executor = new QueryExecutor(store, mockJxaExecutor, cache);
  });

  /**
   * Helper: create a string of N lines, each ~80 chars
   */
  function makeLines(n: number): string {
    return Array.from({ length: n }, (_, i) => `Line ${i + 1}: ${"x".repeat(70)}`).join("\n");
  }

  /**
   * Helper: create a string larger than LARGE_VALUE_THRESHOLD
   */
  function makeLargeString(): string {
    // Each line is ~80 chars + newline, so ~80 bytes per line
    // 50KB / 80 ≈ 640 lines; let's use 700 to be safe
    return makeLines(700);
  }

  describe("processLargeValues (via getProperties)", () => {
    it("should pass through values below threshold unchanged", async () => {
      const refId = store.create("TestApp", "window", {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      });

      const smallValue = "small text value";
      executeFn.mockResolvedValue(jxaResult({ text: smallValue }));

      const result = await executor.getProperties(refId, ["text"]);
      expect(result.text).toBe(smallValue);
    });

    it("should auto-cache values exceeding threshold", async () => {
      const refId = store.create("TestApp", "window", {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      });

      const largeValue = makeLargeString();
      expect(largeValue.length).toBeGreaterThan(LARGE_VALUE_THRESHOLD);

      executeFn.mockResolvedValue(jxaResult({ text: largeValue }));

      const result = await executor.getProperties(refId, ["text"]);

      // Should return a _large_value marker
      expect(result.text._large_value).toBe(true);
      expect(result.text._cached_ref).toMatch(/^cache_/);
      expect(result.text._total_lines).toBe(largeValue.split("\n").length);
      expect(result.text._total_chars).toBe(largeValue.length);
      expect(typeof result.text._preview).toBe("string");
    });

    it("should include last N lines as preview", async () => {
      const refId = store.create("TestApp", "window", {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      });

      const largeValue = makeLargeString();
      executeFn.mockResolvedValue(jxaResult({ text: largeValue }));

      const result = await executor.getProperties(refId, ["text"]);
      const lines = largeValue.split("\n");
      const expectedPreview = lines.slice(-PREVIEW_LINES).join("\n");
      expect(result.text._preview).toBe(expectedPreview);
    });

    it("should not auto-cache when largeValueCache is not provided", async () => {
      const noCacheExecutor = new QueryExecutor(store, { execute: executeFn } as any);
      const refId = store.create("TestApp", "window", {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      });

      const largeValue = makeLargeString();
      executeFn.mockResolvedValue(jxaResult({ text: largeValue }));

      const result = await noCacheExecutor.getProperties(refId, ["text"]);
      // Should return raw value (no _large_value marker)
      expect(result.text).toBe(largeValue);
    });

    it("should only cache string values, not objects", async () => {
      const refId = store.create("TestApp", "window", {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      });

      executeFn.mockResolvedValue(jxaResult({ name: "hello", count: 42, visible: true }));

      const result = await executor.getProperties(refId, ["name", "count", "visible"]);
      expect(result.name).toBe("hello");
      expect(result.count).toBe(42);
      expect(result.visible).toBe(true);
    });
  });

  describe("getCachedValue", () => {
    it("should return full value when no options specified", () => {
      const value = "line1\nline2\nline3\nline4\nline5";
      const cacheId = cache.store(value, "text", "ref_1");

      const result = executor.getCachedValue(cacheId);
      expect(result.value).toBe(value);
      expect(result.total_lines).toBe(5);
      expect(result.total_chars).toBe(value.length);
      expect(result.lines_returned).toBe(5);
    });

    it("should return last N lines with tail_lines", () => {
      const value = "line1\nline2\nline3\nline4\nline5";
      const cacheId = cache.store(value, "text", "ref_1");

      const result = executor.getCachedValue(cacheId, { tail_lines: 2 });
      expect(result.value).toBe("line4\nline5");
      expect(result.lines_returned).toBe(2);
    });

    it("should return first N lines with head_lines", () => {
      const value = "line1\nline2\nline3\nline4\nline5";
      const cacheId = cache.store(value, "text", "ref_1");

      const result = executor.getCachedValue(cacheId, { head_lines: 3 });
      expect(result.value).toBe("line1\nline2\nline3");
      expect(result.lines_returned).toBe(3);
    });

    it("should apply offset_lines before tail_lines", () => {
      const value = "line1\nline2\nline3\nline4\nline5";
      const cacheId = cache.store(value, "text", "ref_1");

      const result = executor.getCachedValue(cacheId, { offset_lines: 1, tail_lines: 2 });
      // After offset: line2, line3, line4, line5
      // After tail(2): line4, line5
      expect(result.value).toBe("line4\nline5");
      expect(result.lines_returned).toBe(2);
    });

    it("should apply offset_lines before head_lines", () => {
      const value = "line1\nline2\nline3\nline4\nline5";
      const cacheId = cache.store(value, "text", "ref_1");

      const result = executor.getCachedValue(cacheId, { offset_lines: 2, head_lines: 2 });
      // After offset: line3, line4, line5
      // After head(2): line3, line4
      expect(result.value).toBe("line3\nline4");
      expect(result.lines_returned).toBe(2);
    });

    it("should apply max_lines cap", () => {
      const value = "line1\nline2\nline3\nline4\nline5";
      const cacheId = cache.store(value, "text", "ref_1");

      const result = executor.getCachedValue(cacheId, { max_lines: 3 });
      expect(result.value).toBe("line1\nline2\nline3");
      expect(result.lines_returned).toBe(3);
    });

    it("should throw for non-existent cache ref", () => {
      expect(() => executor.getCachedValue("cache_nonexistent")).toThrow(
        /Cached value not found/
      );
    });

    it("should throw when largeValueCache is not available", () => {
      const noCacheExecutor = new QueryExecutor(store, { execute: executeFn } as any);
      expect(() => noCacheExecutor.getCachedValue("cache_123")).toThrow(
        /Large value cache is not available/
      );
    });

    it("should include slice description in response", () => {
      const cacheId = cache.store("a\nb\nc", "text", "ref_1");

      const r1 = executor.getCachedValue(cacheId);
      expect(r1.slice).toBe("full");

      const r2 = executor.getCachedValue(cacheId, { tail_lines: 2 });
      expect(r2.slice).toContain("tail 2");

      const r3 = executor.getCachedValue(cacheId, { head_lines: 1, offset_lines: 1 });
      expect(r3.slice).toContain("offset 1");
      expect(r3.slice).toContain("head 1");
    });
  });

  describe("JXA Line Truncation (buildPropertyAccessorIIFE)", () => {
    it("should include tail_lines truncation in JXA code", async () => {
      const refId = store.create("TestApp", "session", {
        type: "element",
        element: "session",
        index: 0,
        container: "application",
      });

      executeFn.mockResolvedValue(jxaResult({ text: "last line" }));

      await executor.getProperties(refId, ["text"], { tail_lines: 50 });

      const jxaCode = executeFn.mock.calls[0]![0] as string;
      expect(jxaCode).toContain("slice(-50)");
    });

    it("should include head_lines truncation in JXA code", async () => {
      const refId = store.create("TestApp", "session", {
        type: "element",
        element: "session",
        index: 0,
        container: "application",
      });

      executeFn.mockResolvedValue(jxaResult({ text: "first line" }));

      await executor.getProperties(refId, ["text"], { head_lines: 10 });

      const jxaCode = executeFn.mock.calls[0]![0] as string;
      expect(jxaCode).toContain("slice(0, 10)");
    });

    it("should not include truncation code when no options", async () => {
      const refId = store.create("TestApp", "session", {
        type: "element",
        element: "session",
        index: 0,
        container: "application",
      });

      executeFn.mockResolvedValue(jxaResult({ text: "value" }));

      await executor.getProperties(refId, ["text"]);

      const jxaCode = executeFn.mock.calls[0]![0] as string;
      // Should not contain line splitting/slicing for truncation
      expect(jxaCode).not.toContain("lines.slice");
    });

    it("should pass options through getPropertiesBatch", async () => {
      const refId = store.create("TestApp", "session", {
        type: "element",
        element: "session",
        index: 0,
        container: "application",
      });

      executeFn.mockResolvedValue(
        jxaResult([{ idx: 0, props: { text: "value" } }])
      );

      await executor.getPropertiesBatch([refId], ["text"], { tail_lines: 25 });

      const jxaCode = executeFn.mock.calls[0]![0] as string;
      expect(jxaCode).toContain("slice(-25)");
    });

    it("should pass options through getElementsWithProperties", async () => {
      const refId = store.create("TestApp", "window", {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      });

      executeFn.mockResolvedValue(
        jxaResult({ count: 1, items: [{ index: 0, props: { text: "value" } }] })
      );

      await executor.getElementsWithProperties(
        refId, "tab", ["text"], undefined, 100, { head_lines: 30 }
      );

      const jxaCode = executeFn.mock.calls[0]![0] as string;
      expect(jxaCode).toContain("slice(0, 30)");
    });
  });
});
