/**
 * Unit Tests for ReferenceStore
 *
 * Following TDD: These tests are written BEFORE the implementation.
 * They define the expected behavior of the ReferenceStore class.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ReferenceStore } from "../../../src/execution/reference-store.js";
import type { ObjectSpecifier } from "../../../src/types/object-specifier.js";

describe("ReferenceStore", () => {
  let store: ReferenceStore;

  beforeEach(() => {
    // Fresh store for each test
    store = new ReferenceStore();
  });

  afterEach(() => {
    // Stop cleanup timer to avoid test interference
    store.stopCleanup();
  });

  describe("ID Generation", () => {
    it("should generate unique IDs with ref_ prefix", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);

      expect(id).toMatch(/^ref_[a-z0-9]+$/);
    });

    it("should generate different IDs for multiple create calls", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id1 = store.create("com.apple.finder", "window", specifier);
      const id2 = store.create("com.apple.finder", "window", specifier);
      const id3 = store.create("com.apple.finder", "window", specifier);

      expect(id1).not.toBe(id2);
      expect(id1).not.toBe(id3);
      expect(id2).not.toBe(id3);
    });
  });

  describe("Storage and Retrieval", () => {
    it("should retrieve reference by ID", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect(ref?.id).toBe(id);
      expect(ref?.app).toBe("com.apple.finder");
      expect(ref?.type).toBe("window");
      expect(ref?.specifier).toEqual(specifier);
    });

    it("should return undefined for non-existent ID", () => {
      const ref = store.get("ref_nonexistent");
      expect(ref).toBeUndefined();
    });

    it("should store reference with correct app, type, and specifier", () => {
      const specifier: ObjectSpecifier = {
        type: "named",
        element: "document",
        name: "README.md",
        container: "application",
      };

      const id = store.create("com.apple.textedit", "document", specifier);
      const ref = store.get(id);

      expect(ref?.app).toBe("com.apple.textedit");
      expect(ref?.type).toBe("document");
      expect(ref?.specifier).toEqual(specifier);
    });

    it("should set createdAt and lastAccessedAt to current time", () => {
      const now = Date.now();
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);
      const ref = store.get(id);

      expect(ref?.createdAt).toBeGreaterThanOrEqual(now);
      expect(ref?.createdAt).toBeLessThanOrEqual(Date.now());
      expect(ref?.lastAccessedAt).toBeGreaterThanOrEqual(now);
      expect(ref?.lastAccessedAt).toBeLessThanOrEqual(Date.now());
    });
  });

  describe("Touch Functionality", () => {
    it("should update lastAccessedAt when touched", async () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);
      const ref1 = store.get(id);
      const originalLastAccessed = ref1?.lastAccessedAt;

      // Wait a bit to ensure timestamp difference
      await new Promise((resolve) => setTimeout(resolve, 10));

      store.touch(id);
      const ref2 = store.get(id);

      expect(ref2?.lastAccessedAt).toBeGreaterThan(originalLastAccessed!);
    });

    it("should not throw error when touching non-existent ID", () => {
      expect(() => {
        store.touch("ref_nonexistent");
      }).not.toThrow();
    });

    it("should not change createdAt when touched", async () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);
      const ref1 = store.get(id);
      const originalCreatedAt = ref1?.createdAt;

      await new Promise((resolve) => setTimeout(resolve, 10));

      store.touch(id);
      const ref2 = store.get(id);

      expect(ref2?.createdAt).toBe(originalCreatedAt);
    });
  });

  describe("TTL Cleanup", () => {
    it("should remove expired references based on TTL", () => {
      // Use a short TTL for testing (100ms)
      const shortTtlStore = new ReferenceStore(100);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = shortTtlStore.create("com.apple.finder", "window", specifier);
      expect(shortTtlStore.get(id)).toBeDefined();

      // Mock time passing by 150ms (beyond TTL)
      const originalNow = Date.now;
      const baseTime = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(baseTime + 150);

      shortTtlStore.cleanup();

      expect(shortTtlStore.get(id)).toBeUndefined();

      // Restore Date.now
      vi.mocked(Date.now).mockRestore();
      shortTtlStore.stopCleanup();
    });

    it("should keep non-expired references", () => {
      // Use longer TTL (1 second)
      const longTtlStore = new ReferenceStore(1000);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = longTtlStore.create("com.apple.finder", "window", specifier);

      // Mock time passing by 500ms (within TTL)
      const originalNow = Date.now;
      const baseTime = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(baseTime + 500);

      longTtlStore.cleanup();

      expect(longTtlStore.get(id)).toBeDefined();

      vi.mocked(Date.now).mockRestore();
      longTtlStore.stopCleanup();
    });

    it("should run automatic cleanup every 5 minutes", async () => {
      // Use fake timers to test automatic cleanup
      vi.useFakeTimers();

      const shortTtlStore = new ReferenceStore(100); // 100ms TTL
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      // Create a reference
      const id = shortTtlStore.create("com.apple.finder", "window", specifier);
      expect(shortTtlStore.get(id)).toBeDefined();

      // Advance time by 150ms (beyond TTL)
      vi.advanceTimersByTime(150);

      // Reference should still exist (no automatic cleanup yet)
      expect(shortTtlStore.get(id)).toBeDefined();

      // Advance time by 5 minutes (cleanup interval)
      vi.advanceTimersByTime(5 * 60 * 1000);

      // Now cleanup should have run and removed the expired reference
      expect(shortTtlStore.get(id)).toBeUndefined();

      shortTtlStore.stopCleanup();
      vi.useRealTimers();
    });

    it("should stop automatic cleanup when stopCleanup is called", () => {
      const testStore = new ReferenceStore();

      // Verify timer is running
      expect(testStore["cleanupInterval"]).not.toBeNull();

      testStore.stopCleanup();

      // Verify timer is stopped
      expect(testStore["cleanupInterval"]).toBeNull();
    });
  });

  describe("Statistics", () => {
    it("should return correct totalReferences count", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      store.create("com.apple.finder", "window", specifier);
      store.create("com.apple.finder", "window", specifier);
      store.create("com.apple.safari", "window", specifier);

      const stats = store.getStats();
      expect(stats.totalReferences).toBe(3);
    });

    it("should track per-app references correctly", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      store.create("com.apple.finder", "window", specifier);
      store.create("com.apple.finder", "window", specifier);
      store.create("com.apple.safari", "window", specifier);
      store.create("com.apple.safari", "tab", specifier);
      store.create("com.apple.mail", "message", specifier);

      const stats = store.getStats();
      expect(stats.referencesPerApp).toEqual({
        "com.apple.finder": 2,
        "com.apple.safari": 2,
        "com.apple.mail": 1,
      });
    });

    it("should report oldest and newest timestamps", async () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const time1 = Date.now();
      store.create("com.apple.finder", "window", specifier);

      await new Promise((resolve) => setTimeout(resolve, 10));

      const time2 = Date.now();
      store.create("com.apple.safari", "window", specifier);

      await new Promise((resolve) => setTimeout(resolve, 10));

      const time3 = Date.now();
      store.create("com.apple.mail", "message", specifier);

      const stats = store.getStats();

      expect(stats.oldestReference).toBeGreaterThanOrEqual(time1);
      expect(stats.oldestReference).toBeLessThan(time2);
      expect(stats.newestReference).toBeGreaterThanOrEqual(time3);
    });

    it("should handle empty store in getStats", () => {
      const stats = store.getStats();

      expect(stats.totalReferences).toBe(0);
      expect(stats.referencesPerApp).toEqual({});
      expect(stats.oldestReference).toBe(Date.now()); // Current time when no refs
      expect(stats.newestReference).toBe(0);
    });
  });

  describe("Clear", () => {
    it("should remove all references", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id1 = store.create("com.apple.finder", "window", specifier);
      const id2 = store.create("com.apple.safari", "window", specifier);
      const id3 = store.create("com.apple.mail", "message", specifier);

      expect(store.get(id1)).toBeDefined();
      expect(store.get(id2)).toBeDefined();
      expect(store.get(id3)).toBeDefined();

      store.clear();

      expect(store.get(id1)).toBeUndefined();
      expect(store.get(id2)).toBeUndefined();
      expect(store.get(id3)).toBeUndefined();
    });

    it("should show zero references in getStats after clear", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      store.create("com.apple.finder", "window", specifier);
      store.create("com.apple.safari", "window", specifier);

      expect(store.getStats().totalReferences).toBe(2);

      store.clear();

      const stats = store.getStats();
      expect(stats.totalReferences).toBe(0);
      expect(stats.referencesPerApp).toEqual({});
    });
  });

  describe("Memory Safety", () => {
    it("should handle many references without memory issues", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      // Create 1000 references
      const ids: string[] = [];
      for (let i = 0; i < 1000; i++) {
        const id = store.create("com.apple.finder", "window", specifier);
        ids.push(id);
      }

      // Verify all are retrievable
      expect(store.getStats().totalReferences).toBe(1000);

      for (const id of ids) {
        expect(store.get(id)).toBeDefined();
      }

      // Verify cleanup works with many references
      store.clear();
      expect(store.getStats().totalReferences).toBe(0);
    });

    it("should properly remove old references during cleanup with many refs", () => {
      const shortTtlStore = new ReferenceStore(100);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      // Create 100 references
      for (let i = 0; i < 100; i++) {
        shortTtlStore.create("com.apple.finder", "window", specifier);
      }

      expect(shortTtlStore.getStats().totalReferences).toBe(100);

      // Mock time passing beyond TTL
      const baseTime = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(baseTime + 150);

      shortTtlStore.cleanup();

      expect(shortTtlStore.getStats().totalReferences).toBe(0);

      vi.mocked(Date.now).mockRestore();
      shortTtlStore.stopCleanup();
    });
  });
});
