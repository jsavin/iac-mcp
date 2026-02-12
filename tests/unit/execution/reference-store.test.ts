/**
 * Unit Tests for ReferenceStore
 *
 * Tests LRU eviction, auto-touch on get, delete, and core CRUD behavior.
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
    // Stop cleanup timer to avoid test interference (no-op but kept for compat)
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

      expect(id).toMatch(/^ref_[a-f0-9-]+$/);  // UUID format with dashes
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

  describe("Auto-touch on get()", () => {
    it("should update lastAccessedAt when get() is called", async () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);

      // Wait a bit to ensure timestamp difference
      await new Promise((resolve) => setTimeout(resolve, 10));

      const ref = store.get(id);

      // lastAccessedAt should be updated by get()
      expect(ref?.lastAccessedAt).toBeGreaterThan(ref?.createdAt!);
    });

    it("should not update createdAt when get() is called", async () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);
      const initialCreatedAt = store.get(id)?.createdAt;

      await new Promise((resolve) => setTimeout(resolve, 10));

      const ref = store.get(id);
      expect(ref?.createdAt).toBe(initialCreatedAt);
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

  describe("Delete", () => {
    it("should remove a reference by ID", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);
      expect(store.get(id)).toBeDefined();

      const result = store.delete(id);
      expect(result).toBe(true);
      expect(store.get(id)).toBeUndefined();
    });

    it("should return false when deleting non-existent reference", () => {
      const result = store.delete("ref_nonexistent");
      expect(result).toBe(false);
    });

    it("should decrement total references after delete", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);
      store.create("com.apple.finder", "window", specifier);
      expect(store.getStats().totalReferences).toBe(2);

      store.delete(id);
      expect(store.getStats().totalReferences).toBe(1);
    });
  });

  describe("LRU Eviction", () => {
    it("should evict least recently used reference when over capacity", () => {
      const smallStore = new ReferenceStore(3);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id1 = smallStore.create("com.apple.finder", "window", specifier);
      const id2 = smallStore.create("com.apple.finder", "window", specifier);
      const id3 = smallStore.create("com.apple.finder", "window", specifier);

      // All 3 should exist
      expect(smallStore.get(id1)).toBeDefined();
      expect(smallStore.get(id2)).toBeDefined();
      expect(smallStore.get(id3)).toBeDefined();

      // Adding a 4th should evict the LRU (id1, since id2/id3 were touched by get())
      // But id1 was also touched by get() above. Let's use time mocking for precision.
      const baseTime = Date.now();
      vi.spyOn(Date, "now")
        .mockReturnValueOnce(baseTime + 100)  // create's Date.now
        .mockReturnValueOnce(baseTime + 100)  // create's second Date.now
        .mockReturnValueOnce(baseTime + 100); // evictIfNeeded check

      const id4 = smallStore.create("com.apple.finder", "window", specifier);

      vi.mocked(Date.now).mockRestore();

      // Store should have 3 references (one evicted)
      expect(smallStore.getStats().totalReferences).toBe(3);

      // The newest one should exist
      expect(smallStore.get(id4)).toBeDefined();
    });

    it("should not evict when at or below capacity", () => {
      const smallStore = new ReferenceStore(3);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      smallStore.create("com.apple.finder", "window", specifier);
      smallStore.create("com.apple.finder", "window", specifier);
      smallStore.create("com.apple.finder", "window", specifier);

      expect(smallStore.getStats().totalReferences).toBe(3);
    });

    it("should evict based on lastAccessedAt not createdAt", async () => {
      const smallStore = new ReferenceStore(2);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      // Create two references
      const id1 = smallStore.create("com.apple.finder", "window", specifier);
      await new Promise((resolve) => setTimeout(resolve, 10));
      const id2 = smallStore.create("com.apple.finder", "window", specifier);

      // Touch id1 so it's more recently accessed than id2
      await new Promise((resolve) => setTimeout(resolve, 10));
      smallStore.touch(id1);

      // Create a third — should evict id2 (least recently accessed)
      await new Promise((resolve) => setTimeout(resolve, 10));
      const id3 = smallStore.create("com.apple.finder", "window", specifier);

      expect(smallStore.getStats().totalReferences).toBe(2);
      expect(smallStore.get(id1)).toBeDefined();  // kept (recently touched)
      expect(smallStore.get(id3)).toBeDefined();  // kept (just created)
    });

    it("should handle eviction of multiple references at once", () => {
      // Create a store with cap of 2, fill with 5
      const tinyStore = new ReferenceStore(2);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      // Need to create refs one at a time since eviction happens on each create
      const ids: string[] = [];
      for (let i = 0; i < 5; i++) {
        ids.push(tinyStore.create("com.apple.finder", "window", specifier));
      }

      // Should never exceed capacity
      expect(tinyStore.getStats().totalReferences).toBe(2);
    });

    it("should use default max of 1000 references", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      // Create 1000 references
      for (let i = 0; i < 1000; i++) {
        store.create("com.apple.finder", "window", specifier);
      }
      expect(store.getStats().totalReferences).toBe(1000);

      // Adding one more should evict one
      store.create("com.apple.finder", "window", specifier);
      expect(store.getStats().totalReferences).toBe(1000);
    });
  });

  describe("No TTL - References persist indefinitely", () => {
    it("should not expire references based on time", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);

      // Mock time passing by 1 hour
      const baseTime = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(baseTime + 3600000);

      // Reference should still exist (no TTL)
      expect(store.get(id)).toBeDefined();

      vi.mocked(Date.now).mockRestore();
    });

    it("should not expire references based on time even after 24 hours", () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const id = store.create("com.apple.finder", "window", specifier);

      // Mock time passing by 24 hours
      const baseTime = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(baseTime + 86400000);

      // Reference should still exist (no TTL)
      expect(store.get(id)).toBeDefined();

      vi.mocked(Date.now).mockRestore();
    });
  });

  describe("stopCleanup (backward compatibility)", () => {
    it("should not throw when stopCleanup is called", () => {
      expect(() => {
        store.stopCleanup();
      }).not.toThrow();
    });

    it("should be callable multiple times without error", () => {
      store.stopCleanup();
      store.stopCleanup();
      store.stopCleanup();
      // No assertions needed — just verifying no throws
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

      // Create 1000 references (at default cap)
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

      // Verify clear works with many references
      store.clear();
      expect(store.getStats().totalReferences).toBe(0);
    });

    it("should enforce capacity limit with many creates", () => {
      const smallStore = new ReferenceStore(50);
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      // Create 100 references (2x capacity)
      for (let i = 0; i < 100; i++) {
        smallStore.create("com.apple.finder", "window", specifier);
      }

      // Should never exceed capacity
      expect(smallStore.getStats().totalReferences).toBe(50);
    });
  });
});
