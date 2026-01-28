import { describe, it, expect } from "vitest";
import {
  type ObjectReference,
  type ReferenceStats,
} from "../../../src/types/object-reference.js";
import type { ElementSpecifier } from "../../../src/types/object-specifier.js";

describe("ObjectReference Interface", () => {
  describe("Structure Validation", () => {
    it("should create valid ObjectReference with required fields", () => {
      const specifier: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const ref: ObjectReference = {
        id: "ref_abc123",
        app: "com.apple.finder",
        type: "window",
        specifier: specifier,
        createdAt: Date.now(),
        lastAccessedAt: Date.now(),
      };

      expect(ref.id).toBe("ref_abc123");
      expect(ref.app).toBe("com.apple.finder");
      expect(ref.type).toBe("window");
      expect(ref.specifier).toEqual(specifier);
      expect(typeof ref.createdAt).toBe("number");
      expect(typeof ref.lastAccessedAt).toBe("number");
    });

    it("should create valid ObjectReference with optional metadata", () => {
      const specifier: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const ref: ObjectReference = {
        id: "ref_xyz789",
        app: "com.apple.safari",
        type: "window",
        specifier: specifier,
        createdAt: Date.now(),
        lastAccessedAt: Date.now(),
        metadata: {
          title: "Example Page",
          url: "https://example.com",
        },
      };

      expect(ref.metadata).toBeDefined();
      expect(ref.metadata?.title).toBe("Example Page");
      expect(ref.metadata?.url).toBe("https://example.com");
    });

    it("should create valid ObjectReference without metadata", () => {
      const specifier: ElementSpecifier = {
        type: "element",
        element: "document",
        index: 1,
        container: "application",
      };

      const ref: ObjectReference = {
        id: "ref_no_metadata",
        app: "com.apple.TextEdit",
        type: "document",
        specifier: specifier,
        createdAt: Date.now(),
        lastAccessedAt: Date.now(),
      };

      expect(ref.metadata).toBeUndefined();
    });

    it("should handle various metadata types", () => {
      const specifier: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const ref: ObjectReference = {
        id: "ref_meta_test",
        app: "com.example.app",
        type: "window",
        specifier: specifier,
        createdAt: Date.now(),
        lastAccessedAt: Date.now(),
        metadata: {
          stringValue: "test",
          numberValue: 42,
          booleanValue: true,
          arrayValue: [1, 2, 3],
          nestedObject: { key: "value" },
        },
      };

      expect(ref.metadata?.stringValue).toBe("test");
      expect(ref.metadata?.numberValue).toBe(42);
      expect(ref.metadata?.booleanValue).toBe(true);
      expect(ref.metadata?.arrayValue).toEqual([1, 2, 3]);
      expect(ref.metadata?.nestedObject).toEqual({ key: "value" });
    });

    it("should validate timestamp fields are numbers", () => {
      const specifier: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };

      const now = Date.now();
      const ref: ObjectReference = {
        id: "ref_timestamp_test",
        app: "com.example.app",
        type: "window",
        specifier: specifier,
        createdAt: now,
        lastAccessedAt: now + 1000,
      };

      expect(typeof ref.createdAt).toBe("number");
      expect(typeof ref.lastAccessedAt).toBe("number");
      expect(ref.lastAccessedAt).toBeGreaterThan(ref.createdAt);
    });
  });
});

describe("ReferenceStats Interface", () => {
  describe("Structure Validation", () => {
    it("should create valid ReferenceStats with required fields", () => {
      const stats: ReferenceStats = {
        totalReferences: 10,
        referencesPerApp: {
          "com.apple.finder": 5,
          "com.apple.safari": 3,
          "com.apple.mail": 2,
        },
        oldestReference: Date.now() - 3600000, // 1 hour ago
        newestReference: Date.now(),
      };

      expect(stats.totalReferences).toBe(10);
      expect(Object.keys(stats.referencesPerApp).length).toBe(3);
      expect(stats.referencesPerApp["com.apple.finder"]).toBe(5);
      expect(typeof stats.oldestReference).toBe("number");
      expect(typeof stats.newestReference).toBe("number");
    });

    it("should handle empty referencesPerApp", () => {
      const stats: ReferenceStats = {
        totalReferences: 0,
        referencesPerApp: {},
        oldestReference: Date.now(),
        newestReference: Date.now(),
      };

      expect(stats.totalReferences).toBe(0);
      expect(Object.keys(stats.referencesPerApp).length).toBe(0);
    });

    it("should validate timestamp ordering", () => {
      const older = Date.now() - 7200000; // 2 hours ago
      const newer = Date.now();

      const stats: ReferenceStats = {
        totalReferences: 5,
        referencesPerApp: {
          "com.apple.finder": 5,
        },
        oldestReference: older,
        newestReference: newer,
      };

      expect(stats.oldestReference).toBeLessThan(stats.newestReference);
    });

    it("should handle single reference scenario", () => {
      const timestamp = Date.now();

      const stats: ReferenceStats = {
        totalReferences: 1,
        referencesPerApp: {
          "com.apple.finder": 1,
        },
        oldestReference: timestamp,
        newestReference: timestamp,
      };

      expect(stats.oldestReference).toBe(stats.newestReference);
      expect(stats.totalReferences).toBe(1);
    });

    it("should handle multiple apps with varying counts", () => {
      const stats: ReferenceStats = {
        totalReferences: 100,
        referencesPerApp: {
          "com.apple.finder": 50,
          "com.apple.safari": 30,
          "com.apple.mail": 15,
          "com.apple.calendar": 5,
        },
        oldestReference: Date.now() - 86400000, // 24 hours ago
        newestReference: Date.now(),
      };

      const totalFromApps = Object.values(stats.referencesPerApp).reduce(
        (sum, count) => sum + count,
        0
      );
      expect(totalFromApps).toBe(stats.totalReferences);
    });
  });
});

describe("ObjectReference and ReferenceStats Integration", () => {
  it("should match reference structure expectations with stats", () => {
    const specifier: ElementSpecifier = {
      type: "element",
      element: "window",
      index: 0,
      container: "application",
    };

    const refs: ObjectReference[] = [
      {
        id: "ref_1",
        app: "com.apple.finder",
        type: "window",
        specifier: specifier,
        createdAt: Date.now() - 3600000,
        lastAccessedAt: Date.now(),
      },
      {
        id: "ref_2",
        app: "com.apple.finder",
        type: "window",
        specifier: specifier,
        createdAt: Date.now() - 1800000,
        lastAccessedAt: Date.now(),
      },
      {
        id: "ref_3",
        app: "com.apple.safari",
        type: "window",
        specifier: specifier,
        createdAt: Date.now(),
        lastAccessedAt: Date.now(),
      },
    ];

    const stats: ReferenceStats = {
      totalReferences: refs.length,
      referencesPerApp: {
        "com.apple.finder": 2,
        "com.apple.safari": 1,
      },
      oldestReference: Math.min(...refs.map((r) => r.createdAt)),
      newestReference: Math.max(...refs.map((r) => r.createdAt)),
    };

    expect(stats.totalReferences).toBe(3);
    expect(stats.referencesPerApp["com.apple.finder"]).toBe(2);
    expect(stats.referencesPerApp["com.apple.safari"]).toBe(1);
  });
});
