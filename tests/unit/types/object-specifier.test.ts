import { describe, it, expect } from "vitest";
import {
  type ObjectSpecifier,
  type ElementSpecifier,
  type NamedSpecifier,
  type IdSpecifier,
  type PropertySpecifier,
  isElementSpecifier,
  isNamedSpecifier,
  isIdSpecifier,
  isPropertySpecifier,
  isReferenceId,
} from "../../../src/types/object-specifier.js";

describe("ObjectSpecifier Type Guards", () => {
  describe("isElementSpecifier", () => {
    it("should return true for valid element specifier", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should return true for element specifier with nested container", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "document",
        index: 1,
        container: {
          type: "element",
          element: "window",
          index: 0,
          container: "application",
        },
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should return false for non-element specifier", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "window",
        name: "MyWindow",
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(false);
    });

    it("should return false for null", () => {
      expect(isElementSpecifier(null as any)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(isElementSpecifier(undefined as any)).toBe(false);
    });

    it("should return false for object with wrong type field", () => {
      const spec = {
        type: "wrong",
        element: "window",
        index: 0,
        container: "application",
      };
      expect(isElementSpecifier(spec as any)).toBe(false);
    });

    it("should return false for object missing required fields", () => {
      const spec = {
        type: "element",
        element: "window",
      };
      expect(isElementSpecifier(spec as any)).toBe(false);
    });

    it("should return false for non-object values", () => {
      expect(isElementSpecifier("string" as any)).toBe(false);
      expect(isElementSpecifier(123 as any)).toBe(false);
      expect(isElementSpecifier(true as any)).toBe(false);
    });
  });

  describe("isNamedSpecifier", () => {
    it("should return true for valid named specifier", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "window",
        name: "MyWindow",
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });

    it("should return true for named specifier with nested container", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "document",
        name: "MyDoc",
        container: {
          type: "element",
          element: "window",
          index: 0,
          container: "application",
        },
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });

    it("should return false for non-named specifier", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(false);
    });

    it("should return false for null", () => {
      expect(isNamedSpecifier(null as any)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(isNamedSpecifier(undefined as any)).toBe(false);
    });

    it("should return false for object with wrong type field", () => {
      const spec = {
        type: "wrong",
        element: "window",
        name: "MyWindow",
        container: "application",
      };
      expect(isNamedSpecifier(spec as any)).toBe(false);
    });

    it("should return false for object missing required fields", () => {
      const spec = {
        type: "named",
        element: "window",
      };
      expect(isNamedSpecifier(spec as any)).toBe(false);
    });
  });

  describe("isIdSpecifier", () => {
    it("should return true for valid id specifier", () => {
      const spec: IdSpecifier = {
        type: "id",
        element: "window",
        id: "12345",
        container: "application",
      };
      expect(isIdSpecifier(spec)).toBe(true);
    });

    it("should return true for id specifier with nested container", () => {
      const spec: IdSpecifier = {
        type: "id",
        element: "document",
        id: "doc-123",
        container: {
          type: "element",
          element: "window",
          index: 0,
          container: "application",
        },
      };
      expect(isIdSpecifier(spec)).toBe(true);
    });

    it("should return false for non-id specifier", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };
      expect(isIdSpecifier(spec)).toBe(false);
    });

    it("should return false for null", () => {
      expect(isIdSpecifier(null as any)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(isIdSpecifier(undefined as any)).toBe(false);
    });

    it("should return false for object with wrong type field", () => {
      const spec = {
        type: "wrong",
        element: "window",
        id: "12345",
        container: "application",
      };
      expect(isIdSpecifier(spec as any)).toBe(false);
    });

    it("should return false for object missing required fields", () => {
      const spec = {
        type: "id",
        element: "window",
      };
      expect(isIdSpecifier(spec as any)).toBe(false);
    });
  });

  describe("isPropertySpecifier", () => {
    it("should return true for valid property specifier with string 'of'", () => {
      const spec: PropertySpecifier = {
        type: "property",
        property: "name",
        of: "ref_abc123",
      };
      expect(isPropertySpecifier(spec)).toBe(true);
    });

    it("should return true for property specifier with object 'of'", () => {
      const spec: PropertySpecifier = {
        type: "property",
        property: "name",
        of: {
          type: "element",
          element: "window",
          index: 0,
          container: "application",
        },
      };
      expect(isPropertySpecifier(spec)).toBe(true);
    });

    it("should return false for non-property specifier", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };
      expect(isPropertySpecifier(spec)).toBe(false);
    });

    it("should return false for null", () => {
      expect(isPropertySpecifier(null as any)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(isPropertySpecifier(undefined as any)).toBe(false);
    });

    it("should return false for object with wrong type field", () => {
      const spec = {
        type: "wrong",
        property: "name",
        of: "ref_abc123",
      };
      expect(isPropertySpecifier(spec as any)).toBe(false);
    });

    it("should return false for object missing required fields", () => {
      const spec = {
        type: "property",
        property: "name",
      };
      expect(isPropertySpecifier(spec as any)).toBe(false);
    });
  });

  describe("isReferenceId", () => {
    it("should return true for valid reference ID", () => {
      expect(isReferenceId("ref_abc123")).toBe(true);
      expect(isReferenceId("ref_")).toBe(true);
      expect(isReferenceId("ref_1234567890")).toBe(true);
    });

    it("should return false for non-reference strings", () => {
      expect(isReferenceId("abc123")).toBe(false);
      expect(isReferenceId("_ref_abc")).toBe(false);
      expect(isReferenceId("reference_123")).toBe(false);
    });

    it("should return false for empty string", () => {
      expect(isReferenceId("")).toBe(false);
    });

    it("should return false for non-string values", () => {
      expect(isReferenceId(null as any)).toBe(false);
      expect(isReferenceId(undefined as any)).toBe(false);
      expect(isReferenceId(123 as any)).toBe(false);
      expect(isReferenceId({} as any)).toBe(false);
      expect(isReferenceId([] as any)).toBe(false);
    });
  });

  describe("Edge Cases", () => {
    it("should handle deeply nested specifiers", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "item",
        index: 0,
        container: {
          type: "element",
          element: "folder",
          index: 0,
          container: {
            type: "element",
            element: "window",
            index: 0,
            container: "application",
          },
        },
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should handle property specifier with nested object specifier", () => {
      const spec: PropertySpecifier = {
        type: "property",
        property: "name",
        of: {
          type: "element",
          element: "document",
          index: 0,
          container: {
            type: "element",
            element: "window",
            index: 0,
            container: "application",
          },
        },
      };
      expect(isPropertySpecifier(spec)).toBe(true);
    });
  });
});
