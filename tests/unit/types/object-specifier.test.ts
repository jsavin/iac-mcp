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

  describe("Unicode Characters in Specifiers", () => {
    describe("NamedSpecifier with Unicode names", () => {
      it("should accept Chinese characters in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "folder",
          name: "\u4E2D\u6587\u6587\u4EF6\u5939", // Chinese folder name
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept Japanese characters in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "document",
          name: "\u65E5\u672C\u8A9E\u30C9\u30AD\u30E5\u30E1\u30F3\u30C8", // Japanese document name
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept Cyrillic characters in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "file",
          name: "\u0420\u0443\u0441\u0441\u043A\u0438\u0439\u0444\u0430\u0439\u043B", // Russian file name
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept Arabic characters in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "folder",
          name: "\u0645\u0644\u0641\u0639\u0631\u0628\u064A", // Arabic folder name
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept emoji in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "folder",
          name: "My Folder \u{1F4C1}\u{1F4DD}", // folder and memo emoji
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept mixed Unicode and ASCII in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "document",
          name: "Report_2024_\u65E5\u672C\u8A9E_final",
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });
    });

    describe("IdSpecifier with Unicode IDs", () => {
      it("should accept Unicode characters in id", () => {
        const spec: IdSpecifier = {
          type: "id",
          element: "message",
          id: "msg-\u4E2D\u6587-123",
          container: "application",
        };
        expect(isIdSpecifier(spec)).toBe(true);
      });

      it("should accept emoji in id", () => {
        const spec: IdSpecifier = {
          type: "id",
          element: "item",
          id: "item-\u{1F600}-001",
          container: "application",
        };
        expect(isIdSpecifier(spec)).toBe(true);
      });
    });

    describe("ElementSpecifier with Unicode element names", () => {
      it("should accept Unicode in element name (type guard only)", () => {
        const spec: ElementSpecifier = {
          type: "element",
          element: "\u30A6\u30A3\u30F3\u30C9\u30A6", // Japanese "window"
          index: 0,
          container: "application",
        };
        expect(isElementSpecifier(spec)).toBe(true);
      });
    });

    describe("PropertySpecifier with Unicode property names", () => {
      it("should accept Unicode in property name", () => {
        const spec: PropertySpecifier = {
          type: "property",
          property: "\u540D\u524D", // Japanese "name"
          of: "ref_123",
        };
        expect(isPropertySpecifier(spec)).toBe(true);
      });
    });

    describe("Special Unicode Edge Cases", () => {
      it("should accept zero-width characters in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "file",
          name: "file\u200B\u200Cname", // zero-width space and non-joiner
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept combining diacritical marks in name", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "document",
          name: "cafe\u0301", // e + combining acute accent
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept right-to-left override characters", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "file",
          name: "\u202Ereversed\u202C",
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });

      it("should accept surrogate pairs (emoji)", () => {
        const spec: NamedSpecifier = {
          type: "named",
          element: "folder",
          name: "\u{1F1FA}\u{1F1F8}", // US flag emoji (surrogate pair)
          container: "application",
        };
        expect(isNamedSpecifier(spec)).toBe(true);
      });
    });
  });

  describe("Special Characters and Control Characters", () => {
    it("should accept newline characters in name", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "document",
        name: "line1\nline2",
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });

    it("should accept tab characters in name", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "document",
        name: "col1\tcol2",
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });

    it("should accept null byte in name (type guard only)", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "file",
        name: "file\x00name",
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });

    it("should accept carriage return in name", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "document",
        name: "line1\r\nline2",
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });
  });

  describe("Very Long Strings", () => {
    it("should accept very long element name", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "a".repeat(10000),
        index: 0,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should accept very long name in NamedSpecifier", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "mailbox",
        name: "x".repeat(50000),
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });

    it("should accept very long id", () => {
      const spec: IdSpecifier = {
        type: "id",
        element: "message",
        id: "id-" + "0123456789".repeat(1000),
        container: "application",
      };
      expect(isIdSpecifier(spec)).toBe(true);
    });
  });

  describe("Empty and Whitespace Strings", () => {
    it("should accept empty element name", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "",
        index: 0,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should accept empty name in NamedSpecifier", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "mailbox",
        name: "",
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });

    it("should accept empty id", () => {
      const spec: IdSpecifier = {
        type: "id",
        element: "message",
        id: "",
        container: "application",
      };
      expect(isIdSpecifier(spec)).toBe(true);
    });

    it("should accept whitespace-only name", () => {
      const spec: NamedSpecifier = {
        type: "named",
        element: "folder",
        name: "   ",
        container: "application",
      };
      expect(isNamedSpecifier(spec)).toBe(true);
    });
  });

  describe("Special Index Values", () => {
    it("should accept zero index", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should accept negative index", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: -1,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should accept MAX_SAFE_INTEGER index", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: Number.MAX_SAFE_INTEGER,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should accept floating point index", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: 1.5,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should accept Infinity as index", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: Infinity,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });

    it("should accept NaN as index (typeof number)", () => {
      const spec: ElementSpecifier = {
        type: "element",
        element: "window",
        index: NaN,
        container: "application",
      };
      expect(isElementSpecifier(spec)).toBe(true);
    });
  });
});
