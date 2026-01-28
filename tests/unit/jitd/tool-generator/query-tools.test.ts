import { describe, it, expect } from "vitest";
import { generateQueryTools } from "../../../../src/jitd/tool-generator/query-tools.js";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("generateQueryTools", () => {
  describe("Function Returns 3 Tools", () => {
    it("should return an array of 3 tools", () => {
      const tools = generateQueryTools();
      expect(tools).toBeInstanceOf(Array);
      expect(tools).toHaveLength(3);
    });

    it("should return tools with name, description, and inputSchema", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        expect(tool).toHaveProperty("name");
        expect(tool).toHaveProperty("description");
        expect(tool).toHaveProperty("inputSchema");
        expect(typeof tool.name).toBe("string");
        expect(typeof tool.description).toBe("string");
        expect(typeof tool.inputSchema).toBe("object");
      });
    });
  });

  describe("Tool 1: query_object", () => {
    let queryObjectTool: Tool;

    beforeEach(() => {
      const tools = generateQueryTools();
      queryObjectTool = tools.find((t) => t.name === "iac_mcp_query_object")!;
    });

    it("should have correct name", () => {
      expect(queryObjectTool.name).toBe("iac_mcp_query_object");
    });

    it("should have description mentioning stable references and 15-minute validity", () => {
      expect(queryObjectTool.description).toContain("stable reference");
      expect(queryObjectTool.description).toContain("15 minutes");
    });

    it("should have inputSchema with app and specifier properties", () => {
      const schema = queryObjectTool.inputSchema as any;
      expect(schema.type).toBe("object");
      expect(schema.properties).toHaveProperty("app");
      expect(schema.properties).toHaveProperty("specifier");
    });

    it("should require both app and specifier", () => {
      const schema = queryObjectTool.inputSchema as any;
      expect(schema.required).toEqual(
        expect.arrayContaining(["app", "specifier"])
      );
      expect(schema.required).toHaveLength(2);
    });

    it("should define app as string type", () => {
      const schema = queryObjectTool.inputSchema as any;
      expect(schema.properties.app.type).toBe("string");
      expect(schema.properties.app.description).toBeTruthy();
    });

    it("should define specifier as object type", () => {
      const schema = queryObjectTool.inputSchema as any;
      expect(schema.properties.specifier.type).toBe("object");
      expect(schema.properties.specifier.description).toBeTruthy();
    });

    it("should have description mentioning specifier types", () => {
      const schema = queryObjectTool.inputSchema as any;
      expect(schema.properties.specifier.description).toContain(
        "ElementSpecifier"
      );
      expect(schema.properties.specifier.description).toContain(
        "NamedSpecifier"
      );
      expect(schema.properties.specifier.description).toContain("IdSpecifier");
      expect(schema.properties.specifier.description).toContain(
        "PropertySpecifier"
      );
    });
  });

  describe("Tool 2: get_properties", () => {
    let getPropertiesTool: Tool;

    beforeEach(() => {
      const tools = generateQueryTools();
      getPropertiesTool = tools.find(
        (t) => t.name === "iac_mcp_get_properties"
      )!;
    });

    it("should have correct name", () => {
      expect(getPropertiesTool.name).toBe("iac_mcp_get_properties");
    });

    it("should have description mentioning getting properties", () => {
      expect(getPropertiesTool.description).toContain("properties");
      expect(getPropertiesTool.description.toLowerCase()).toContain("get");
    });

    it("should have inputSchema with reference and properties properties", () => {
      const schema = getPropertiesTool.inputSchema as any;
      expect(schema.type).toBe("object");
      expect(schema.properties).toHaveProperty("reference");
      expect(schema.properties).toHaveProperty("properties");
    });

    it("should require reference only (properties is optional)", () => {
      const schema = getPropertiesTool.inputSchema as any;
      expect(schema.required).toEqual(["reference"]);
    });

    it("should define reference as string type", () => {
      const schema = getPropertiesTool.inputSchema as any;
      expect(schema.properties.reference.type).toBe("string");
      expect(schema.properties.reference.description).toContain("ref_");
    });

    it("should define properties as array of strings", () => {
      const schema = getPropertiesTool.inputSchema as any;
      expect(schema.properties.properties.type).toBe("array");
      expect(schema.properties.properties.items.type).toBe("string");
    });

    it("should mention returning all properties when omitted", () => {
      const schema = getPropertiesTool.inputSchema as any;
      expect(schema.properties.properties.description).toContain("all");
    });
  });

  describe("Tool 3: get_elements", () => {
    let getElementsTool: Tool;

    beforeEach(() => {
      const tools = generateQueryTools();
      getElementsTool = tools.find((t) => t.name === "iac_mcp_get_elements")!;
    });

    it("should have correct name", () => {
      expect(getElementsTool.name).toBe("iac_mcp_get_elements");
    });

    it("should have description mentioning pagination", () => {
      expect(getElementsTool.description.toLowerCase()).toContain("paginat");
    });

    it("should have inputSchema with container, elementType, and limit properties", () => {
      const schema = getElementsTool.inputSchema as any;
      expect(schema.type).toBe("object");
      expect(schema.properties).toHaveProperty("container");
      expect(schema.properties).toHaveProperty("elementType");
      expect(schema.properties).toHaveProperty("limit");
    });

    it("should require container and elementType (limit is optional)", () => {
      const schema = getElementsTool.inputSchema as any;
      expect(schema.required).toEqual(
        expect.arrayContaining(["container", "elementType"])
      );
      expect(schema.required).toHaveLength(2);
    });

    it("should define container using oneOf (string or object)", () => {
      const schema = getElementsTool.inputSchema as any;
      expect(schema.properties.container.oneOf).toBeDefined();
      expect(schema.properties.container.oneOf).toHaveLength(2);

      const types = schema.properties.container.oneOf.map((s: any) => s.type);
      expect(types).toContain("string");
      expect(types).toContain("object");
    });

    it("should define elementType as string", () => {
      const schema = getElementsTool.inputSchema as any;
      expect(schema.properties.elementType.type).toBe("string");
      expect(schema.properties.elementType.description).toBeTruthy();
    });

    it("should define limit with default value of 100", () => {
      const schema = getElementsTool.inputSchema as any;
      expect(schema.properties.limit.type).toBe("number");
      expect(schema.properties.limit.default).toBe(100);
    });

    it("should mention elements can be used in subsequent calls", () => {
      expect(getElementsTool.description).toContain("subsequent");
    });
  });

  describe("Schema Validity", () => {
    it("should have valid JSON Schema for all tools", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        expect(schema.type).toBe("object");
        expect(schema.properties).toBeDefined();
        expect(typeof schema.properties).toBe("object");
      });
    });

    it("should have required fields in the required array", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        if (schema.required) {
          expect(schema.required).toBeInstanceOf(Array);
          schema.required.forEach((field: string) => {
            expect(schema.properties[field]).toBeDefined();
          });
        }
      });
    });

    it("should have types that match property definitions", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        Object.entries(schema.properties).forEach(([key, prop]: [string, any]) => {
          // Every property should have a type or oneOf
          expect(prop.type || prop.oneOf).toBeDefined();
        });
      });
    });
  });

  describe("Consistency", () => {
    it("should have all tool names start with iac_mcp_", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        expect(tool.name).toMatch(/^iac_mcp_/);
      });
    });

    it("should have clear and helpful descriptions", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        expect(tool.description.length).toBeGreaterThan(20);
        expect(tool.description).not.toMatch(/TODO|FIXME|XXX/);
      });
    });

    it("should follow consistent schema structure", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        expect(schema.type).toBe("object");
        expect(schema.properties).toBeDefined();
      });
    });

    it("should have descriptions for all properties", () => {
      const tools = generateQueryTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        Object.entries(schema.properties).forEach(([key, prop]: [string, any]) => {
          // Handle oneOf case
          if (prop.oneOf) {
            prop.oneOf.forEach((subProp: any) => {
              expect(subProp.description).toBeTruthy();
            });
          } else {
            expect(prop.description).toBeTruthy();
          }
        });
      });
    });
  });
});
