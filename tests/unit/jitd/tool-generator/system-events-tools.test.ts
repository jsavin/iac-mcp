import { describe, it, expect, beforeEach } from "vitest";
import { generateSystemEventsTools } from "../../../../src/jitd/tool-generator/system-events-tools.js";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("generateSystemEventsTools", () => {
  describe("Function Returns 6 Tools", () => {
    it("should return an array of 6 tools", () => {
      const tools = generateSystemEventsTools();
      expect(tools).toBeInstanceOf(Array);
      expect(tools).toHaveLength(6);
    });

    it("should return tools with name, description, and inputSchema", () => {
      const tools = generateSystemEventsTools();
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

  describe("Tool 1: activate_app", () => {
    let tool: Tool;

    beforeEach(() => {
      const tools = generateSystemEventsTools();
      tool = tools.find((t) => t.name === "iac_mcp_activate_app")!;
    });

    it("should have correct name", () => {
      expect(tool.name).toBe("iac_mcp_activate_app");
    });

    it("should have a non-empty description", () => {
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it("should have inputSchema with type object", () => {
      const schema = tool.inputSchema as any;
      expect(schema.type).toBe("object");
    });

    it("should require only app", () => {
      const schema = tool.inputSchema as any;
      expect(schema.required).toEqual(["app"]);
    });

    it("should define app as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.app.type).toBe("string");
      expect(schema.properties.app.description).toBeTruthy();
    });
  });

  describe("Tool 2: ui_snapshot", () => {
    let tool: Tool;

    beforeEach(() => {
      const tools = generateSystemEventsTools();
      tool = tools.find((t) => t.name === "iac_mcp_ui_snapshot")!;
    });

    it("should have correct name", () => {
      expect(tool.name).toBe("iac_mcp_ui_snapshot");
    });

    it("should have a non-empty description", () => {
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it("should have inputSchema with type object", () => {
      const schema = tool.inputSchema as any;
      expect(schema.type).toBe("object");
    });

    it("should require only app", () => {
      const schema = tool.inputSchema as any;
      expect(schema.required).toEqual(["app"]);
    });

    it("should define app as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.app.type).toBe("string");
      expect(schema.properties.app.description).toBeTruthy();
    });

    it("should define max_depth as number type with default", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.max_depth.type).toBe("number");
      expect(schema.properties.max_depth.default).toBe(2);
      expect(schema.properties.max_depth.description).toBeTruthy();
    });
  });

  describe("Tool 3: click_menu", () => {
    let tool: Tool;

    beforeEach(() => {
      const tools = generateSystemEventsTools();
      tool = tools.find((t) => t.name === "iac_mcp_click_menu")!;
    });

    it("should have correct name", () => {
      expect(tool.name).toBe("iac_mcp_click_menu");
    });

    it("should have a non-empty description", () => {
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it("should have inputSchema with type object", () => {
      const schema = tool.inputSchema as any;
      expect(schema.type).toBe("object");
    });

    it("should require app and menu_path", () => {
      const schema = tool.inputSchema as any;
      expect(schema.required).toEqual(
        expect.arrayContaining(["app", "menu_path"])
      );
      expect(schema.required).toHaveLength(2);
    });

    it("should define app as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.app.type).toBe("string");
      expect(schema.properties.app.description).toBeTruthy();
    });

    it("should define menu_path as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.menu_path.type).toBe("string");
      expect(schema.properties.menu_path.description).toBeTruthy();
    });
  });

  describe("Tool 4: send_keystroke", () => {
    let tool: Tool;

    beforeEach(() => {
      const tools = generateSystemEventsTools();
      tool = tools.find((t) => t.name === "iac_mcp_send_keystroke")!;
    });

    it("should have correct name", () => {
      expect(tool.name).toBe("iac_mcp_send_keystroke");
    });

    it("should have a non-empty description", () => {
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it("should have inputSchema with type object", () => {
      const schema = tool.inputSchema as any;
      expect(schema.type).toBe("object");
    });

    it("should require app and key", () => {
      const schema = tool.inputSchema as any;
      expect(schema.required).toEqual(
        expect.arrayContaining(["app", "key"])
      );
      expect(schema.required).toHaveLength(2);
    });

    it("should define app as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.app.type).toBe("string");
      expect(schema.properties.app.description).toBeTruthy();
    });

    it("should define key as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.key.type).toBe("string");
      expect(schema.properties.key.description).toBeTruthy();
    });

    it("should define modifiers as array of strings", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.modifiers.type).toBe("array");
      expect(schema.properties.modifiers.items.type).toBe("string");
      expect(schema.properties.modifiers.description).toBeTruthy();
    });
  });

  describe("Tool 5: click_element", () => {
    let tool: Tool;

    beforeEach(() => {
      const tools = generateSystemEventsTools();
      tool = tools.find((t) => t.name === "iac_mcp_click_element")!;
    });

    it("should have correct name", () => {
      expect(tool.name).toBe("iac_mcp_click_element");
    });

    it("should have a non-empty description", () => {
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it("should have inputSchema with type object", () => {
      const schema = tool.inputSchema as any;
      expect(schema.type).toBe("object");
    });

    it("should require only ref", () => {
      const schema = tool.inputSchema as any;
      expect(schema.required).toEqual(["ref"]);
    });

    it("should define ref as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.ref.type).toBe("string");
      expect(schema.properties.ref.description).toBeTruthy();
    });
  });

  describe("Tool 6: set_value", () => {
    let tool: Tool;

    beforeEach(() => {
      const tools = generateSystemEventsTools();
      tool = tools.find((t) => t.name === "iac_mcp_set_value")!;
    });

    it("should have correct name", () => {
      expect(tool.name).toBe("iac_mcp_set_value");
    });

    it("should have a non-empty description", () => {
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it("should have inputSchema with type object", () => {
      const schema = tool.inputSchema as any;
      expect(schema.type).toBe("object");
    });

    it("should require ref and value", () => {
      const schema = tool.inputSchema as any;
      expect(schema.required).toEqual(
        expect.arrayContaining(["ref", "value"])
      );
      expect(schema.required).toHaveLength(2);
    });

    it("should define ref as string type", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.ref.type).toBe("string");
      expect(schema.properties.ref.description).toBeTruthy();
    });

    it("should define value without a type to accept any JSON value", () => {
      const schema = tool.inputSchema as any;
      expect(schema.properties.value.type).toBeUndefined();
      expect(schema.properties.value.description).toBeTruthy();
    });
  });

  describe("Schema Validity", () => {
    it("should have valid JSON Schema for all tools", () => {
      const tools = generateSystemEventsTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        expect(schema.type).toBe("object");
        expect(schema.properties).toBeDefined();
        expect(typeof schema.properties).toBe("object");
      });
    });

    it("should have required fields in the required array", () => {
      const tools = generateSystemEventsTools();
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
      const tools = generateSystemEventsTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        Object.entries(schema.properties).forEach(([key, prop]: [string, any]) => {
          if (key === "value") {
            expect(prop.description).toBeDefined();
          } else {
            expect(prop.type).toBeDefined();
          }
        });
      });
    });
  });

  describe("Consistency", () => {
    it("should have all tool names start with iac_mcp_", () => {
      const tools = generateSystemEventsTools();
      tools.forEach((tool) => {
        expect(tool.name).toMatch(/^iac_mcp_/);
      });
    });

    it("should have clear and helpful descriptions", () => {
      const tools = generateSystemEventsTools();
      tools.forEach((tool) => {
        expect(tool.description.length).toBeGreaterThan(20);
        expect(tool.description).not.toMatch(/TODO|FIXME|XXX/);
      });
    });

    it("should follow consistent schema structure", () => {
      const tools = generateSystemEventsTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        expect(schema.type).toBe("object");
        expect(schema.properties).toBeDefined();
      });
    });

    it("should have descriptions for all properties", () => {
      const tools = generateSystemEventsTools();
      tools.forEach((tool) => {
        const schema = tool.inputSchema as any;
        Object.entries(schema.properties).forEach(([_key, prop]: [string, any]) => {
          expect(prop.description).toBeTruthy();
        });
      });
    });
  });
});
