import { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Generates MCP tool definitions for stateful object queries.
 * These tools are app-independent and work with any scriptable application.
 *
 * @returns Array of 3 MCP tools: query_object, get_properties, get_elements
 */
export function generateQueryTools(): Tool[] {
  return [
    // Tool 1: query_object - Query an object and get a stable reference
    {
      name: "iac_mcp_query_object",
      description:
        "Query an object in an application and return a stable reference. The reference can be used in subsequent calls to get_properties, get_elements, or set_property. References remain valid for at least 15 minutes.",
      inputSchema: {
        type: "object",
        properties: {
          app: {
            type: "string",
            description: "App bundle ID (e.g., 'com.apple.mail')",
          },
          specifier: {
            type: "object",
            description:
              "JSON object specifier defining how to locate the object. Must be one of: ElementSpecifier (get by index), NamedSpecifier (get by name), IdSpecifier (get by ID), or PropertySpecifier (get property of object).",
          },
        },
        required: ["app", "specifier"],
      },
    },

    // Tool 2: get_properties - Get properties of a referenced object
    {
      name: "iac_mcp_get_properties",
      description:
        "Get properties of a referenced object. If properties array is null or omitted, returns all available properties.",
      inputSchema: {
        type: "object",
        properties: {
          reference: {
            type: "string",
            description:
              "Object reference ID from query_object (format: ref_<id>)",
          },
          properties: {
            type: "array",
            items: { type: "string" },
            description:
              "Property names to retrieve (omit or null = all properties)",
          },
        },
        required: ["reference"],
      },
    },

    // Tool 3: get_elements - Get elements from a container object
    {
      name: "iac_mcp_get_elements",
      description:
        "Get elements from a container object. Returns references to the elements, which can be used in subsequent calls. Supports pagination via limit parameter.",
      inputSchema: {
        type: "object",
        properties: {
          container: {
            oneOf: [
              {
                type: "string",
                description: "Reference ID of container",
              },
              {
                type: "object",
                description: "Object specifier for container",
              },
            ],
          },
          elementType: {
            type: "string",
            description:
              "Type of elements to retrieve (e.g., 'message', 'file', 'event')",
          },
          limit: {
            type: "number",
            description:
              "Maximum number of elements to return (default: 100)",
            default: 100,
          },
        },
        required: ["container", "elementType"],
      },
    },
  ];
}
