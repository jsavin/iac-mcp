import { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Generates MCP tool definitions for stateful object queries.
 * These tools are app-independent and work with any scriptable application.
 *
 * @returns Array of 6 MCP tools: query_object, get_properties, set_property, get_elements, get_elements_with_properties, get_properties_batch
 */
export function generateQueryTools(): Tool[] {
  return [
    // Tool 1: query_object - Query an object and get a stable reference
    {
      name: "iac_mcp_query_object",
      description: `Query an object in a macOS application and return a stable reference for subsequent operations.

**When to use:** Use query tools (query_object, get_properties, get_elements) to navigate the application's object model. Use action tools (from get_app_tools) to perform operations like sending emails or creating files.

**Specifier Types:**

1. **NamedSpecifier** - Find by name:
   {"type": "named", "element": "mailbox", "name": "INBOX", "container": "application"}

2. **ElementSpecifier** - Find by index (0-based):
   {"type": "element", "element": "message", "index": 0, "container": <parent-specifier-or-reference>}

3. **IdSpecifier** - Find by unique ID:
   {"type": "id", "element": "message", "id": "msg-12345", "container": "application"}

4. **PropertySpecifier** - Get a property value:
   {"type": "property", "property": "subject", "of": <specifier-or-reference-id>}

**Common Patterns:**

| App | Object | Specifier Example |
|-----|--------|-------------------|
| Mail | Inbox | {"type": "named", "element": "mailbox", "name": "INBOX", "container": "application"} |
| Mail | First message in inbox | Use get_elements on mailbox reference with elementType "message" |
| Finder | Desktop folder | {"type": "named", "element": "folder", "name": "Desktop", "container": "application"} |
| Calendar | Default calendar | {"type": "named", "element": "calendar", "name": "Calendar", "container": "application"} |
| Contacts | All people | Use get_elements on application with elementType "person" |
| Safari | Front window | {"type": "element", "element": "window", "index": 0, "container": "application"} |

**Nested Containers:** Chain specifiers by setting "container" to a parent specifier:
{"type": "element", "element": "message", "index": 0, "container": {"type": "named", "element": "mailbox", "name": "INBOX", "container": "application"}}

**Reference Lifetime:** References remain valid for 15 minutes. Use the returned reference ID in get_properties, get_elements, or action tools.

**Note:** This may launch the application if it's not running.`,
      inputSchema: {
        type: "object",
        properties: {
          app: {
            type: "string",
            description:
              "Application name (e.g., 'Mail', 'Finder', 'Safari') or bundle ID (e.g., 'com.apple.mail')",
          },
          specifier: {
            type: "object",
            description:
              "Object specifier defining how to locate the object. See tool description for specifier types and examples.",
          },
        },
        required: ["app", "specifier"],
      },
    },

    // Tool 2: get_properties - Get properties of a referenced object
    {
      name: "iac_mcp_get_properties",
      description: `Get properties of a referenced object. Returns property names and their current values.

**Usage:**
1. First obtain a reference using query_object
2. Pass the reference ID to this tool
3. Optionally specify which properties you want (omit for all properties)

**Examples:**

Get all properties of a Mail message:
- reference: "ref_abc123" (from query_object)
- properties: null (returns all: subject, sender, dateReceived, etc.)

Get specific properties:
- reference: "ref_abc123"
- properties: ["subject", "sender", "dateReceived"]

**Common Property Names by App:**

| App | Object Type | Common Properties |
|-----|-------------|-------------------|
| Mail | message | subject, sender, dateReceived, read status, content |
| Mail | mailbox | name, unreadCount |
| Finder | file | name, size, creationDate, modificationDate, kind |
| Finder | folder | name, items, window |
| Calendar | event | summary, startDate, endDate, location |
| Contacts | person | firstName, lastName, email, phone |
| Safari | tab | URL, name |

**Note:** Property names with spaces should be provided as-is (e.g., "read status"). The tool handles conversion to the correct format.`,
      inputSchema: {
        type: "object",
        properties: {
          reference: {
            type: "string",
            description:
              "Object reference ID from query_object (format: ref_<uuid>)",
          },
          properties: {
            type: "array",
            items: { type: "string" },
            description:
              "Specific property names to retrieve. Omit or set to null to get all available properties.",
          },
        },
        required: ["reference"],
      },
    },

    // Tool 3: set_property - Set a property on a referenced object
    {
      name: "iac_mcp_set_property",
      description: `Set a property value on a referenced object.

**Usage:**
1. First obtain a reference using query_object
2. Call set_property with the reference ID, property name, and new value
3. The property will be updated on the target object

**Examples:**

Mark a Mail message as read:
- reference: "ref_message123" (from query_object)
- property: "readStatus"
- value: true

Hide a window:
- reference: "ref_window123"
- property: "visible"
- value: false

Rename a Finder file:
- reference: "ref_file123"
- property: "name"
- value: "new-filename.txt"

**Common Writable Properties by App:**

| App | Object Type | Writable Properties |
|-----|-------------|---------------------|
| Mail | message | readStatus, flaggedStatus, junkMailStatus |
| Finder | file/folder | name, comment, labelIndex, locked |
| Finder | window | bounds, position, visible |
| Safari | tab | URL |
| System Events | process | visible, frontmost |

**Value Types:**
- Strings: "new value"
- Numbers: 42
- Booleans: true/false
- Null to clear (if supported)

**Permissions:** Some properties may require user confirmation before modification. Destructive changes may be blocked by the permission system.

**Note:** Not all properties are writable. Read-only properties will return an error.`,
      inputSchema: {
        type: "object",
        properties: {
          reference: {
            type: "string",
            description:
              "Object reference ID from query_object (format: ref_<uuid>)",
          },
          property: {
            type: "string",
            description:
              "Name of the property to set (e.g., 'visible', 'name', 'readStatus')",
          },
          value: {
            description:
              "New value for the property. Type depends on the property (string, number, boolean, or null).",
          },
        },
        required: ["reference", "property", "value"],
      },
    },

    // Tool 4: get_elements - Get elements from a container object
    {
      name: "iac_mcp_get_elements",
      description: `Get child elements from a container object. Returns references to the elements for further operations.

**Usage:**
1. Obtain a reference to a container (mailbox, folder, calendar, etc.) using query_object
2. Call get_elements with the container reference and element type
3. Receive references to each element for use in get_properties or action tools

**Examples:**

Get messages in a mailbox:
- container: "ref_mailbox123" (reference to INBOX from query_object)
- elementType: "message"
- limit: 10

Get files in a folder:
- container: {"type": "named", "element": "folder", "name": "Desktop", "container": "application"}
- elementType: "file"
- app: "Finder"
- limit: 50

**Common Container/Element Relationships:**

| App | Container | Element Type |
|-----|-----------|--------------|
| Mail | mailbox | message |
| Mail | message | attachment |
| Finder | folder | file, folder |
| Finder | application | disk, window |
| Calendar | calendar | event |
| Contacts | application | person |
| Contacts | person | email, phone |
| Safari | window | tab |

**Pagination:**
- Use limit to control how many elements to retrieve (default: 100, max recommended: 1000)
- Response includes hasMore: true if more elements exist beyond the limit
- Use index-based specifiers to access elements beyond the limit

**Performance Tips:**
- Start with small limits (10-20) when exploring
- Increase limit only when you need more results
- Large collections (1000+ elements) may take several seconds`,
      inputSchema: {
        type: "object",
        properties: {
          container: {
            oneOf: [
              {
                type: "string",
                description:
                  "Reference ID of container object (app is inferred from the reference)",
              },
              {
                type: "object",
                description:
                  "Object specifier for container (requires app parameter)",
              },
            ],
          },
          elementType: {
            type: "string",
            description:
              "Type of elements to retrieve in singular form (e.g., 'message', 'file', 'event', 'person')",
          },
          app: {
            type: "string",
            description:
              "Application name or bundle ID. Required when container is an ObjectSpecifier, ignored when container is a reference ID.",
          },
          limit: {
            type: "number",
            description:
              "Maximum number of elements to return (default: 100). Response includes hasMore flag if more exist.",
            default: 100,
          },
        },
        required: ["container", "elementType"],
      },
    },

    // Tool 5: get_elements_with_properties - Batch get elements + properties
    {
      name: "iac_mcp_get_elements_with_properties",
      description: `Get child elements from a container with their properties in a single batch operation. Reduces round trips compared to calling get_elements + get_properties separately.

**Usage:**
1. Obtain a reference to a container (mailbox, folder, etc.) using query_object
2. Call this tool with the container, element type, and desired properties
3. Receive elements with their properties in one response

**Examples:**

Get messages with subject and sender:
- container: "ref_mailbox123"
- elementType: "message"
- properties: ["subject", "sender", "dateReceived"]
- limit: 10

Get files with name and size:
- container: {"type": "named", "element": "folder", "name": "Desktop", "container": "application"}
- elementType: "file"
- properties: ["name", "size", "modificationDate"]
- app: "Finder"

**Performance:** Fetches all data in 1-2 JXA calls instead of 2N+1 calls (where N = number of elements).

**Error Resilience:** If a property fails for an element (e.g., permission denied), the error is reported per-property with an _error field, while other properties still return normally.`,
      inputSchema: {
        type: "object",
        properties: {
          container: {
            oneOf: [
              {
                type: "string",
                description:
                  "Reference ID of container object (app is inferred from the reference)",
              },
              {
                type: "object",
                description:
                  "Object specifier for container (requires app parameter)",
              },
            ],
          },
          elementType: {
            type: "string",
            description:
              "Type of elements to retrieve in singular form (e.g., 'message', 'file', 'event')",
          },
          properties: {
            type: "array",
            items: { type: "string" },
            description:
              "Property names to retrieve for each element (e.g., ['subject', 'sender', 'dateReceived'])",
          },
          app: {
            type: "string",
            description:
              "Application name or bundle ID. Required when container is an ObjectSpecifier, ignored when container is a reference ID.",
          },
          limit: {
            type: "number",
            description:
              "Maximum number of elements to return (default: 100). Response includes hasMore flag if more exist.",
            default: 100,
          },
        },
        required: ["container", "elementType", "properties"],
      },
    },

    // Tool 6: get_properties_batch - Batch get properties for multiple references
    {
      name: "iac_mcp_get_properties_batch",
      description: `Get properties for multiple referenced objects in a single batch call. Reduces N separate get_properties calls to 1.

**Usage:**
1. Obtain multiple references (e.g., from get_properties returning reference lists, or from get_elements)
2. Pass all reference IDs to this tool
3. Receive all properties in one response

**Examples:**

Get subjects of selected messages:
- references: ["ref_abc1", "ref_abc2", "ref_abc3"] (from get_properties on selectedMessages)
- properties: ["subject", "sender"]

Get names and sizes of multiple files:
- references: ["ref_file1", "ref_file2", "ref_file3"]
- properties: ["name", "size"]

**Performance:** References from the same app are batched into a single JXA call. References from different apps run concurrently.

**Error Resilience:** If one reference fails (e.g., expired), its entry gets an error field while others succeed normally.

**Order:** Results are returned in the same order as the input references array.`,
      inputSchema: {
        type: "object",
        properties: {
          references: {
            type: "array",
            items: { type: "string" },
            description:
              "Array of reference IDs to fetch properties for (format: ref_<uuid>)",
          },
          properties: {
            type: "array",
            items: { type: "string" },
            description:
              "Specific property names to retrieve. Omit or set to null to get all available properties.",
          },
        },
        required: ["references"],
      },
    },
  ];
}
