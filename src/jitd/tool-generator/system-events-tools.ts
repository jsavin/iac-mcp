/**
 * System Events UI Automation Tool Definitions
 *
 * Generates MCP tool schemas for high-level System Events UI automation.
 * These tools collapse common multi-step workflows (activate app, read menus,
 * click elements) into single MCP tool calls.
 *
 * These tools work alongside existing query tools (query_object, get_properties, etc.)
 * and are NOT replacements.
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Generates MCP tool definitions for System Events UI automation.
 *
 * @returns Array of 6 MCP tools for UI automation
 */
export function generateSystemEventsTools(): Tool[] {
  return [
    // Tool 1: activate_app - Bring app to front
    {
      name: "iac_mcp_activate_app",
      description: `Bring a macOS application to the front (activate it).

**Usage:** Pass the application name. The app will become the frontmost application.

**Examples:**
- app: "Calendar" → brings Calendar to the front
- app: "Finder" → brings Finder to the front

**Note:** The application must be running. If it's not running, this will return an error.`,
      inputSchema: {
        type: "object",
        properties: {
          app: {
            type: "string",
            description: "Application name (e.g., 'Calendar', 'Finder', 'Safari')",
          },
        },
        required: ["app"],
      },
    },

    // Tool 2: ui_snapshot - Capture UI tree with references
    {
      name: "iac_mcp_ui_snapshot",
      description: `Capture a snapshot of an application's UI element tree. Returns the window hierarchy with element roles, names, values, and stable references for subsequent click_element or set_value calls.

**Usage:**
1. Call ui_snapshot with the app name and optional depth
2. Examine the returned tree to find elements of interest
3. Use the ref IDs in click_element or set_value

**Parameters:**
- app: Application name
- max_depth: How deep to traverse (default: 2, max: 5). Higher depth = more detail but slower.

**Response:** JSON tree with windows → UI elements, each annotated with:
- role: Accessibility role (button, textField, menu, etc.)
- name: Display name (if available)
- value: Current value (for text fields, checkboxes, etc.)
- enabled: Whether the element is interactive
- ref: Reference ID for click_element/set_value
- children: Nested UI elements (up to max_depth)

**Performance:** Depth 2 is usually sufficient for finding buttons and fields. Use depth 3-4 for deeply nested UIs.

**Staleness:** References are valid for about 30 seconds. If the UI changes, re-snapshot.`,
      inputSchema: {
        type: "object",
        properties: {
          app: {
            type: "string",
            description: "Application name (e.g., 'Calendar', 'TextEdit')",
          },
          max_depth: {
            type: "number",
            description: "Maximum depth to traverse the UI tree (default: 2, max: 5)",
            default: 2,
          },
        },
        required: ["app"],
      },
    },

    // Tool 3: click_menu - Click menu item by path
    {
      name: "iac_mcp_click_menu",
      description: `Click a menu item in an application by specifying the menu path.

**Usage:** Provide the app name and menu path as "Menu > Item" or "Menu > Submenu > Item".

**Examples:**
- app: "Calendar", menu_path: "View > Go to Today"
- app: "Finder", menu_path: "File > New Finder Window"
- app: "Safari", menu_path: "File > New Tab"

**Behavior:**
1. Activates the app (brings to front)
2. Clicks through the menu hierarchy
3. Returns success or failure with details

**Error handling:**
- If a menu item is disabled, returns the disabled item name
- If a menu path is invalid, returns available items at the failing level`,
      inputSchema: {
        type: "object",
        properties: {
          app: {
            type: "string",
            description: "Application name (e.g., 'Calendar', 'Finder')",
          },
          menu_path: {
            type: "string",
            description: "Menu path using ' > ' as separator (e.g., 'View > Go to Today', 'File > New Tab')",
          },
        },
        required: ["app", "menu_path"],
      },
    },

    // Tool 4: send_keystroke - Send keystroke with modifiers
    {
      name: "iac_mcp_send_keystroke",
      description: `Send a keystroke to an application with optional modifier keys.

**Usage:** Specify the app, key to press, and optional modifiers.

**Examples:**
- app: "Finder", key: "n", modifiers: ["cmd"] → Cmd+N (new window)
- app: "Safari", key: "t", modifiers: ["cmd"] → Cmd+T (new tab)
- app: "TextEdit", key: "s", modifiers: ["cmd", "shift"] → Cmd+Shift+S (save as)
- app: "Finder", key: "return" → Press Return key

**Modifier mapping:**
- "cmd" → Command key
- "shift" → Shift key
- "option" → Option key
- "control" → Control key

**Special keys:** "return", "tab", "escape", "space", "delete", "up", "down", "left", "right"

**Behavior:** Activates the app first, then sends the keystroke.`,
      inputSchema: {
        type: "object",
        properties: {
          app: {
            type: "string",
            description: "Application name (e.g., 'Finder', 'Safari')",
          },
          key: {
            type: "string",
            description: "Key to press (single character or special key name like 'return', 'tab', 'escape')",
          },
          modifiers: {
            type: "array",
            items: { type: "string" },
            description: "Modifier keys: 'cmd', 'shift', 'option', 'control'",
          },
        },
        required: ["app", "key"],
      },
    },

    // Tool 5: click_element - Click element from snapshot
    {
      name: "iac_mcp_click_element",
      description: `Click a UI element identified by a reference from ui_snapshot.

**Usage:**
1. First call ui_snapshot to get element references
2. Find the element you want to click
3. Pass its reference ID to this tool

**Example workflow:**
1. ui_snapshot("Calendar", 2) → finds button with ref "ref_abc123"
2. click_element("ref_abc123") → clicks that button

**Staleness:** If the UI has changed since the snapshot, the element may not be found. In that case, re-run ui_snapshot.`,
      inputSchema: {
        type: "object",
        properties: {
          ref: {
            type: "string",
            description: "Reference ID from ui_snapshot (format: ref_<uuid>)",
          },
        },
        required: ["ref"],
      },
    },

    // Tool 6: set_value - Set text field/checkbox value
    {
      name: "iac_mcp_set_value",
      description: `Set the value of a UI element identified by a reference from ui_snapshot. Works with text fields, text areas, checkboxes, and other value-holding elements.

**Usage:**
1. First call ui_snapshot to get element references
2. Find the text field or checkbox you want to modify
3. Pass its reference ID and the new value

**Examples:**
- Set text field: ref: "ref_abc123", value: "Meeting notes"
- Set checkbox: ref: "ref_def456", value: true
- Clear text field: ref: "ref_abc123", value: ""

**Staleness:** If the UI has changed since the snapshot, the element may not be found. In that case, re-run ui_snapshot.`,
      inputSchema: {
        type: "object",
        properties: {
          ref: {
            type: "string",
            description: "Reference ID from ui_snapshot (format: ref_<uuid>)",
          },
          value: {
            description: "New value to set (string for text fields, boolean for checkboxes)",
          },
        },
        required: ["ref", "value"],
      },
    },
  ];
}
