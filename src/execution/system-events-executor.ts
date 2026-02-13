/**
 * SystemEventsExecutor - Executes System Events UI automation commands
 *
 * Builds JXA scripts for UI automation via System Events and executes them
 * using JXAExecutor. Manages UI element references in ReferenceStore.
 *
 * This is separate from QueryExecutor because System Events UI automation
 * is fundamentally different from object model queries:
 * - UI elements are ephemeral (disappear when UI changes)
 * - Requires accessibility API patterns (menu traversal, keystrokes)
 * - Different error modes (element not found vs. property access failed)
 */

import { JXAExecutor } from "../adapters/macos/jxa-executor.js";
import { ResultParser } from "../adapters/macos/result-parser.js";
import { ReferenceStore } from "./reference-store.js";
import { UIElementRef, UIElementPathSegment, UI_ELEMENT_STALENESS_MS, isUIElementRef } from "../types/ui-element.js";
import type { ObjectSpecifier } from "../types/object-specifier.js";

/**
 * Regex for validating application names.
 * Allows alphanumeric, spaces, dots, hyphens, underscores.
 */
const SAFE_APP_NAME_REGEX = /^[a-zA-Z0-9_.\- ]+$/;

/**
 * Regex for validating identifiers (menu item names, key names, etc.).
 * Allows alphanumeric, spaces, hyphens, underscores.
 */
const SAFE_IDENTIFIER_REGEX = /^[a-zA-Z0-9_ \-]+$/;

/**
 * Maximum length for string parameters.
 */
const MAX_STRING_LENGTH = 256;

/**
 * Maximum depth for UI snapshot traversal.
 */
const MAX_SNAPSHOT_DEPTH = 5;

/**
 * Maximum elements per level in UI snapshot.
 */
const MAX_ELEMENTS_PER_LEVEL = 100;

/**
 * Valid modifier keys for keystroke.
 */
const VALID_MODIFIERS = new Set(["cmd", "shift", "option", "control"]);

/**
 * Modifier key mapping from short names to JXA names.
 */
const MODIFIER_MAP: Record<string, string> = {
  cmd: "command down",
  shift: "shift down",
  option: "option down",
  control: "control down",
};

/**
 * Special key mapping from names to JXA key code expressions.
 * These are keys that can't be sent via keystroke() and need keyCode().
 */
const SPECIAL_KEYS = new Set([
  "return", "tab", "escape", "space", "delete",
  "up", "down", "left", "right",
  "f1", "f2", "f3", "f4", "f5", "f6",
  "f7", "f8", "f9", "f10", "f11", "f12",
]);

/**
 * JXA key code values for special keys.
 */
const KEY_CODES: Record<string, number> = {
  return: 36,
  tab: 48,
  escape: 53,
  space: 49,
  delete: 51,
  up: 126,
  down: 125,
  left: 123,
  right: 124,
  f1: 122,
  f2: 120,
  f3: 99,
  f4: 118,
  f5: 96,
  f6: 97,
  f7: 98,
  f8: 100,
  f9: 101,
  f10: 109,
  f11: 103,
  f12: 111,
};

/**
 * Role name to JXA collection name mapping.
 * Maps accessibility roles to their JXA UI element collection names.
 */
const ROLE_TO_COLLECTION: Record<string, string> = {
  window: "windows",
  button: "buttons",
  toolbar: "toolbars",
  textField: "textFields",
  textArea: "textAreas",
  staticText: "staticTexts",
  checkbox: "checkboxes",
  radioButton: "radioButtons",
  popUpButton: "popUpButtons",
  comboBox: "comboBoxes",
  slider: "sliders",
  tabGroup: "tabGroups",
  tab: "tabs",
  table: "tables",
  row: "rows",
  column: "columns",
  cell: "cells",
  scrollArea: "scrollAreas",
  scrollBar: "scrollBars",
  group: "groups",
  splitGroup: "splitGroups",
  image: "images",
  menu: "menus",
  menuItem: "menuItems",
  menuBar: "menuBars",
  menuBarItem: "menuBarItems",
  outline: "outlines",
  sheet: "sheets",
  drawer: "drawers",
  list: "lists",
  progressIndicator: "progressIndicators",
};

/**
 * UI snapshot tree node returned by JXA.
 */
interface UISnapshotNode {
  role: string;
  name: string | null;
  value?: unknown;
  enabled: boolean;
  focused?: boolean;
  index?: number;
  children: UISnapshotNode[];
}

/**
 * Annotated UI snapshot node with reference IDs.
 */
interface AnnotatedUINode {
  role: string;
  name: string | null;
  value?: unknown;
  enabled: boolean;
  focused?: boolean;
  ref?: string;
  children: AnnotatedUINode[];
}

/**
 * SystemEventsExecutor
 *
 * Executes System Events UI automation commands via JXA.
 */
export class SystemEventsExecutor {
  private resultParser: ResultParser;

  constructor(
    private referenceStore: ReferenceStore,
    private jxaExecutor?: JXAExecutor
  ) {
    this.resultParser = new ResultParser();
  }

  /**
   * Activate an application (bring to front).
   */
  async activateApp(app: string): Promise<{ success: boolean; app?: string; error?: string }> {
    this.validateAppName(app);

    if (!this.jxaExecutor) {
      return { success: true, app };
    }

    const escaped = this.escapeJxaString(app);
    const jxaCode =
      "(() => {" +
      '  var se = Application("System Events");' +
      '  var proc = se.processes.byName("' + escaped + '");' +
      "  proc.frontmost = true;" +
      "  delay(0.3);" +
      '  return JSON.stringify({ success: true, app: "' + escaped + '" });' +
      "})()";

    const result = await this.jxaExecutor.execute(jxaCode);
    const parsed = this.resultParser.parse(result, { appName: "System Events" });

    if (!parsed.success) {
      return { success: false, error: parsed.error?.message || "Failed to activate app" };
    }

    return parsed.data || { success: true, app };
  }

  /**
   * Capture a snapshot of an app's UI element tree.
   */
  async uiSnapshot(
    app: string,
    maxDepth: number = 2
  ): Promise<{ app: string; windows: AnnotatedUINode[]; _warning?: string }> {
    this.validateAppName(app);

    // Validate and clamp depth
    if (!Number.isInteger(maxDepth) || maxDepth < 1) {
      maxDepth = 2;
    }
    if (maxDepth > MAX_SNAPSHOT_DEPTH) {
      maxDepth = MAX_SNAPSHOT_DEPTH;
    }

    if (!this.jxaExecutor) {
      return { app, windows: [] };
    }

    const escaped = this.escapeJxaString(app);
    const jxaCode =
      "(() => {" +
      '  var se = Application("System Events");' +
      '  var proc = se.processes.byName("' + escaped + '");' +
      "  function cap(el, d, max) {" +
      "    if (d >= max) return null;" +
      '    var info = { role: "", name: null, enabled: true, children: [] };' +
      "    try { info.role = el.role(); } catch(e) {}" +
      "    try { info.name = el.name(); } catch(e) {}" +
      "    try { info.value = el.value(); } catch(e) {}" +
      "    try { info.enabled = el.enabled(); } catch(e) {}" +
      "    try { info.focused = el.focused(); } catch(e) {}" +
      "    try {" +
      "      var kids = el.uiElements();" +
      "      for (var i = 0; i < Math.min(kids.length, " + MAX_ELEMENTS_PER_LEVEL + "); i++) {" +
      "        var child = cap(kids[i], d + 1, max);" +
      "        if (child) { child.index = i; info.children.push(child); }" +
      "      }" +
      "    } catch(e) {}" +
      "    return info;" +
      "  }" +
      "  var wins = proc.windows();" +
      '  var result = { app: "' + escaped + '", windows: [] };' +
      "  for (var i = 0; i < wins.length; i++) {" +
      "    var w = cap(wins[i], 0, " + maxDepth + ");" +
      "    if (w) { w.index = i; result.windows.push(w); }" +
      "  }" +
      "  return JSON.stringify(result);" +
      "})()";

    const result = await this.jxaExecutor.execute(jxaCode);
    const parsed = this.resultParser.parse(result, { appName: "System Events" });

    if (!parsed.success) {
      return { app, windows: [], _warning: parsed.error?.message || "Failed to capture UI snapshot" };
    }

    const rawResult = parsed.data || { app, windows: [] };
    const snapshotTime = Date.now();

    // Post-process: walk tree, create references, annotate with ref IDs
    const annotatedWindows = rawResult.windows.map((windowNode: UISnapshotNode, windowIndex: number) => {
      return this.annotateNode(windowNode, app, [{ role: "window", index: windowIndex, name: windowNode.name || undefined }], snapshotTime);
    });

    return { app, windows: annotatedWindows };
  }

  /**
   * Click a menu item by path (e.g., "View > Go to Today").
   */
  async clickMenu(
    app: string,
    menuPath: string
  ): Promise<{ success: boolean; path?: string[]; error?: string; item?: string; available_items?: string[] }> {
    this.validateAppName(app);

    // Parse and validate menu path
    const parts = menuPath.split(" > ").map(s => s.trim()).filter(s => s.length > 0);
    if (parts.length === 0) {
      return { success: false, error: "empty_menu_path" };
    }

    for (const part of parts) {
      this.validateIdentifier(part, "menu item name");
    }

    if (!this.jxaExecutor) {
      return { success: true, path: parts };
    }

    const escaped = this.escapeJxaString(app);

    // Build menu navigation JXA
    // First part is the menu bar item, rest are menu items
    let jxaLines: string[] = [];
    jxaLines.push("(() => {");
    jxaLines.push('  var se = Application("System Events");');
    jxaLines.push('  var proc = se.processes.byName("' + escaped + '");');
    jxaLines.push("  proc.frontmost = true;");
    jxaLines.push("  delay(0.3);");
    jxaLines.push("  var mb = proc.menuBars[0];");

    // First level: menu bar item
    const firstEscaped = this.escapeJxaString(parts[0]!);
    jxaLines.push('  var item0 = mb.menuBarItems.byName("' + firstEscaped + '");');
    jxaLines.push("  item0.click();");
    jxaLines.push("  delay(0.2);");

    // Subsequent levels: menu items in submenus
    for (let i = 1; i < parts.length; i++) {
      const partEscaped = this.escapeJxaString(parts[i]!);
      const menuVar = "menu" + (i - 1);
      const itemVar = "item" + i;
      jxaLines.push("  var " + menuVar + " = item" + (i - 1) + ".menus[0];");
      jxaLines.push('  var ' + itemVar + ' = ' + menuVar + '.menuItems.byName("' + partEscaped + '");');

      // Only click and check enabled for the last item
      if (i === parts.length - 1) {
        jxaLines.push("  var enabled = true;");
        jxaLines.push("  try { enabled = " + itemVar + ".enabled(); } catch(e) {}");
        jxaLines.push("  if (!enabled) {");
        jxaLines.push('    return JSON.stringify({ success: false, error: "menu_item_disabled", item: "' + partEscaped + '" });');
        jxaLines.push("  }");
        jxaLines.push("  " + itemVar + ".click();");
      } else {
        jxaLines.push("  " + itemVar + ".click();");
        jxaLines.push("  delay(0.2);");
      }
    }

    // Build path array for response
    const pathJson = "[" + parts.map(p => '"' + this.escapeJxaString(p) + '"').join(", ") + "]";
    jxaLines.push("  return JSON.stringify({ success: true, path: " + pathJson + " });");
    jxaLines.push("})()");

    const jxaCode = jxaLines.join("\n");

    const result = await this.jxaExecutor.execute(jxaCode);
    const parsed = this.resultParser.parse(result, { appName: "System Events" });

    if (!parsed.success) {
      // Try to extract meaningful error
      const errorMsg = parsed.error?.message || "Failed to click menu item";
      if (errorMsg.includes("Can't get") || errorMsg.includes("Invalid index")) {
        return { success: false, error: "menu_path_not_found", path: parts };
      }
      return { success: false, error: errorMsg };
    }

    return parsed.data || { success: true, path: parts };
  }

  /**
   * Send a keystroke to an application.
   */
  async sendKeystroke(
    app: string,
    key: string,
    modifiers?: string[]
  ): Promise<{ success: boolean; error?: string }> {
    this.validateAppName(app);

    // Validate key
    if (!key || typeof key !== "string") {
      return { success: false, error: "invalid_key" };
    }

    const keyLower = key.toLowerCase();

    // Validate modifiers
    if (modifiers) {
      for (const mod of modifiers) {
        if (!VALID_MODIFIERS.has(mod)) {
          return { success: false, error: "invalid_modifier: " + mod + ". Valid: cmd, shift, option, control" };
        }
      }
    }

    if (!this.jxaExecutor) {
      return { success: true };
    }

    const escaped = this.escapeJxaString(app);

    // Build modifier string for JXA
    let modifierStr = "";
    if (modifiers && modifiers.length > 0) {
      const mappedMods = modifiers.map(m => '"' + MODIFIER_MAP[m] + '"');
      modifierStr = ", { using: [" + mappedMods.join(", ") + "] }";
    }

    let keystrokeExpr: string;
    if (SPECIAL_KEYS.has(keyLower)) {
      // Use key code for special keys
      const code = KEY_CODES[keyLower];
      if (code === undefined) {
        return { success: false, error: "unknown_special_key: " + key };
      }
      keystrokeExpr = "se.keyCode(" + code + modifierStr + ");";
    } else {
      // Validate single character for regular keystroke
      if (key.length !== 1) {
        return { success: false, error: "key must be a single character or a special key name" };
      }
      // Validate the key is safe
      if (!/^[a-zA-Z0-9]$/.test(key)) {
        return { success: false, error: "key contains invalid characters. Only alphanumeric characters are allowed for regular keys." };
      }
      const keyEscaped = this.escapeJxaString(key);
      keystrokeExpr = 'se.keystroke("' + keyEscaped + '"' + modifierStr + ");";
    }

    const jxaCode =
      "(() => {" +
      '  var se = Application("System Events");' +
      '  var proc = se.processes.byName("' + escaped + '");' +
      "  proc.frontmost = true;" +
      "  delay(0.3);" +
      "  " + keystrokeExpr +
      '  return JSON.stringify({ success: true });' +
      "})()";

    const result = await this.jxaExecutor.execute(jxaCode);
    const parsed = this.resultParser.parse(result, { appName: "System Events" });

    if (!parsed.success) {
      return { success: false, error: parsed.error?.message || "Failed to send keystroke" };
    }

    return parsed.data || { success: true };
  }

  /**
   * Click a UI element by reference.
   */
  async clickElement(
    ref: string
  ): Promise<{ success: boolean; error?: string; suggestion?: string; _warning?: string }> {
    // Resolve reference
    const reference = this.referenceStore.get(ref);
    if (!reference) {
      return {
        success: false,
        error: "reference_not_found",
        suggestion: "Run ui_snapshot to get fresh references",
      };
    }

    // Check if it's a UI element reference
    if (!isUIElementRef(reference.specifier)) {
      return {
        success: false,
        error: "invalid_reference_type",
        suggestion: "This reference is not a UI element. Use ui_snapshot to get UI element references.",
      };
    }

    const uiRef = reference.specifier as UIElementRef;
    const staleness = Date.now() - uiRef.snapshotTime;
    const isStale = staleness > UI_ELEMENT_STALENESS_MS;

    if (!this.jxaExecutor) {
      const result: { success: boolean; _warning?: string } = { success: true };
      if (isStale) {
        result._warning = "Reference is " + Math.round(staleness / 1000) + "s old. UI may have changed.";
      }
      return result;
    }

    const jxaPath = this.buildJxaPathFromUIRef(uiRef);
    const escaped = this.escapeJxaString(uiRef.appName);

    const jxaCode =
      "(() => {" +
      '  var se = Application("System Events");' +
      '  var proc = se.processes.byName("' + escaped + '");' +
      "  var el = " + jxaPath + ";" +
      "  el.click();" +
      '  return JSON.stringify({ success: true });' +
      "})()";

    const result = await this.jxaExecutor.execute(jxaCode);
    const parsed = this.resultParser.parse(result, { appName: "System Events" });

    if (!parsed.success) {
      const errorMsg = parsed.error?.message || "Failed to click element";
      if (errorMsg.includes("Can't get") || errorMsg.includes("Invalid index")) {
        return {
          success: false,
          error: "element_not_found",
          suggestion: "Run ui_snapshot to get fresh references",
        };
      }
      return { success: false, error: errorMsg };
    }

    const response: { success: boolean; _warning?: string } = parsed.data || { success: true };
    if (isStale) {
      response._warning = "Reference is " + Math.round(staleness / 1000) + "s old. UI may have changed.";
    }
    return response;
  }

  /**
   * Set the value of a UI element by reference.
   */
  async setValue(
    ref: string,
    value: unknown
  ): Promise<{ success: boolean; error?: string; suggestion?: string; _warning?: string }> {
    // Resolve reference
    const reference = this.referenceStore.get(ref);
    if (!reference) {
      return {
        success: false,
        error: "reference_not_found",
        suggestion: "Run ui_snapshot to get fresh references",
      };
    }

    // Check if it's a UI element reference
    if (!isUIElementRef(reference.specifier)) {
      return {
        success: false,
        error: "invalid_reference_type",
        suggestion: "This reference is not a UI element. Use ui_snapshot to get UI element references.",
      };
    }

    const uiRef = reference.specifier as UIElementRef;
    const staleness = Date.now() - uiRef.snapshotTime;
    const isStale = staleness > UI_ELEMENT_STALENESS_MS;

    if (!this.jxaExecutor) {
      const result: { success: boolean; _warning?: string } = { success: true };
      if (isStale) {
        result._warning = "Reference is " + Math.round(staleness / 1000) + "s old. UI may have changed.";
      }
      return result;
    }

    const jxaPath = this.buildJxaPathFromUIRef(uiRef);
    const escaped = this.escapeJxaString(uiRef.appName);

    // Serialize value for JXA
    const serializedValue = this.serializeValue(value);

    const jxaCode =
      "(() => {" +
      '  var se = Application("System Events");' +
      '  var proc = se.processes.byName("' + escaped + '");' +
      "  var el = " + jxaPath + ";" +
      "  el.value = " + serializedValue + ";" +
      '  return JSON.stringify({ success: true });' +
      "})()";

    const result = await this.jxaExecutor.execute(jxaCode);
    const parsed = this.resultParser.parse(result, { appName: "System Events" });

    if (!parsed.success) {
      const errorMsg = parsed.error?.message || "Failed to set value";
      if (errorMsg.includes("Can't get") || errorMsg.includes("Invalid index")) {
        return {
          success: false,
          error: "element_not_found",
          suggestion: "Run ui_snapshot to get fresh references",
        };
      }
      return { success: false, error: errorMsg };
    }

    const response: { success: boolean; _warning?: string } = parsed.data || { success: true };
    if (isStale) {
      response._warning = "Reference is " + Math.round(staleness / 1000) + "s old. UI may have changed.";
    }
    return response;
  }

  // ===========================================================================
  // Private helpers
  // ===========================================================================

  /**
   * Recursively annotate a UI snapshot node with reference IDs.
   */
  private annotateNode(
    node: UISnapshotNode,
    appName: string,
    pathSoFar: UIElementPathSegment[],
    snapshotTime: number
  ): AnnotatedUINode {
    // Create reference for this node
    const uiRef: UIElementRef = {
      type: "ui_element",
      appName,
      path: [...pathSoFar],
      snapshotTime,
    };

    // Store as ObjectSpecifier (UIElementRef extends the shape)
    const refId = this.referenceStore.create(
      appName,
      node.role || "unknown",
      uiRef as unknown as ObjectSpecifier
    );

    // Build annotated node
    const annotated: AnnotatedUINode = {
      role: node.role,
      name: node.name,
      enabled: node.enabled,
      ref: refId,
      children: [],
    };

    if (node.value !== undefined && node.value !== null) {
      annotated.value = node.value;
    }

    if (node.focused !== undefined) {
      annotated.focused = node.focused;
    }

    // Recursively annotate children
    annotated.children = node.children.map((child) => {
      const childPath: UIElementPathSegment[] = [
        ...pathSoFar,
        {
          role: child.role || "unknown",
          index: child.index ?? 0,
          name: child.name || undefined,
        },
      ];
      return this.annotateNode(child, appName, childPath, snapshotTime);
    });

    return annotated;
  }

  /**
   * Build JXA path from a UIElementRef.
   * Converts the path segments into JXA accessor chain.
   *
   * Example: [{role: "window", index: 0}, {role: "toolbar", index: 0}, {role: "button", index: 2}]
   * → proc.windows[0].toolbars[0].buttons[2]
   */
  private buildJxaPathFromUIRef(uiRef: UIElementRef): string {
    let path = "proc";

    for (const segment of uiRef.path) {
      const collection = ROLE_TO_COLLECTION[segment.role];
      if (collection) {
        path = path + "." + collection + "[" + segment.index + "]";
      } else {
        // Fallback: use uiElements for unknown roles
        path = path + ".uiElements[" + segment.index + "]";
      }
    }

    return path;
  }

  /**
   * Validate application name for safe JXA usage.
   */
  private validateAppName(app: string): void {
    if (!app || typeof app !== "string") {
      throw new Error("App name is required and must be a string");
    }

    if (app.length > MAX_STRING_LENGTH) {
      throw new Error("App name exceeds maximum length (" + MAX_STRING_LENGTH + " characters)");
    }

    if (!SAFE_APP_NAME_REGEX.test(app)) {
      throw new Error("App name contains invalid characters. Only alphanumeric, spaces, dots, hyphens, and underscores are allowed.");
    }
  }

  /**
   * Validate an identifier (menu item name, key name, etc.).
   */
  private validateIdentifier(value: string, fieldName: string): void {
    if (!value || typeof value !== "string") {
      throw new Error(fieldName + " is required and must be a string");
    }

    if (value.length > MAX_STRING_LENGTH) {
      throw new Error(fieldName + " exceeds maximum length (" + MAX_STRING_LENGTH + " characters)");
    }

    if (!SAFE_IDENTIFIER_REGEX.test(value)) {
      throw new Error(fieldName + " contains invalid characters. Only alphanumeric, spaces, hyphens, and underscores are allowed.");
    }
  }

  /**
   * Escape a string for safe inclusion in JXA string literals.
   */
  private escapeJxaString(value: string): string {
    return value
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/'/g, "\\'")
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")
      .replace(/\t/g, "\\t");
  }

  /**
   * Serialize a value for inclusion in JXA code.
   */
  private serializeValue(value: unknown): string {
    if (value === null || value === undefined) {
      return "null";
    }
    if (typeof value === "string") {
      return '"' + this.escapeJxaString(value) + '"';
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new Error("Invalid number value: " + value);
      }
      return String(value);
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    throw new Error("Unsupported value type: " + typeof value);
  }
}
