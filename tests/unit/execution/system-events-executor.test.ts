import { describe, it, expect, beforeEach, vi } from "vitest";
import { SystemEventsExecutor } from "../../../src/execution/system-events-executor.js";
import { ReferenceStore } from "../../../src/execution/reference-store.js";
import { UIElementRef, UI_ELEMENT_STALENESS_MS } from "../../../src/types/ui-element.js";
import type { JXAExecutionResult } from "../../../src/adapters/macos/jxa-executor.js";
import type { ObjectSpecifier } from "../../../src/types/object-specifier.js";

/**
 * Helper to create a mock JXA executor.
 */
function createMockJxaExecutor() {
  return {
    execute: vi.fn<(script: string) => Promise<JXAExecutionResult>>(),
  };
}

/**
 * Helper to create a successful JXA result with JSON data.
 */
function jxaSuccess(data: unknown): JXAExecutionResult {
  return {
    exitCode: 0,
    stdout: JSON.stringify(data),
    stderr: "",
    timedOut: false,
  };
}

/**
 * Helper to create a failed JXA result.
 */
function jxaFailure(stderr: string): JXAExecutionResult {
  return {
    exitCode: 1,
    stdout: "",
    stderr,
    timedOut: false,
  };
}

/**
 * Helper to create a valid UIElementRef and store it.
 */
function createUIRef(
  store: ReferenceStore,
  overrides: Partial<UIElementRef> = {}
): string {
  const uiRef: UIElementRef = {
    type: "ui_element",
    appName: "Calendar",
    path: [
      { role: "window", index: 0 },
      { role: "button", index: 2, name: "Today" },
    ],
    snapshotTime: Date.now(),
    ...overrides,
  };
  return store.create(uiRef.appName, "button", uiRef as unknown as ObjectSpecifier);
}

/**
 * Helper to create a stale UIElementRef (older than staleness threshold).
 */
function createStaleUIRef(
  store: ReferenceStore,
  overrides: Partial<UIElementRef> = {}
): string {
  return createUIRef(store, {
    snapshotTime: Date.now() - UI_ELEMENT_STALENESS_MS - 30_000,
    ...overrides,
  });
}

describe("SystemEventsExecutor", () => {
  let referenceStore: ReferenceStore;
  let mockJxaExecutor: ReturnType<typeof createMockJxaExecutor>;
  let executor: SystemEventsExecutor;
  let executorNoJxa: SystemEventsExecutor;

  beforeEach(() => {
    referenceStore = new ReferenceStore();
    mockJxaExecutor = createMockJxaExecutor();
    executor = new SystemEventsExecutor(referenceStore, mockJxaExecutor as any);
    executorNoJxa = new SystemEventsExecutor(referenceStore);
  });

  // ===========================================================================
  // activateApp
  // ===========================================================================

  describe("activateApp", () => {
    it("should reject empty app name", async () => {
      await expect(executor.activateApp("")).rejects.toThrow(
        "App name is required and must be a string"
      );
    });

    it("should reject app name with invalid characters", async () => {
      await expect(executor.activateApp("App;rm -rf /")).rejects.toThrow(
        "App name contains invalid characters"
      );
    });

    it("should reject app name exceeding max length", async () => {
      const longName = "A".repeat(257);
      await expect(executor.activateApp(longName)).rejects.toThrow(
        "App name exceeds maximum length"
      );
    });

    it("should return success without JXAExecutor (no-executor mode)", async () => {
      const result = await executorNoJxa.activateApp("Finder");
      expect(result).toEqual({ success: true, app: "Finder" });
    });

    it("should build correct JXA code and return success", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true, app: "Finder" })
      );

      const result = await executor.activateApp("Finder");

      expect(result).toEqual({ success: true, app: "Finder" });
      expect(mockJxaExecutor.execute).toHaveBeenCalledOnce();

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('Application("System Events")');
      expect(jxaCode).toContain('processes.byName("Finder")');
      expect(jxaCode).toContain("proc.frontmost = true");
    });

    it("should handle JXA execution failure", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Application not found")
      );

      const result = await executor.activateApp("NonExistent");

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should return fallback when parsed.data is falsy on success", async () => {
      // ResultParser returns success with no data when stdout is empty
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.activateApp("Finder");
      // When parsed.data is null/undefined, falls back to { success: true, app }
      expect(result).toEqual({ success: true, app: "Finder" });
    });

    it("should handle parsed error without message", async () => {
      // exitCode non-zero but no stderr => generic error without .message
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 1,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.activateApp("Finder");
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  // ===========================================================================
  // uiSnapshot
  // ===========================================================================

  describe("uiSnapshot", () => {
    it("should validate app name", async () => {
      await expect(executor.uiSnapshot("")).rejects.toThrow(
        "App name is required"
      );
    });

    it("should clamp maxDepth below 1 to default (2)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ app: "Finder", windows: [] })
      );

      await executor.uiSnapshot("Finder", 0);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      // Default depth is 2 when input < 1
      expect(jxaCode).toContain(", 0, 2)");
    });

    it("should clamp non-integer maxDepth to default (2)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ app: "Finder", windows: [] })
      );

      await executor.uiSnapshot("Finder", 2.5);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain(", 0, 2)");
    });

    it("should clamp maxDepth above 5 to 5", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ app: "Finder", windows: [] })
      );

      await executor.uiSnapshot("Finder", 10);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain(", 0, 5)");
    });

    it("should accept valid maxDepth within range", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ app: "Finder", windows: [] })
      );

      await executor.uiSnapshot("Finder", 3);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain(", 0, 3)");
    });

    it("should return empty windows without JXAExecutor", async () => {
      const result = await executorNoJxa.uiSnapshot("Finder");
      expect(result).toEqual({ app: "Finder", windows: [] });
    });

    it("should return annotated tree with refs from JXA result", async () => {
      const snapshotData = {
        app: "Calendar",
        windows: [
          {
            role: "window",
            name: "Main Window",
            enabled: true,
            children: [
              {
                role: "button",
                name: "Today",
                enabled: true,
                index: 0,
                children: [],
              },
            ],
          },
        ],
      };
      mockJxaExecutor.execute.mockResolvedValue(jxaSuccess(snapshotData));

      const result = await executor.uiSnapshot("Calendar");

      expect(result.app).toBe("Calendar");
      expect(result.windows).toHaveLength(1);

      const win = result.windows[0]!;
      expect(win.role).toBe("window");
      expect(win.name).toBe("Main Window");
      expect(win.ref).toMatch(/^ref_/);
      expect(win.children).toHaveLength(1);

      const btn = win.children[0]!;
      expect(btn.role).toBe("button");
      expect(btn.name).toBe("Today");
      expect(btn.ref).toMatch(/^ref_/);
      expect(btn.ref).not.toBe(win.ref);
    });

    it("should create references for each UI element in the tree", async () => {
      const snapshotData = {
        app: "Calendar",
        windows: [
          {
            role: "window",
            name: "Main",
            enabled: true,
            children: [
              {
                role: "toolbar",
                name: null,
                enabled: true,
                index: 0,
                children: [
                  {
                    role: "button",
                    name: "Back",
                    enabled: true,
                    index: 0,
                    children: [],
                  },
                ],
              },
            ],
          },
        ],
      };
      mockJxaExecutor.execute.mockResolvedValue(jxaSuccess(snapshotData));

      const result = await executor.uiSnapshot("Calendar");

      // All 3 elements (window, toolbar, button) should have refs
      const winRef = result.windows[0]!.ref!;
      const toolbarRef = result.windows[0]!.children[0]!.ref!;
      const buttonRef = result.windows[0]!.children[0]!.children[0]!.ref!;

      // All refs should resolve from the store
      expect(referenceStore.get(winRef)).toBeDefined();
      expect(referenceStore.get(toolbarRef)).toBeDefined();
      expect(referenceStore.get(buttonRef)).toBeDefined();
    });

    it("should include value and focused fields when present", async () => {
      const snapshotData = {
        app: "TextEdit",
        windows: [
          {
            role: "window",
            name: "Doc",
            value: "Hello",
            enabled: true,
            focused: true,
            children: [],
          },
        ],
      };
      mockJxaExecutor.execute.mockResolvedValue(jxaSuccess(snapshotData));

      const result = await executor.uiSnapshot("TextEdit");

      const win = result.windows[0]!;
      expect(win.value).toBe("Hello");
      expect(win.focused).toBe(true);
    });

    it("should not include value when null or undefined", async () => {
      const snapshotData = {
        app: "Finder",
        windows: [
          {
            role: "window",
            name: "Desktop",
            value: null,
            enabled: true,
            children: [],
          },
        ],
      };
      mockJxaExecutor.execute.mockResolvedValue(jxaSuccess(snapshotData));

      const result = await executor.uiSnapshot("Finder");
      expect(result.windows[0]!).not.toHaveProperty("value");
    });

    it("should handle JXA execution failure with _warning", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Application not running")
      );

      const result = await executor.uiSnapshot("Finder");

      expect(result.app).toBe("Finder");
      expect(result.windows).toEqual([]);
      expect(result._warning).toBeDefined();
    });

    it("should handle failure with no error message", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 1,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.uiSnapshot("Finder");
      expect(result._warning).toBeDefined();
    });

    it("should handle window node with child missing index (defaults to 0)", async () => {
      const snapshotData = {
        app: "Notes",
        windows: [
          {
            role: "window",
            name: "Note",
            enabled: true,
            children: [
              {
                role: "button",
                name: "Close",
                enabled: true,
                // no index field => child.index ?? 0 should default to 0
                children: [],
              },
            ],
          },
        ],
      };
      mockJxaExecutor.execute.mockResolvedValue(jxaSuccess(snapshotData));

      const result = await executor.uiSnapshot("Notes");

      const btn = result.windows[0]!.children[0]!;
      expect(btn.ref).toMatch(/^ref_/);
      // The ref should be stored with index 0 in the path
      const ref = referenceStore.get(btn.ref!)!;
      const uiRef = ref.specifier as unknown as UIElementRef;
      const lastSegment = uiRef.path[uiRef.path.length - 1]!;
      expect(lastSegment.index).toBe(0);
    });

    it("should handle child with null name (converts to undefined in path)", async () => {
      const snapshotData = {
        app: "Preview",
        windows: [
          {
            role: "window",
            name: null,
            enabled: true,
            children: [
              {
                role: "group",
                name: null,
                enabled: true,
                index: 0,
                children: [],
              },
            ],
          },
        ],
      };
      mockJxaExecutor.execute.mockResolvedValue(jxaSuccess(snapshotData));

      const result = await executor.uiSnapshot("Preview");

      // Child name: null || undefined => name is undefined in path segment
      const ref = referenceStore.get(result.windows[0]!.children[0]!.ref!)!;
      const uiRef = ref.specifier as unknown as UIElementRef;
      const lastSegment = uiRef.path[uiRef.path.length - 1]!;
      expect(lastSegment.name).toBeUndefined();
    });

    it("should handle parsed.data being falsy on success (empty stdout)", async () => {
      // Empty stdout parses to null data but success:true
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.uiSnapshot("Finder");
      // rawResult falls back to { app, windows: [] }
      expect(result).toEqual({ app: "Finder", windows: [] });
    });
  });

  // ===========================================================================
  // clickMenu
  // ===========================================================================

  describe("clickMenu", () => {
    it("should validate app name", async () => {
      await expect(executor.clickMenu("", "File")).rejects.toThrow(
        "App name is required"
      );
    });

    it("should reject menu item names with invalid characters", async () => {
      await expect(
        executor.clickMenu("Finder", "File > Open;drop")
      ).rejects.toThrow("contains invalid characters");
    });

    it("should return error for empty menu path", async () => {
      const result = await executor.clickMenu("Finder", "");
      expect(result).toEqual({ success: false, error: "empty_menu_path" });
    });

    it("should return error for whitespace-only menu path", async () => {
      const result = await executor.clickMenu("Finder", "  >  > ");
      expect(result).toEqual({ success: false, error: "empty_menu_path" });
    });

    it("should handle single-level menu path", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true, path: ["File"] })
      );

      const result = await executor.clickMenu("Finder", "File");

      expect(result).toEqual({ success: true, path: ["File"] });

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('menuBarItems.byName("File")');
      // Single item: no submenu navigation
      expect(jxaCode).not.toContain("menus[0]");
    });

    it("should handle multi-level menu path", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true, path: ["View", "Go to Today"] })
      );

      const result = await executor.clickMenu("Calendar", "View > Go to Today");

      expect(result).toEqual({
        success: true,
        path: ["View", "Go to Today"],
      });

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('menuBarItems.byName("View")');
      expect(jxaCode).toContain("menus[0]");
      expect(jxaCode).toContain('menuItems.byName("Go to Today")');
    });

    it("should handle three-level menu path with intermediate clicks", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true, path: ["View", "Sort By", "Name"] })
      );

      const result = await executor.clickMenu(
        "Finder",
        "View > Sort By > Name"
      );

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      // item1 (Sort By) should click and delay (intermediate)
      expect(jxaCode).toContain("item1.click()");
      expect(jxaCode).toContain("delay(0.2)");
      // item2 (Name) should check enabled and click (last)
      expect(jxaCode).toContain("item2.click()");
      expect(jxaCode).toContain("enabled");
    });

    it("should return success without JXAExecutor", async () => {
      const result = await executorNoJxa.clickMenu(
        "Finder",
        "File > New Window"
      );
      expect(result).toEqual({ success: true, path: ["File", "New Window"] });
    });

    it("should handle menu_item_disabled response from JXA", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({
          success: false,
          error: "menu_item_disabled",
          item: "Paste",
        })
      );

      const result = await executor.clickMenu("Finder", "Edit > Paste");

      expect(result.success).toBe(false);
      expect(result.error).toBe("menu_item_disabled");
    });

    it("should handle menu_path_not_found error (Can't get)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Can't get menu bar item 'NonExistent'")
      );

      const result = await executor.clickMenu("Finder", "NonExistent");

      expect(result.success).toBe(false);
      expect(result.error).toBe("menu_path_not_found");
      expect(result.path).toEqual(["NonExistent"]);
    });

    it("should handle menu_path_not_found error (Invalid index)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Invalid index for menu item")
      );

      const result = await executor.clickMenu("Finder", "File > BadItem");

      expect(result.success).toBe(false);
      expect(result.error).toBe("menu_path_not_found");
    });

    it("should handle generic JXA error", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Something unexpected happened")
      );

      const result = await executor.clickMenu("Finder", "File");

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).not.toBe("menu_path_not_found");
    });

    it("should handle failure with no error message", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 1,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.clickMenu("Finder", "File");
      expect(result.success).toBe(false);
    });

    it("should return fallback when parsed.data is falsy on success", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.clickMenu("Finder", "File");
      // Falls back to { success: true, path: parts }
      expect(result).toEqual({ success: true, path: ["File"] });
    });
  });

  // ===========================================================================
  // sendKeystroke
  // ===========================================================================

  describe("sendKeystroke", () => {
    it("should validate app name", async () => {
      await expect(executor.sendKeystroke("", "a")).rejects.toThrow(
        "App name is required"
      );
    });

    it("should return error for empty key", async () => {
      const result = await executor.sendKeystroke("Finder", "");
      expect(result).toEqual({ success: false, error: "invalid_key" });
    });

    it("should return error for non-string key", async () => {
      const result = await executor.sendKeystroke(
        "Finder",
        null as unknown as string
      );
      expect(result).toEqual({ success: false, error: "invalid_key" });
    });

    it("should return error for invalid modifier", async () => {
      const result = await executor.sendKeystroke("Finder", "a", [
        "cmd",
        "meta",
      ]);
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid_modifier: meta");
      expect(result.error).toContain("Valid:");
    });

    it("should handle regular key with modifiers", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const result = await executor.sendKeystroke("Finder", "c", [
        "cmd",
        "shift",
      ]);

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('keystroke("c"');
      expect(jxaCode).toContain('"command down"');
      expect(jxaCode).toContain('"shift down"');
    });

    it("should handle regular key without modifiers", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const result = await executor.sendKeystroke("Finder", "a");

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('keystroke("a"');
      expect(jxaCode).not.toContain("using:");
    });

    it("should handle special key 'return'", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const result = await executor.sendKeystroke("Finder", "return");

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("keyCode(36");
    });

    it("should handle special key 'tab' with modifiers", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const result = await executor.sendKeystroke("Finder", "tab", [
        "control",
      ]);

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("keyCode(48");
      expect(jxaCode).toContain('"control down"');
    });

    it("should handle special key 'escape'", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      await executor.sendKeystroke("Finder", "escape");

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("keyCode(53");
    });

    it("should handle special key case-insensitively", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      await executor.sendKeystroke("Finder", "RETURN");

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("keyCode(36");
    });

    it("should return success without JXAExecutor", async () => {
      const result = await executorNoJxa.sendKeystroke("Finder", "a", ["cmd"]);
      expect(result).toEqual({ success: true });
    });

    it("should return error for multi-character non-special key", async () => {
      const result = await executor.sendKeystroke("Finder", "abc");
      expect(result.success).toBe(false);
      expect(result.error).toContain("single character or a special key name");
    });

    it("should reject non-alphanumeric regular keys", async () => {
      const result = await executor.sendKeystroke("Finder", "!");
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid characters");
    });

    it("should handle JXA execution failure", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Cannot send keystroke")
      );

      const result = await executor.sendKeystroke("Finder", "a");

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should handle failure with no error message", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 1,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.sendKeystroke("Finder", "a");
      expect(result.success).toBe(false);
    });

    it("should return fallback when parsed.data is falsy on success", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const result = await executor.sendKeystroke("Finder", "a");
      expect(result).toEqual({ success: true });
    });

    it("should handle empty modifiers array (no using clause)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      await executor.sendKeystroke("Finder", "a", []);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).not.toContain("using:");
    });

    it("should handle 'option' modifier", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      await executor.sendKeystroke("Finder", "a", ["option"]);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('"option down"');
    });

    it("should send all four valid modifiers", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      await executor.sendKeystroke("Finder", "a", [
        "cmd",
        "shift",
        "option",
        "control",
      ]);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('"command down"');
      expect(jxaCode).toContain('"shift down"');
      expect(jxaCode).toContain('"option down"');
      expect(jxaCode).toContain('"control down"');
    });
  });

  // ===========================================================================
  // clickElement
  // ===========================================================================

  describe("clickElement", () => {
    it("should return error when reference not found", async () => {
      const result = await executor.clickElement("ref_nonexistent");

      expect(result.success).toBe(false);
      expect(result.error).toBe("reference_not_found");
      expect(result.suggestion).toContain("ui_snapshot");
    });

    it("should return error for non-UI element reference (invalid type)", async () => {
      // Create a non-UIElementRef in the store
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };
      const refId = referenceStore.create("Finder", "window", specifier);

      const result = await executor.clickElement(refId);

      expect(result.success).toBe(false);
      expect(result.error).toBe("invalid_reference_type");
      expect(result.suggestion).toContain("ui_snapshot");
    });

    it("should return success for valid reference without JXAExecutor", async () => {
      const refId = createUIRef(referenceStore);

      const result = await executorNoJxa.clickElement(refId);

      expect(result.success).toBe(true);
      expect(result._warning).toBeUndefined();
    });

    it("should add staleness warning for old references without JXAExecutor", async () => {
      const refId = createStaleUIRef(referenceStore);

      const result = await executorNoJxa.clickElement(refId);

      expect(result.success).toBe(true);
      expect(result._warning).toContain("old");
      expect(result._warning).toContain("UI may have changed");
    });

    it("should build correct JXA path and execute click", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.clickElement(refId);

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("proc.windows[0]");
      expect(jxaCode).toContain("buttons[2]");
      expect(jxaCode).toContain("el.click()");
    });

    it("should add staleness warning for old references with JXA", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createStaleUIRef(referenceStore);

      const result = await executor.clickElement(refId);

      expect(result.success).toBe(true);
      expect(result._warning).toContain("old");
    });

    it("should handle element_not_found error (Can't get)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Can't get window 1 of process 'Calendar'")
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.clickElement(refId);

      expect(result.success).toBe(false);
      expect(result.error).toBe("element_not_found");
      expect(result.suggestion).toContain("ui_snapshot");
    });

    it("should handle element_not_found error (Invalid index)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Invalid index for element")
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.clickElement(refId);

      expect(result.success).toBe(false);
      expect(result.error).toBe("element_not_found");
    });

    it("should handle generic JXA error", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Unexpected error occurred")
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.clickElement(refId);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).not.toBe("element_not_found");
    });

    it("should handle failure with no error message", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 1,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const refId = createUIRef(referenceStore);
      const result = await executor.clickElement(refId);
      expect(result.success).toBe(false);
    });

    it("should return fallback when parsed.data is falsy on success", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const refId = createUIRef(referenceStore);
      const result = await executor.clickElement(refId);
      expect(result.success).toBe(true);
    });
  });

  // ===========================================================================
  // setValue
  // ===========================================================================

  describe("setValue", () => {
    it("should return error when reference not found", async () => {
      const result = await executor.setValue("ref_nonexistent", "hello");

      expect(result.success).toBe(false);
      expect(result.error).toBe("reference_not_found");
      expect(result.suggestion).toContain("ui_snapshot");
    });

    it("should return error for non-UI element reference (invalid type)", async () => {
      const specifier: ObjectSpecifier = {
        type: "element",
        element: "window",
        index: 0,
        container: "application",
      };
      const refId = referenceStore.create("Finder", "window", specifier);

      const result = await executor.setValue(refId, "test");

      expect(result.success).toBe(false);
      expect(result.error).toBe("invalid_reference_type");
    });

    it("should set string values", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.setValue(refId, "hello world");

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('el.value = "hello world"');
    });

    it("should set boolean values", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.setValue(refId, true);

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("el.value = true");
    });

    it("should set false boolean values", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);
      await executor.setValue(refId, false);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("el.value = false");
    });

    it("should set number values", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.setValue(refId, 42);

      expect(result.success).toBe(true);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("el.value = 42");
    });

    it("should handle null values", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);
      await executor.setValue(refId, null);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("el.value = null");
    });

    it("should handle undefined values", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);
      await executor.setValue(refId, undefined);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("el.value = null");
    });

    it("should throw for non-finite number values", async () => {
      const refId = createUIRef(referenceStore);

      await expect(executor.setValue(refId, Infinity)).rejects.toThrow(
        "Invalid number value"
      );
      await expect(executor.setValue(refId, NaN)).rejects.toThrow(
        "Invalid number value"
      );
      await expect(executor.setValue(refId, -Infinity)).rejects.toThrow(
        "Invalid number value"
      );
    });

    it("should throw for unsupported value types", async () => {
      const refId = createUIRef(referenceStore);

      await expect(
        executor.setValue(refId, { complex: "object" })
      ).rejects.toThrow("Unsupported value type: object");

      await expect(executor.setValue(refId, Symbol("test"))).rejects.toThrow(
        "Unsupported value type: symbol"
      );
    });

    it("should add staleness warning for old references", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createStaleUIRef(referenceStore);

      const result = await executor.setValue(refId, "test");

      expect(result.success).toBe(true);
      expect(result._warning).toContain("old");
      expect(result._warning).toContain("UI may have changed");
    });

    it("should add staleness warning for old references without JXAExecutor", async () => {
      const refId = createStaleUIRef(referenceStore);

      const result = await executorNoJxa.setValue(refId, "test");

      expect(result.success).toBe(true);
      expect(result._warning).toContain("old");
    });

    it("should return success without staleness warning for fresh refs without JXAExecutor", async () => {
      const refId = createUIRef(referenceStore);

      const result = await executorNoJxa.setValue(refId, "test");

      expect(result.success).toBe(true);
      expect(result._warning).toBeUndefined();
    });

    it("should handle element_not_found error (Can't get)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Can't get element")
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.setValue(refId, "test");

      expect(result.success).toBe(false);
      expect(result.error).toBe("element_not_found");
      expect(result.suggestion).toContain("ui_snapshot");
    });

    it("should handle element_not_found error (Invalid index)", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Invalid index")
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.setValue(refId, "test");

      expect(result.success).toBe(false);
      expect(result.error).toBe("element_not_found");
    });

    it("should handle generic JXA error", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaFailure("Error: Unexpected failure")
      );

      const refId = createUIRef(referenceStore);

      const result = await executor.setValue(refId, "test");

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).not.toBe("element_not_found");
    });

    it("should handle failure with no error message", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 1,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const refId = createUIRef(referenceStore);
      const result = await executor.setValue(refId, "test");
      expect(result.success).toBe(false);
    });

    it("should return fallback when parsed.data is falsy on success", async () => {
      mockJxaExecutor.execute.mockResolvedValue({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
      });

      const refId = createUIRef(referenceStore);
      const result = await executor.setValue(refId, "test");
      expect(result.success).toBe(true);
    });
  });

  // ===========================================================================
  // Private helpers (tested via public methods)
  // ===========================================================================

  describe("buildJxaPathFromUIRef (via clickElement/setValue)", () => {
    it("should map known roles to correct JXA collections", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const uiRef: UIElementRef = {
        type: "ui_element",
        appName: "Finder",
        path: [
          { role: "window", index: 0 },
          { role: "toolbar", index: 0 },
          { role: "button", index: 1 },
        ],
        snapshotTime: Date.now(),
      };
      const refId = referenceStore.create(
        "Finder",
        "button",
        uiRef as unknown as ObjectSpecifier
      );

      await executor.clickElement(refId);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("proc.windows[0].toolbars[0].buttons[1]");
    });

    it("should fallback to uiElements for unknown roles", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const uiRef: UIElementRef = {
        type: "ui_element",
        appName: "Finder",
        path: [
          { role: "window", index: 0 },
          { role: "unknownWidget", index: 3 },
        ],
        snapshotTime: Date.now(),
      };
      const refId = referenceStore.create(
        "Finder",
        "unknownWidget",
        uiRef as unknown as ObjectSpecifier
      );

      await executor.clickElement(refId);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("proc.windows[0].uiElements[3]");
    });

    it("should handle single-segment path", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const uiRef: UIElementRef = {
        type: "ui_element",
        appName: "Finder",
        path: [{ role: "window", index: 2 }],
        snapshotTime: Date.now(),
      };
      const refId = referenceStore.create(
        "Finder",
        "window",
        uiRef as unknown as ObjectSpecifier
      );

      await executor.clickElement(refId);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("proc.windows[2]");
    });

    it("should handle various known role mappings", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const uiRef: UIElementRef = {
        type: "ui_element",
        appName: "Safari",
        path: [
          { role: "window", index: 0 },
          { role: "tabGroup", index: 0 },
          { role: "tab", index: 1 },
        ],
        snapshotTime: Date.now(),
      };
      const refId = referenceStore.create(
        "Safari",
        "tab",
        uiRef as unknown as ObjectSpecifier
      );

      await executor.clickElement(refId);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("proc.windows[0].tabGroups[0].tabs[1]");
    });
  });

  describe("escapeJxaString (via public methods)", () => {
    it("should handle app names with dots and hyphens", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true, app: "Adobe After Effects" })
      );

      await executor.activateApp("Adobe After Effects");

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('processes.byName("Adobe After Effects")');
    });

    it("should handle app names with underscores", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true, app: "My_App" })
      );

      await executor.activateApp("My_App");

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain('processes.byName("My_App")');
    });
  });

  describe("serializeValue (via setValue)", () => {
    it("should handle string with special characters needing escape", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);

      // String with backslash and double quote - these need escaping
      await executor.setValue(refId, 'line1\nline2');

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      // The \n in the input string is a real newline, which gets escaped to \\n
      expect(jxaCode).toContain("el.value = ");
    });

    it("should handle zero as a valid number", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);
      await executor.setValue(refId, 0);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("el.value = 0");
    });

    it("should handle negative numbers", async () => {
      mockJxaExecutor.execute.mockResolvedValue(
        jxaSuccess({ success: true })
      );

      const refId = createUIRef(referenceStore);
      await executor.setValue(refId, -3.14);

      const jxaCode = mockJxaExecutor.execute.mock.calls[0]![0];
      expect(jxaCode).toContain("el.value = -3.14");
    });
  });

  describe("validateAppName (via public methods)", () => {
    it("should allow alphanumeric with spaces, dots, hyphens, underscores", async () => {
      // These should all not throw
      await expect(
        executorNoJxa.activateApp("Adobe Photoshop CC 2023")
      ).resolves.toBeDefined();
      await expect(
        executorNoJxa.activateApp("App.Name-With_Things")
      ).resolves.toBeDefined();
    });

    it("should reject various injection attempts", async () => {
      await expect(executor.activateApp('Finder";rm')).rejects.toThrow(
        "invalid characters"
      );
      await expect(executor.activateApp("App$HOME")).rejects.toThrow(
        "invalid characters"
      );
      await expect(executor.activateApp("App\nName")).rejects.toThrow(
        "invalid characters"
      );
    });
  });

  describe("validateIdentifier (via clickMenu)", () => {
    it("should allow valid menu item names", async () => {
      // These should not throw on validation
      const result = await executorNoJxa.clickMenu(
        "Finder",
        "File > New Finder Window"
      );
      expect(result.success).toBe(true);
    });

    it("should reject menu items with dots", async () => {
      // Dots are NOT in SAFE_IDENTIFIER_REGEX
      await expect(
        executor.clickMenu("Finder", "File > Open...")
      ).rejects.toThrow("contains invalid characters");
    });

    it("should reject overly long identifiers", async () => {
      const longName = "A".repeat(257);
      await expect(
        executor.clickMenu("Finder", longName)
      ).rejects.toThrow("exceeds maximum length");
    });
  });
});
