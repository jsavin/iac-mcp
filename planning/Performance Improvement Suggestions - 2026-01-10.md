Suggestions from Claude about how to improve performance of the MCP server.

**Prompt**: “From the perspective of the MCP server's design, what recommendations do you have as the consumer of the tools and objects it exposes for making working with it faster, more predictable, and more capable?”

**Response**:

Great question — I have a lot of thoughts on this after our session. Here are my recommendations, roughly ordered by impact:

**1. Batch property fetching across elements**

This is the single biggest performance issue. Getting the names of 9 menu bar items required 9 separate `get_properties` calls. There should be a `get_elements_with_properties` call that returns elements and their key properties in one shot. Something like: "get all menuBarItems of this menu bar, and include their name and enabled status." This alone would cut the number of round-trips by 5-10x for common exploration tasks.

**2. A universal `activate` command**

Every session will likely start with activating an app. Right now I have to figure out whether the app has its own `activate` command (Finder does, Brave doesn't), and if not, fall back to the System Events process route (which requires knowing that pattern). A top-level `activate_app` command that handles this logic internally would save multiple round-trips and eliminate a confusing failure mode.

**3. Clearer specifier documentation and examples**

I struggled significantly with specifier syntax. I tried `{"type": "named", "element": "application", ...}` before you told me `{"type": "application"}` was correct. The tool descriptions show patterns for child elements (mailboxes, folders) but not the application object itself. A few concrete examples embedded in the tool description for the most common patterns would help a lot — especially "how to reference the application itself" since that's always the starting point.

**4. Element type naming normalization**

`"menu bar"` failed with a syntax error but `"menuBar"` worked. The object model reports element names with spaces ("menu bar", "menu bar item", "static text"), but the API apparently needs camelCase. Either accept both formats or document which format is expected. This kind of silent mismatch is hard for me to debug since the error message was a JXA syntax error, not a clear "invalid element type" message.

**5. A `describe_ui` or `snapshot` command**

For UI automation, the most common task is "tell me what's on screen." A single call that returns a shallow tree of the current window's UI elements with their names, types, and enabled states would be transformative. Right now, exploring a window requires: get elements → for each element, get properties → for interesting elements, get children → repeat. That's dozens of calls just to understand what I'm looking at.

**6. Common action shortcuts**

Certain operations are done so frequently they deserve dedicated shortcuts that collapse multiple steps into one:

- `activate_app(name)` — as mentioned above
- `click_menu(app, menuPath)` — e.g., `click_menu("BusyCal", "View > Go to Today")` instead of: get menu bar → get menu bar items → find "View" → get its menu → get menu items → find "Go to Today" → click it (6+ calls)
- `send_keystroke(app, keystroke, modifiers)` — activate app and send keystroke in one call

**7. Pre-load app tools implicitly**

Having to call `get_app_tools` before `execute_app_command` is a friction point. If `execute_app_command` could auto-load tools on first use (or if the server cached them), that would save a call every time I work with a new app. Alternatively, the requirement could be documented more prominently — I only discovered it because you told me.

**8. Richer error messages with suggestions**

When `set_property` on `frontmost` succeeded but didn't actually activate Brave, there was no indication that this approach doesn't work for some apps. When specifier syntax was wrong, the errors were sometimes JXA stack traces rather than actionable guidance. Errors that say "did you mean X?" or "for this app, try Y instead" would help me self-correct without user intervention.

**9. Property type hints in responses**

When `get_properties` returns values, include type information. Knowing that a property is a boolean vs. an enum vs. a reference helps me construct the right `set_property` call without trial and error.

**10. Reference lifetime management**

References expire after 15 minutes, which is fine, but I had to re-query after you restarted the MCP server. A way to check if a reference is still valid (without the overhead of a full query) would help, or the ability to create "persistent" references by path (like "process 'Brave Browser' of application 'System Events'") that auto-resolve.

The theme across all of these is **reducing round-trips**. As an LLM, every tool call has significant latency (network + execution + response parsing). The current design is very "Unix philosophy" — small composable primitives — which is elegant but painful when each composition step costs 2-5 seconds. The highest-leverage changes are the ones that collapse common multi-step workflows into single calls.