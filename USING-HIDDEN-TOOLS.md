# Using Hidden Tools in Claude Desktop

## Quick Answer

**Yes, you can use tools from apps not shown in Claude's UI picker!**

The ~18 app limit in Claude Desktop's UI is just for visual convenience. Claude actually has access to **all 405 tools** from 53 apps.

## How to Use Hidden Tools

### Method 1: Ask Claude what tools it has

```
What tools do you have from Hammerspoon?
```

Claude will list all available Hammerspoon tools, even if Hammerspoon doesn't appear in the UI picker.

### Method 2: Call the tool directly by name

```
Use the viscosity_count tool to count VPN connections.
```

Claude will recognize the tool and execute it (if Viscosity is installed and running).

### Method 3: Natural language (Claude figures it out)

```
Can you control my Moom window manager?
```

Claude will check its available tools and tell you what Moom commands it can execute.

## Example: Hidden Apps You Can Control

Here are some apps that may not be in the visible 18, but ARE available:

### Hammerspoon (2 tools)
```
hammerspoon_quit
hammerspoon_reload_configuration
```

**Try:**
```
Reload my Hammerspoon configuration
```

### BeardedSpice (3 tools)
```
beardedspice_playpause
beardedspice_next_track
beardedspice_previous_track
```

**Try:**
```
Pause my music using BeardedSpice
```

### Viscosity (5 tools)
```
viscosity_count
viscosity_open
viscosity_quit
viscosity_close
viscosity_delete
```

**Try:**
```
How many VPN connections do I have in Viscosity?
```

### SuperDuper! (10 tools)
```
superduper_open
superduper_quit
superduper_close
superduper_count
superduper_delete
... and more
```

**Try:**
```
List my SuperDuper backup scripts
```

### MindNode (12 tools)
```
mindnode_open
mindnode_close
mindnode_save
mindnode_count
mindnode_quit
... and more
```

**Try:**
```
Open a specific mind map in MindNode
```

### Moom (19 tools)
```
moom_open
moom_close
moom_count
moom_quit
moom_exists
... and more
```

**Try:**
```
Arrange my windows using Moom
```

## Complete List of Apps

To see all 53 apps with tools, ask Claude:

```
List all apps you have tools for, with tool counts.
```

## Why This Works

1. **MCP server discovers all 53 scriptable apps**
2. **Server generates all 405 tools** from their SDEF files
3. **Claude receives ALL 405 tools** when it starts up
4. **UI shows only ~18 apps** for convenience (prevents clutter)
5. **Claude can call ANY tool** by name, regardless of UI visibility

Think of it like this:
- **UI picker** = Quick shortcuts to most-used apps (18 shown)
- **Claude's memory** = Complete tool catalog (all 405 available)

## Tips

### ✅ Do This

```
# Ask Claude what it can do
What tools do you have from [app name]?

# Call tools directly by name
Use the [app]_[command] tool to do something

# Use natural language - Claude knows its tools
Can you control my [app name]?
```

### ❌ Don't Assume

```
# Don't assume UI picker shows everything
"I only see 18 apps, so those are the only ones available"

# Don't assume hidden = unavailable
"The app isn't in the picker, so Claude can't control it"
```

## Troubleshooting

### "Claude says it doesn't have that tool"

**Possible reasons:**

1. **App not installed** - Claude can only control apps you have installed
2. **App not scriptable** - Only apps with AppleScript support work
3. **Tool name wrong** - Ask Claude "what tools do you have from [app]?"

### "Tool exists but execution fails"

**Possible reasons:**

1. **App not running** - Some tools require the app to be open
2. **Permissions needed** - macOS may need accessibility/automation permissions
3. **Invalid arguments** - Check what parameters the tool needs

### "Claude doesn't recognize the app name"

**Try these:**

```
# Try full app name
What tools do you have from "SuperDuper!"?

# Try common name
What tools do you have from Hammerspoon?

# Ask Claude to search
Search your available tools for "backup" or "window"
```

## Verification

Want to prove this to yourself? Try these tests:

### Test 1: Ask about a specific hidden app
```
Do you have tools for Hammerspoon?
```

**Expected:** Claude says "Yes" and lists tools.

### Test 2: Call a hidden tool
```
Use the hammerspoon_reload_configuration tool.
```

**Expected:** Claude attempts to execute it (may fail if Hammerspoon not running, but should recognize the tool).

### Test 3: Compare UI vs. Claude's knowledge
```
List ALL apps you have tools for.
```

**Expected:** Claude lists ~50+ apps (way more than the 18 in UI).

## Summary

### 🎉 You have access to ALL 405 tools from 53 apps!

- ✅ UI shows ~18 most tool-rich apps (convenience)
- ✅ Claude knows about ALL apps and tools
- ✅ Just ask Claude by name - it'll work
- ✅ Natural language works too - Claude figures it out

Don't let the UI picker limit you. Claude has way more tools available than what's shown!

---

**Want more details?** See `VERIFICATION-SUMMARY.md` for technical proof.
