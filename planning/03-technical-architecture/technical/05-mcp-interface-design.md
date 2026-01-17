# MCP Interface Design

## Core Question: Resources vs Tools?

Given the dynamic nature of AppleScript dictionaries, how should we expose capabilities to LLMs?

## Option 1: AppleScript Dictionaries as Resources

### Approach
- Expose each app's parsed dictionary as an MCP Resource
- LLM reads the dictionary to understand what's possible
- LLM constructs AppleScript code
- Execute via a generic `execute_applescript` tool

### Resources Structure
```typescript
// List available apps
Resource: "osa://apps"
{
  apps: [
    { bundleId: "com.apple.finder", name: "Finder", version: "..." },
    { bundleId: "com.apple.Safari", name: "Safari", version: "..." },
    // ...
  ]
}

// Get specific app's dictionary
Resource: "osa://apps/com.apple.finder/dictionary"
{
  commands: [
    {
      name: "open",
      description: "Open the specified object(s)",
      parameters: [
        { name: "target", type: "file", required: true },
        { name: "using", type: "application", required: false }
      ]
    },
    // ...
  ],
  classes: [
    {
      name: "folder",
      properties: [
        { name: "name", type: "text", access: "r" },
        { name: "items", type: "list<item>", access: "r" }
      ]
    }
    // ...
  ]
}
```

### Tools
```typescript
// Single execution tool
Tool: "execute_applescript"
{
  script: string;      // The AppleScript code
  appBundleId: string; // Which app (for permissions)
  timeout?: number;    // Max execution time
}
```

### Pros
- **Flexible**: LLM can construct any valid AppleScript
- **Simple Server**: Just one tool to implement
- **Future-Proof**: Works with any app capability
- **Efficient**: Dictionaries loaded on-demand

### Cons
- **LLM Dependency**: Relies on LLM's ability to write AppleScript
- **Error-Prone**: LLM might generate invalid syntax
- **No Validation**: Can't validate parameters before execution
- **Context Size**: Large dictionaries consume token budget

## Option 2: Dynamic Tool Generation

### Approach
- Parse each app's dictionary
- Generate MCP tools for each command
- LLM calls tools directly with parameters
- Server constructs and executes AppleScript

### Tools Structure
```typescript
// Tools generated per app
Tool: "finder_open"
{
  target: string;  // File path
  using?: string;  // Application to use
}

Tool: "finder_get_items"
{
  folder: string;  // Folder path
  filter?: string; // Optional filter
}

Tool: "safari_open_url"
{
  url: string;
  newWindow?: boolean;
}

// Potentially hundreds of tools...
```

### Pros
- **Type Safety**: Parameter validation before execution
- **Better UX**: Clear tool names and descriptions
- **Error Prevention**: Invalid calls rejected early
- **Discoverable**: LLM can see what's available

### Cons
- **Tool Explosion**: Could be hundreds/thousands of tools
- **MCP Limits**: How many tools can MCP handle?
- **Memory**: All tools loaded at once?
- **Maintenance**: Complex parsing and generation logic
- **Dictionary Complexity**: Some commands have 10+ parameters

## Option 3: Hybrid Approach (Recommended)

### Approach
Combine both strategies:

1. **Resources**: Expose dictionaries for LLM to understand capabilities
2. **Common Tools**: Generate tools for frequently-used commands
3. **Fallback Tool**: Generic `execute_applescript` for everything else

### Structure
```typescript
// Resources for discovery
Resource: "osa://apps"
Resource: "osa://apps/{bundleId}/dictionary"

// Pre-generated common tools
Tool: "finder_list_folder"
Tool: "safari_get_current_url"
Tool: "mail_send_message"
// ~20-50 most common operations

// Fallback for everything else
Tool: "execute_applescript"
{
  script: string;
  appBundleId: string;
}

// Meta tool for app discovery
Tool: "get_app_capabilities"
{
  appBundleId: string;
  format: "summary" | "full"; // Summary = high-level, Full = complete dictionary
}
```

### Pros
- **Best of Both**: Type-safe for common tasks, flexible for rare ones
- **Manageable**: ~50 curated tools instead of 1000s
- **Efficient**: LLM uses simple tools when possible
- **Powerful**: Can still do anything via execute_applescript

### Cons
- **Decision Required**: Which commands to pre-generate?
- **Dual Maintenance**: Both tools and fallback path
- **Potential Confusion**: When to use tool vs custom script?

## Recommended Structure

### Resources (3)
1. `osa://apps` - List all scriptable apps
2. `osa://apps/{id}/dictionary/summary` - High-level capabilities
3. `osa://apps/{id}/dictionary/full` - Complete SDEF parsed

### Core Tools (5-7)
1. `discover_apps` - Trigger app scan, get list
2. `get_app_info` - Get specific app details and capabilities
3. `execute_applescript` - Run arbitrary AppleScript
4. `execute_applescript_file` - Run .scpt file
5. `list_running_apps` - Get currently running apps
6. `validate_script` - Check syntax without executing
7. `search_commands` - Search across all dictionaries

### Optional: Common Command Tools
Generate tools for:
- Finder: list, open, move, copy, trash
- Safari: open URL, get current URL, close tab
- Mail: send message, get inbox count
- System Events: get processes, keystroke, click

Could be enabled/disabled via config:
```json
{
  "generateCommonTools": true,
  "includeApps": ["com.apple.finder", "com.apple.Safari"]
}
```

## Dictionary Parsing Strategy

### SDEF Format
Modern apps use SDEF (XML):
```xml
<dictionary>
  <suite name="Standard Suite">
    <command name="open" code="aevtodoc">
      <cocoa class="NSOpenCommand"/>
      <parameter name="target" type="file" code="----"/>
    </command>
  </suite>
</dictionary>
```

### Parsing Approach
```typescript
interface ParsedDictionary {
  suites: Array<{
    name: string;
    description: string;
    commands: Array<{
      name: string;
      code: string;
      description: string;
      directParameter?: Parameter;
      parameters: Parameter[];
      result?: TypeInfo;
    }>;
    classes: Array<{
      name: string;
      plural?: string;
      description: string;
      properties: Property[];
      elements: Element[];
    }>;
  }>;
}
```

### LLM-Friendly Format
Convert to simplified JSON for resources:
```typescript
{
  app: "Finder",
  categories: {
    "File Operations": [
      { command: "open", args: ["file path"], description: "..." },
      { command: "move", args: ["file", "to folder"], description: "..." }
    ],
    "Navigation": [
      { command: "go to", args: ["folder"], description: "..." }
    ]
  },
  examples: [
    "tell application \"Finder\" to open home folder",
    "tell application \"Finder\" to get name of every file of desktop"
  ]
}
```

## Open Questions

1. What's the optimal number of tools before LLM performance degrades?
2. Should we use tool categorization/namespacing?
3. How to handle apps with multiple dictionaries?
4. Should examples be included in resources or separate?
5. Can we use embeddings to help LLM find relevant commands?
6. Should we cache LLM-friendly dictionary versions?
7. How to version dictionaries when apps update?
