# Tool Explosion Solutions

## The Problem

With JITD, we could easily generate **10,000+ tools** from all installed applications:
- Finder: ~200 commands
- Safari: ~100 commands
- Mail: ~150 commands
- Adobe Photoshop: ~500+ commands
- Microsoft Word: ~300+ commands
- System Events: ~100 commands
- **Total system-wide: 10,000-50,000 tools**

**Challenge:** How do we expose this many tools efficiently without overwhelming the LLM or MCP protocol?

## Solution 1: Lazy Tool Discovery

### Concept
Don't register all tools upfront. Register meta-tools that allow discovery on-demand.

### Implementation
```typescript
// Initial registration (just a few meta-tools)
Tool: discover_applications()
  → Returns list of available apps

Tool: discover_app_capabilities({
  app: string,
  category?: string
})
  → Returns capabilities for specific app
  → Optionally filtered by category

Tool: search_capabilities({
  query: string,
  app?: string
})
  → Natural language search for capabilities
  → "send email with attachment" → mail_send_message
```

### LLM Workflow
```
User: "List files on my desktop"

LLM: Hmm, I need file management capabilities
→ Calls: discover_applications()
→ Gets: ["Finder", "Safari", "Mail", ...]

→ Calls: discover_app_capabilities({ app: "Finder", category: "file_operations" })
→ Gets: [
    { tool: "finder_list_folder", params: {...} },
    { tool: "finder_open_file", params: {...} },
    ...
  ]

→ Calls: finder_list_folder({ path: "~/Desktop" })
→ Success!
```

### Pros
- Fast startup (minimal tools registered)
- Scales to unlimited apps
- Discovery is explicit and trackable

### Cons
- Extra round-trip for discovery
- LLM must know to discover first
- Cold-start problem for every new app

## Solution 2: Smart Filtering

### Concept
Only register "common" or "frequently used" tools initially. Rare tools available on-demand.

### Implementation
```typescript
// Classify tools by frequency
interface ToolMetadata {
  frequency: "common" | "rare" | "advanced";
  category: string;
  safety: "safe" | "requires_confirmation" | "dangerous";
}

// Initial registration: common tools only
const commonTools = [
  "finder_list_folder",
  "finder_open_file",
  "safari_open_url",
  "mail_send_message",
  // ~100-200 most common operations
];

// Register meta-tool for accessing rare/advanced
Tool: execute_advanced_capability({
  app: string,
  capability: string,
  parameters: object
})
```

### Classification Strategy
```typescript
// Frequency based on:
// 1. General usage patterns (open > delete)
// 2. User's historical usage (learn over time)
// 3. App importance (Finder > obscure apps)

function classifyTool(app: string, capability: string): Frequency {
  // Common: operations users do daily
  if (capability.match(/^(list|get|open|send|create)$/)) {
    return "common";
  }

  // Rare: specialized operations
  if (capability.match(/^(export|import|convert|analyze)$/)) {
    return "rare";
  }

  // Advanced: power user features
  return "advanced";
}
```

### Pros
- Balanced: Essential tools available immediately
- Learnable: Can adapt to user's actual usage
- Performant: Limited tool count

### Cons
- Requires good classification heuristics
- Might hide useful tools
- Classification might be wrong for some users

## Solution 3: Hierarchical Tools

### Concept
Create high-level tools that delegate to specific operations. Reduces tool count by grouping related operations.

### Implementation
```typescript
// Instead of 50 finder tools, have a few delegating tools
Tool: finder_file_operation({
  operation: "list" | "open" | "move" | "copy" | "delete" | "get_info",
  path: string,
  destination?: string,  // for move/copy
  filter?: string        // for list
})

Tool: mail_operation({
  operation: "send" | "get_inbox" | "search" | "delete",
  ...parameters
})

Tool: browser_operation({
  operation: "open_url" | "get_current_url" | "close_tab" | "new_window",
  ...parameters
})
```

### Pros
- Drastically reduces tool count (50 → 5)
- Still type-safe (operation is enum)
- Conceptually clean

### Cons
- Less specific tool names
- Complex parameter schemas (lots of optionals)
- LLM must choose operation parameter

## Solution 4: Category-Based Namespacing

### Concept
Organize tools into categories. LLM explores categories first.

### Implementation
```typescript
// Tools organized by category
Tool: file_operations.list_folder({ path: string })
Tool: file_operations.open_file({ path: string })
Tool: email.send({ to, subject, body })
Tool: browser.open_url({ url: string })

// Discovery
Tool: list_categories()
  → ["file_operations", "email", "browser", "calendar", ...]

Tool: list_tools_in_category({ category: string })
  → Returns tools for that category
```

### Pros
- Organized, discoverable
- Natural mental model
- Can load categories on-demand

### Cons
- Still potentially many tools per category
- Categorization not always clear
- Cross-category operations?

## Solution 5: Natural Language Tool Search

### Concept
LLM describes what it wants to do. Server finds matching tools.

### Implementation
```typescript
Tool: find_tools({
  description: string,  // "send email with attachment"
  app?: string,         // optional: narrow to specific app
  limit?: number        // how many results to return
})

// Returns:
{
  tools: [
    {
      name: "mail_send_message",
      confidence: 0.95,
      parameters: { to, subject, body, attachments },
      example: "..."
    },
    // ... more matches
  ]
}
```

### Implementation Details
```typescript
class ToolSearchEngine {
  // Index tools by keywords, descriptions
  private index: Map<string, Tool[]>;

  search(query: string): Tool[] {
    // Simple: keyword matching
    const keywords = this.extractKeywords(query);
    const matches = this.findByKeywords(keywords);

    // Advanced: embedding similarity
    const queryEmbedding = this.embed(query);
    const similar = this.findBySimilarity(queryEmbedding);

    return this.rank(matches, similar);
  }
}
```

### Pros
- Very user-friendly
- Handles ambiguity
- Natural LLM workflow

### Cons
- Requires embeddings or sophisticated search
- Potential for wrong matches
- Extra round-trip

## Solution 6: Usage-Based Optimization

### Concept
Learn which tools are actually used. Prioritize those.

### Implementation
```typescript
interface UsageStats {
  toolName: string;
  callCount: number;
  lastUsed: Date;
  successRate: number;
}

class AdaptiveRegistry {
  // Start with baseline tools
  // Track usage over time
  // Promote frequently-used tools to "always registered"
  // Demote rarely-used tools to "on-demand"

  optimize() {
    const topTools = this.getTopUsed(200);
    this.registerEagerly(topTools);

    const rareTools = this.getRarelyUsed();
    this.registerLazily(rareTools);
  }
}
```

### Pros
- Adapts to actual user behavior
- Optimal for each user
- Improves over time

### Cons
- Cold-start problem (new users have no data)
- Privacy concerns (tracking usage)
- Requires analytics infrastructure

## Recommended Hybrid Approach

Combine multiple strategies:

### Tier 1: Always Registered (~100 tools)
**Universal common operations:**
- Basic file operations (list, open, move, copy)
- Email send/receive
- Browser navigation
- Calendar events
- System info

### Tier 2: App-Specific Common (~200 tools)
**Frequently-used app capabilities:**
- Finder advanced operations
- Mail management
- Browser tabs/bookmarks
- Most-used apps for this user

### Tier 3: Lazy Discovery (All remaining)
**Available via meta-tools:**
```typescript
Tool: discover_capabilities({ app, category })
Tool: search_tools({ query })
Tool: get_app_tools({ app })
```

### Tier 4: Direct Execution
**Fallback for anything:**
```typescript
Tool: execute_raw_capability({
  app: string,
  capability: string,
  parameters: object
})
```

## MCP Protocol Considerations

### Tool Limits
Need to investigate:
- What's the max number of tools MCP can handle?
- Performance degradation with tool count?
- Client (Claude Desktop) limitations?

### Tool Registration
- Can tools be registered dynamically after server starts?
- Can tools be unregistered?
- Does re-registration require server restart?

### Resource Alternative
Instead of tools, could use resources:
```typescript
// Expose capabilities as resources
Resource: "iac://capabilities/all"
Resource: "iac://capabilities/finder"

// Single execution tool
Tool: execute_capability({
  capability_id: string,
  parameters: object
})
```

This keeps tool count at 1, but loses type safety benefits.

## Testing the Limits

### Experiments to Run
1. Register 100 tools → measure performance
2. Register 1000 tools → measure performance
3. Register 10000 tools → does it work?
4. Test lazy discovery flow with real LLM
5. Compare LLM success rate: many specific tools vs few generic tools

### Metrics to Track
- Server startup time
- Memory usage
- Tool call latency
- LLM task success rate
- User satisfaction

## Open Questions

1. What's the optimal number of "always registered" tools?
2. Should we use tool namespacing/prefixes?
3. Can MCP handle dynamic tool registration?
4. Does tool count affect LLM performance?
5. Should discovery be automated or LLM-initiated?
6. How do we handle tool name collisions across apps?
7. What's the best user experience for discovering new capabilities?
