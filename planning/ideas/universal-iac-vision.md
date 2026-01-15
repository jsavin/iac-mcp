# Universal IAC Vision

## The Big Picture

Build a **universal Inter-Application Communication layer** for LLM workflows that works across all major platforms and automation systems.

### What It Is
"What Selenium/Playwright is to browsers, but for application automation"

### What It Enables
LLMs can interact with **any installed application** on **any platform** through a unified MCP interface.

## Platform Targets

### macOS (Phase 1)
**Mechanisms:**
- AppleEvents (low-level message passing)
- AppleScript (high-level scripting)
- JavaScript for Automation (JXA)

**Discovery:**
- SDEF files in .app bundles
- System Events queries

**Example Apps:**
- Finder, Safari, Mail, Calendar, Music
- Adobe Creative Suite
- Microsoft Office
- Development tools (Xcode, VS Code)

### Windows (Phase 2)
**Mechanisms:**
- COM (Component Object Model)
- PowerShell automation
- .NET automation APIs
- Windows Runtime (WinRT)

**Discovery:**
- Registry COM entries
- Type libraries
- PowerShell cmdlets

**Example Apps:**
- Explorer, Edge, Outlook, Office Suite
- Visual Studio
- Adobe apps
- Custom line-of-business apps

### Linux (Phase 3)
**Mechanisms:**
- D-Bus (inter-process communication)
- Shell integration
- Wayland/X11 automation
- Native APIs

**Discovery:**
- D-Bus service introspection
- Desktop entry files
- Service files

**Example Apps:**
- File managers (Nautilus, Dolphin)
- Browsers (Firefox, Chrome)
- Development environments
- System services

### Web/Cloud (Phase 4)
**Mechanisms:**
- REST APIs
- GraphQL
- OAuth integration
- WebSocket connections

**Discovery:**
- OpenAPI/Swagger specs
- GraphQL introspection
- Service directories

**Example Services:**
- SaaS applications
- Cloud platforms
- Internal APIs
- Webhooks

## Cross-Platform Abstraction

### Common Operations
Identify operations that exist across platforms:

```typescript
// File Management
list_files(path: string) → File[]
open_file(path: string)
move_file(source: string, destination: string)
delete_file(path: string)

// Email
send_email(to: string, subject: string, body: string)
get_inbox() → Email[]
search_emails(query: string) → Email[]

// Browser
open_url(url: string)
get_current_url() → string
get_page_content() → string

// Calendar
create_event(title: string, date: DateTime, duration: number)
get_events(start: Date, end: Date) → Event[]
```

### Platform-Specific Extensions
Allow platform-specific capabilities while maintaining common core:

```typescript
// macOS-specific
finder_reveal_in_finder(path: string)

// Windows-specific
explorer_pin_to_taskbar(item: string)

// Linux-specific
nautilus_mount_remote(uri: string)
```

## Architecture Layers

### 1. Platform Adapters (Bottom Layer)
```
┌─────────────────────────────────────┐
│     Platform Adapter Interface      │
├─────────────────────────────────────┤
│ • discoverApplications()            │
│ • getCapabilities(appId)            │
│ • invokeCapability(app, cap, args)  │
└─────────────────────────────────────┘
         ↓          ↓          ↓
   ┌─────────┐ ┌─────────┐ ┌─────────┐
   │  macOS  │ │ Windows │ │  Linux  │
   │ Adapter │ │ Adapter │ │ Adapter │
   └─────────┘ └─────────┘ └─────────┘
```

### 2. Capability Translation (Middle Layer)
```
┌─────────────────────────────────────┐
│      Capability Normalizer          │
├─────────────────────────────────────┤
│ • Map platform types to JSON        │
│ • Normalize operation names         │
│ • Handle platform differences       │
└─────────────────────────────────────┘
```

### 3. MCP Interface (Top Layer)
```
┌─────────────────────────────────────┐
│          MCP Tool Registry          │
├─────────────────────────────────────┤
│ • Generate tools from capabilities  │
│ • Register with MCP server          │
│ • Route calls to platform adapters  │
└─────────────────────────────────────┘
```

## Universal Data Model

### Application
```typescript
interface Application {
  id: string;              // com.apple.finder, Microsoft.Excel, org.gnome.Nautilus
  name: string;            // "Finder", "Excel", "Nautilus"
  platform: Platform;      // "macos" | "windows" | "linux" | "web"
  version: string;
  capabilities: Capability[];
  metadata: {
    vendor: string;
    description: string;
    icon?: string;
  };
}
```

### Capability
```typescript
interface Capability {
  id: string;
  name: string;
  type: "command" | "query" | "property";
  description: string;
  parameters: Parameter[];
  returns?: TypeInfo;
  category?: string;       // "file_operations", "email", "ui_control"
  tags?: string[];         // ["read", "write", "destructive"]
  examples?: string[];
}
```

### Parameter
```typescript
interface Parameter {
  name: string;
  type: UniversalType;
  required: boolean;
  description: string;
  default?: any;
  validation?: ValidationRule[];
}

enum UniversalType {
  String = "string",
  Number = "number",
  Boolean = "boolean",
  Path = "path",           // Platform-aware file path
  URL = "url",
  DateTime = "datetime",
  Array = "array",
  Object = "object",
  Enum = "enum"
}
```

## Platform Adapter Interface

```typescript
interface PlatformAdapter {
  readonly platform: Platform;
  readonly mechanisms: string[];  // ["applescript", "jxa"] or ["com", "powershell"]

  // Discovery
  discoverApplications(): Promise<Application[]>;
  getApplicationInfo(appId: string): Promise<Application>;
  getCapabilities(appId: string): Promise<Capability[]>;

  // Execution
  invokeCapability(
    appId: string,
    capabilityId: string,
    parameters: Record<string, any>
  ): Promise<any>;

  // Lifecycle
  initialize(): Promise<void>;
  shutdown(): Promise<void>;

  // Platform-specific
  getNativeInterface(): any;  // For advanced use cases
}
```

## Implementation Phases

### Phase 1: macOS Foundation
**Goal:** Prove JITD concept on single platform
- Implement macOS adapter (AppleEvents + JXA)
- SDEF parsing and tool generation
- Basic permission system
- 5-10 well-supported apps

**Success Criteria:**
- < 5s discovery time
- > 95% tool execution success rate
- Real users adopting it

### Phase 2: Windows Expansion
**Goal:** Validate cross-platform architecture
- Implement Windows adapter (COM + PowerShell)
- Cross-platform capability mapping
- Unified tool naming conventions
- 5-10 Windows apps

**Success Criteria:**
- Same LLM prompts work on both platforms
- Clean abstraction (no platform leakage)
- Performance parity with macOS

### Phase 3: Linux Support
**Goal:** Complete desktop platform coverage
- Implement Linux adapter (D-Bus)
- Support major desktop environments
- Common Linux applications

### Phase 4: Web/Cloud Integration
**Goal:** Extend beyond desktop
- OpenAPI/Swagger integration
- OAuth flows
- Cloud service connectors
- Hybrid workflows (local + cloud)

### Phase 5: Advanced Features
- Natural language capability search
- Workflow recording and playback
- Cross-app orchestration
- Enterprise deployment
- Usage analytics and optimization

## Business Implications

### Market Expansion
- **macOS only:** ~100M potential users
- **+ Windows:** ~1.4B potential users (14x larger)
- **+ Linux:** +30M developers/power users
- **+ Web/Cloud:** Unlimited integration possibilities

### Differentiation
- **Only universal IAC layer for LLMs**
- Not just "AppleScript for Claude"
- Future-proof architecture
- Platform vendors can't replicate easily

### Revenue Opportunities
- Freemium: Basic apps free, advanced paid
- Enterprise: Team deployment, custom adapters
- Per-platform licensing
- API access for developers
- Workflow marketplace

## Technical Risks

### 1. Type System Impedance
Challenge: Platform type systems are very different
- Solution: Universal type abstraction + adapters

### 2. Discovery Complexity
Challenge: Each platform discovers apps differently
- Solution: Plugin architecture for discoverers

### 3. Execution Model Differences
Challenge: Sync vs async, callbacks, events
- Solution: Promise-based universal interface

### 4. Permission Models
Challenge: Each platform handles permissions differently
- Solution: Unified permission system with platform adapters

### 5. Performance at Scale
Challenge: 10,000+ tools across platforms
- Solution: Lazy loading, smart caching, tool search

## Success Metrics

### Technical
- Discovery time < 10s across all platforms
- Tool execution success rate > 95%
- Cross-platform capability coverage > 80%
- Memory usage < 200MB with full cache

### Business
- Monthly active users across all platforms
- Platform distribution (macOS vs Windows vs Linux)
- Most-used applications and capabilities
- Conversion rate to paid tiers
- Enterprise adoption rate

## The End Game

**Vision:** Every installed application, on every platform, is accessible to LLMs through a single, unified, type-safe interface.

**Impact:** LLMs become universal automation agents that can orchestrate complex workflows across any combination of applications and platforms.

**Moat:** Deep platform knowledge, robust adapters, proven at scale, trusted by users.
