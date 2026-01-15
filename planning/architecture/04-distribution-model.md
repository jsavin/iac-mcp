# Distribution Model: Node.js vs macOS App

## The Question
Should OSA MCP be distributed as:
1. A Node.js package (npm install)
2. A native macOS application (.app bundle)
3. Both?

## Option 1: Node.js Package (Pure MCP)

### Pros
- **Standard MCP**: Works exactly like other MCP servers
- **Easy Development**: Fast iteration, standard tooling
- **Claude Desktop Integration**: Direct support via config
- **Developer-Friendly**: Target audience already has Node.js
- **Simple Updates**: `npm update` workflow
- **Cross-Version**: Works with multiple Node versions

### Cons
- **Installation Complexity**: Requires Node.js, command line knowledge
- **No Mac App Store**: Can't reach casual users
- **Limited UI**: No native GUI for configuration
- **Permissions**: Harder to request/manage macOS permissions
- **Discovery**: Not discoverable in App Store
- **Updates**: Users must manually update

### Distribution
```bash
npm install -g osa-mcp
# Or via Claude Desktop config:
# "command": "npx", "args": ["osa-mcp"]
```

## Option 2: Native macOS Application

### Pros
- **Mac App Store**: Huge distribution channel
- **One-Click Install**: Download, drag to Applications
- **Native Permissions**: Proper permission request dialogs
- **Status Bar App**: Always-running, easy access to settings
- **Auto-Updates**: Sparkle framework or App Store updates
- **Professional**: Looks polished, inspires confidence
- **Sandboxing**: App Store sandboxing for security

### Cons
- **MCP Integration**: Needs to expose stdio interface for MCP
- **Development Complexity**: Requires Swift/Objective-C or Electron
- **App Store Review**: Approval process, guidelines compliance
- **Sandboxing Restrictions**: App Store sandbox may limit capabilities
- **Update Latency**: App Store review for each update
- **macOS Only**: Obviously, but that's the point

### Architecture Options

#### 2a: Pure Native (Swift/Objective-C)
- Native macOS app with embedded Node.js runtime
- Pros: Best performance, native feel
- Cons: Complex build, maintaining Node.js bundle

#### 2b: Electron Wrapper
- Electron app wrapping the Node.js MCP server
- Pros: Reuse existing code, easier development
- Cons: Large bundle size, memory usage

#### 2c: Native UI + Node.js Backend
- Swift UI app that spawns Node.js MCP process
- Pros: Best of both worlds
- Cons: Complex IPC, two codebases

## Option 3: Both (Hybrid Approach)

### Architecture
**Core**: Node.js MCP server (shared codebase)
**Wrapper**: Optional macOS app that includes/manages the server

### Distribution Strategy
- **Developers/Power Users**: npm package, manual config
- **General Users**: Mac App Store app
- **Enterprise**: Custom deployment of either

### Benefits
- Maximum reach (developer + consumer markets)
- Single codebase for core functionality
- Flexibility in business model
- A/B test different audiences

### Challenges
- Maintaining two distribution channels
- Version sync between npm and App Store
- Different support expectations
- Potentially confusing to users (which version?)

## Recommendation: Start Node.js, Add macOS App Later

### Phase 1: Node.js Package (MVP)
- **Goal**: Validate core functionality
- **Audience**: Developers, early adopters, Claude Desktop users
- **Timeline**: Fastest to market
- **Learning**: Understand user needs, safety requirements

### Phase 2: macOS App (Growth)
- **Goal**: Reach broader market
- **Audience**: Non-technical users, App Store browsers
- **Timeline**: After core is stable
- **Business**: Enables paid App Store model

### Rationale
1. **Faster Iteration**: Node.js allows rapid development and updates
2. **Prove Concept**: Validate before investing in native development
3. **Community Feedback**: Early users help shape product
4. **MCP Standard**: Align with MCP ecosystem first
5. **Later Transition**: Can wrap Node.js code in app later

## Distribution Scenarios

### For Node.js Package
```json
// Claude Desktop config
{
  "mcpServers": {
    "osa": {
      "command": "npx",
      "args": ["-y", "osa-mcp"]
    }
  }
}
```

### For macOS App
```json
// Claude Desktop config (app runs server)
{
  "mcpServers": {
    "osa": {
      "command": "/Applications/OSA MCP.app/Contents/MacOS/osa-mcp-server"
    }
  }
}
```

Or: App handles Claude Desktop config automatically via installer

## Open Questions

1. Can we get Node.js MCP servers on the Mac App Store? (Answer: Probably no, or very restricted)
2. Should the macOS app _include_ its own Node.js runtime?
3. Is Electron acceptable for a paid app? (Bundle size ~200MB+)
4. Can we use Swift to parse SDEF files more efficiently?
5. What's the right pricing for each distribution channel?
6. Should the App Store version have features the npm version doesn't?
7. How do central rule updates work with App Store review?
