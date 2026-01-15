# Application Discovery and Caching

## Requirements

### Initial Discovery
- **First Startup**: Offer to scan installed applications
- **User Choice**: Allow user to skip or defer initial scan
- **Progress Feedback**: Show scanning progress (X of Y apps scanned)
- **Incremental**: Allow cancellation and resume later

### Automatic Updates
- **Installation Detection**: Detect when new apps are installed
- **Upgrade Detection**: Detect when apps are updated (may have new AppleScript features)
- **Removal Detection**: Clean up cache when apps are uninstalled
- **Efficient**: Minimal performance impact on system

### Manual Triggering
- **User-Directed**: "Add support for [App Name]"
- **Immediate**: Priority scanning for specific apps
- **Validation**: Verify app exists and is scriptable

## Technical Approaches

### Discovery Methods

#### Option 1: System_profiler + Spotlight
```bash
system_profiler SPApplicationsDataType -json
# + Check for SDEF file in bundle
```
- Pros: Comprehensive, official API
- Cons: Slow for full scans

#### Option 2: LaunchServices Database
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump
```
- Pros: Fast, complete
- Cons: Parsing required, private API concerns

#### Option 3: File System Scanning
```bash
find /Applications /System/Applications ~/Applications -name "*.app" -maxdepth 3
# Then check each for SDEF
```
- Pros: Simple, reliable
- Cons: Slow, misses some locations

**Recommended**: Combination of 1 and 3, with caching

### Change Detection

#### Option 1: FSEvents API (via Node.js)
- Monitor `/Applications`, `/System/Applications`, `~/Applications`
- React to file creation/modification/deletion
- Pros: Real-time, efficient
- Cons: Requires native Node module or ffi

#### Option 2: Periodic Polling
- Check known app directories every N minutes
- Compare modification times
- Pros: Simple, cross-platform
- Cons: Delayed updates, wasted cycles

#### Option 3: macOS Launch Services Notifications
- Subscribe to app installation notifications
- Pros: Native, efficient
- Cons: Requires Swift/Objective-C bridge

**Recommended**: Start with FSEvents (using `chokidar` or `nsfw` npm package), fallback to polling

### Cache Structure

```typescript
interface AppCache {
  version: string;
  lastScan: Date;
  apps: {
    [bundleId: string]: {
      name: string;
      path: string;
      bundleId: string;
      version: string;
      lastModified: Date;
      sdefPath: string;
      parsedDictionary: ScriptingDictionary;
      capabilities: string[]; // High-level summary
      lastParsed: Date;
    }
  }
}
```

**Storage**: JSON file in user's home directory or app support folder
- `~/Library/Application Support/osa-mcp/app-cache.json`

### Performance Considerations

- **Lazy Parsing**: Cache app list, parse SDEF on-demand
- **Incremental Updates**: Only re-parse changed apps
- **Background Processing**: Don't block MCP server startup
- **LRU Strategy**: Parse most-used apps first

## Open Questions

1. Should we scan nested apps (e.g., apps inside other apps)?
2. How to handle apps with multiple SDEF files?
3. Should we cache apps without SDEF files (for error messaging)?
4. What's the performance target for full system scan?
5. Should users be able to manually hide/ignore certain apps?
