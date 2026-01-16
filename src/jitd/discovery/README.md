# SDEF Discovery Module

This module provides functionality to discover SDEF (Scripting Definition) files in macOS application bundles.

## Overview

SDEF files are XML files that define the scriptable capabilities of macOS applications. They describe:
- Commands that can be executed
- Parameters for each command
- Object classes and their properties
- Enumerations of valid values

This discovery module locates these files so they can be parsed and converted into MCP tools.

## API

### `findSDEFFile(appBundlePath: string): Promise<string | null>`

Finds the SDEF file for a specific application bundle.

```typescript
import { findSDEFFile } from './jitd/discovery';

const sdefPath = await findSDEFFile('/System/Library/CoreServices/Finder.app');
// Returns: '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef'
```

**Parameters:**
- `appBundlePath`: Absolute path to the .app bundle

**Returns:**
- Path to SDEF file if found
- `null` if no SDEF file exists or app bundle not found

**Behavior:**
- Returns `null` for non-existent apps (no error thrown)
- Returns `null` for apps without SDEF files
- Handles permission errors gracefully
- Checks standard location first: `{app}/Contents/Resources/{AppName}.sdef`
- Falls back to searching for any `.sdef` file in Resources directory

### `findAllScriptableApps(options?): Promise<AppWithSDEF[]>`

Discovers all applications with SDEF files on the system.

```typescript
import { findAllScriptableApps } from './jitd/discovery';

const apps = await findAllScriptableApps();
// Returns array of:
// [
//   {
//     appName: 'Finder',
//     bundlePath: '/System/Library/CoreServices/Finder.app',
//     sdefPath: '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef'
//   },
//   ...
// ]
```

**Parameters:**
- `options.useCache`: Whether to use cached results (default: `true`)

**Returns:**
- Array of `AppWithSDEF` objects

**Behavior:**
- Searches common application directories:
  - `/System/Library/CoreServices`
  - `/System/Applications`
  - `/Applications`
  - `~/Applications`
- Filters out apps without SDEF files
- Caches results for 5 minutes (configurable)
- Handles permission errors gracefully (skips inaccessible directories)
- Typically finds 40-60 scriptable apps on a standard macOS system

**Performance:**
- Fast: ~200-300ms for full system scan
- Cached: <1ms for subsequent calls within TTL

### `getSDEFPath(appBundlePath: string): string`

Constructs the expected SDEF file path from an app bundle path.

```typescript
import { getSDEFPath } from './jitd/discovery';

const path = getSDEFPath('/Applications/Safari.app');
// Returns: '/Applications/Safari.app/Contents/Resources/Safari.sdef'
```

This is a utility function that doesn't check if the file actually exists.

### `invalidateCache(): void`

Forces a fresh scan on the next call to `findAllScriptableApps()`.

```typescript
import { invalidateCache, findAllScriptableApps } from './jitd/discovery';

invalidateCache();
const apps = await findAllScriptableApps(); // Will perform fresh scan
```

Use this when:
- New applications are installed
- Applications are updated
- You need guaranteed fresh data

### `isValidSDEFFile(filePath: string): Promise<boolean>`

Validates that a file appears to be an SDEF file (basic XML check).

```typescript
import { isValidSDEFFile } from './jitd/discovery';

const isValid = await isValidSDEFFile('/path/to/file.sdef');
```

**Behavior:**
- Checks if file is readable
- Reads first 100 bytes to check for XML markers
- Looks for `<?xml`, `<dictionary>`, or `<suite>` tags
- Does NOT perform full XML validation (use parser for that)

### `getKnownScriptableApps(): string[]`

Returns a list of well-known scriptable macOS apps.

```typescript
import { getKnownScriptableApps } from './jitd/discovery';

const knownApps = getKnownScriptableApps();
// Returns paths to Finder, Mail, Safari, Calendar, etc.
```

Useful for testing and quick verification.

## Types

### `AppWithSDEF`

```typescript
interface AppWithSDEF {
  appName: string;      // e.g., 'Finder'
  bundlePath: string;   // e.g., '/System/Library/CoreServices/Finder.app'
  sdefPath: string;     // e.g., '.../Finder.app/Contents/Resources/Finder.sdef'
}
```

## Error Handling

The module is designed to be resilient:

- **Non-existent apps**: Returns `null`, does not throw
- **Permission denied**: Logs error, continues with other apps
- **Malformed app bundles**: Returns `null`, does not throw
- **Invalid paths**: Throws `Error` with descriptive message

```typescript
try {
  const sdefPath = await findSDEFFile(userProvidedPath);
  if (sdefPath) {
    // Found SDEF file
  } else {
    // App not found or has no SDEF file
  }
} catch (error) {
  // Only throws for truly invalid inputs (null, empty string, etc.)
  console.error('Invalid path provided:', error);
}
```

## Performance Considerations

### Caching

Results are cached for 5 minutes to avoid repeated filesystem scans:

```typescript
// First call: scans filesystem (~200-300ms)
const apps1 = await findAllScriptableApps();

// Subsequent calls: returns cached results (<1ms)
const apps2 = await findAllScriptableApps();

// Force refresh
invalidateCache();
const apps3 = await findAllScriptableApps(); // Fresh scan
```

### Parallel Discovery

The discovery process is already optimized, but if you need results faster, you can:

1. Use cached results when possible
2. Search specific directories instead of all directories
3. Query specific apps with `findSDEFFile()` instead of scanning all

## Example Usage

### Find SDEF for a specific app

```typescript
import { findSDEFFile } from './jitd/discovery';

async function getFinderSDEF() {
  const sdefPath = await findSDEFFile('/System/Library/CoreServices/Finder.app');

  if (!sdefPath) {
    throw new Error('Finder SDEF not found');
  }

  return sdefPath;
}
```

### Discover all scriptable apps

```typescript
import { findAllScriptableApps } from './jitd/discovery';

async function listScriptableApps() {
  const apps = await findAllScriptableApps();

  console.log(`Found ${apps.length} scriptable apps:`);

  for (const app of apps) {
    console.log(`- ${app.appName}`);
  }
}
```

### Check if specific apps are scriptable

```typescript
import { findSDEFFile } from './jitd/discovery';

async function checkAppScriptability(appPaths: string[]) {
  const results = await Promise.all(
    appPaths.map(async (path) => ({
      path,
      scriptable: (await findSDEFFile(path)) !== null,
    }))
  );

  return results;
}

// Usage
const apps = [
  '/Applications/Safari.app',
  '/Applications/TextEdit.app',
  '/Applications/Calculator.app',
];

const results = await checkAppScriptability(apps);
```

## Testing

Run the test suite:

```bash
npm test
```

Run manual tests with real apps:

```bash
npm run build
node dist/tools/test-discovery.js
```

## Platform Support

**macOS only**: SDEF files are specific to macOS. This module will not work on Windows or Linux.

The module checks `process.platform === 'darwin'` where appropriate.

## Security Considerations

The discovery module implements several security measures:

### Path Traversal Protection
- All constructed paths are validated against their expected boundary directories
- Prevents symlinks or malicious filenames from accessing files outside app bundles
- Uses `normalize()` and `resolve()` to detect traversal attempts

### Filesystem Access
- Validates file readability before attempting to read
- Handles permission errors gracefully without crashing
- Logs security events (path traversal attempts) when logger is provided

### Best Practices
- **Optional Logging**: Use the `logger` parameter to monitor security events in production
- **Cache Safety**: Returned cached arrays are shallow copies to prevent mutation
- **Input Validation**: All paths are validated before filesystem operations

Example with logging:
```typescript
import { findAllScriptableApps, consoleLogger } from './jitd/discovery/find-sdef.js';

const apps = await findAllScriptableApps({ logger: consoleLogger });
```

## Troubleshooting

### findSDEFFile returns null for known scriptable app

**Possible causes:**
- SDEF file doesn't follow standard naming convention (AppName.sdef)
- SDEF file is in non-standard location within app bundle
- File permissions prevent reading
- App bundle structure is malformed

**Solutions:**
1. Check file permissions: `ls -l /path/to/App.app/Contents/Resources/`
2. Look for SDEF file manually: `find /path/to/App.app -name "*.sdef"`
3. Verify app bundle structure has Contents/Resources directories

### Parser returns "Invalid SDEF format"

**Possible causes:**
- SDEF file is not well-formed XML
- Missing required `<dictionary>` root element
- File is corrupted or empty

**Solutions:**
1. Validate XML structure: `xmllint --noout /path/to/file.sdef`
2. Check file size: `ls -lh /path/to/file.sdef`
3. Try parsing with verbose error output to see specific XML error

### Discovery returns empty array

**Possible causes:**
- No scriptable apps installed in common directories
- Permission denied for application directories
- Running on non-macOS system

**Solutions:**
1. Check platform: `echo $OSTYPE` (should be darwin*)
2. Verify apps exist: `ls -la /Applications/*.app`
3. Check for SDEF files: `find /Applications -name "*.sdef" 2>/dev/null`

### Performance issues with discovery

**Symptoms:**
- Discovery takes >5 seconds
- High CPU usage during scan

**Solutions:**
1. Enable caching: `findAllScriptableApps({ useCache: true })` (default)
2. Limit directories by customizing search paths
3. Run discovery in background thread if needed
4. Cache results at application level

## Future Enhancements

Potential improvements for future versions:

1. **Parallel scanning**: Use worker threads for faster discovery
2. **Watch mode**: Monitor filesystem for new/updated apps
3. **Configurable cache TTL**: Allow users to set cache duration
4. **Filter options**: Allow filtering by app name, directory, etc.
5. **AETE support**: Support older apps that use AETE resources instead of SDEF

## See Also

- [SDEF Parser Module](../parser/README.md) - Parses SDEF XML into structured data
- [Tool Generator Module](../tool-generator/README.md) - Converts SDEF to MCP tools
- [Apple SDEF Documentation](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ScriptingDefinitions/)
