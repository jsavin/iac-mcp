# Troubleshooting Guide

Common issues and solutions for IAC-MCP.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Discovery Issues](#discovery-issues)
3. [Tool Generation Issues](#tool-generation-issues)
4. [Execution Issues](#execution-issues)
5. [MCP Integration Issues](#mcp-integration-issues)
6. [Performance Issues](#performance-issues)
7. [Platform-Specific Issues](#platform-specific-issues)
8. [Debugging Tips](#debugging-tips)

## Installation Issues

### Issue: `npm install` fails with permission errors

**Symptoms:**
```
EACCES: permission denied, mkdir '/usr/local/lib/node_modules/iac-mcp'
```

**Solution:**
```bash
# Option 1: Use nvm to manage Node.js (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 20
nvm use 20

# Option 2: Fix npm permissions
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Issue: TypeScript compilation fails

**Symptoms:**
```
error TS2307: Cannot find module '@modelcontextprotocol/sdk'
```

**Solution:**
```bash
# Clean and reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Rebuild
npm run clean
npm run build
```

### Issue: Node.js version too old

**Symptoms:**
```
❌ Node.js 20+ required, found: v16.x.x
```

**Solution:**
```bash
# Upgrade Node.js using nvm
nvm install 20
nvm use 20
nvm alias default 20

# Verify version
node --version  # Should show v20.x.x or higher
```

## Discovery Issues

### Issue: No apps discovered

**Symptoms:**
```bash
$ npm run cli:discover
Found 0 scriptable applications
```

**Diagnosis:**
```bash
# Check if apps exist
ls -la /Applications/*.app/Contents/Resources/*.sdef
ls -la /System/Library/CoreServices/*.app/Contents/Resources/*.sdef

# Run with verbose logging
npm run cli:discover -- --verbose
```

**Solutions:**

1. **Apps are not scriptable:**
   - Not all macOS apps have SDEF files
   - Check if the app you're looking for supports AppleScript
   - See [list of common scriptable apps](QUICK-START.md#supported-applications)

2. **Permission issues:**
   ```bash
   # Grant Terminal full disk access
   # System Settings → Privacy & Security → Full Disk Access
   # Add Terminal.app (or your terminal emulator)
   ```

3. **Path issues:**
   - SDEF files must be in `Contents/Resources/*.sdef`
   - Some apps store SDEF files in non-standard locations
   - Check app bundle structure: `open /Applications/SomeApp.app`

### Issue: Some apps not discovered

**Symptoms:**
```bash
Found 8 apps, but missing Safari
```

**Diagnosis:**
```bash
# Check if Safari has SDEF
ls -la /Applications/Safari.app/Contents/Resources/*.sdef

# Expected output:
# /Applications/Safari.app/Contents/Resources/Safari.sdef
```

**Solutions:**

1. **App is in different location:**
   ```bash
   # System apps may be in /System/Library/
   ls -la /System/Library/CoreServices/Safari.app/Contents/Resources/*.sdef
   ```

2. **Discovery paths not configured:**
   - Edit `src/jitd/discovery/app-discovery.ts`
   - Add custom search paths

3. **Symlink issues:**
   - Some apps are symlinked
   - Check with: `ls -l /Applications/Safari.app`
   - Solution: Discovery handles symlinks automatically

## Tool Generation Issues

### Issue: Tools not generated for discovered app

**Symptoms:**
```bash
Found Finder, but no tools generated
```

**Diagnosis:**
```bash
# Test tool generation manually
npm run cli:test Finder

# Check SDEF file directly
cat /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef
```

**Solutions:**

1. **Malformed SDEF file:**
   - Some SDEF files have XML errors
   - Check error logs for parsing errors
   - File issue on GitHub with app name

2. **Empty suites:**
   - SDEF file may have no commands
   - Verify with: `grep '<command' Finder.sdef`
   - Expected: multiple `<command>` tags

3. **Parser errors:**
   ```bash
   # Enable verbose logging
   npm run cli:test Finder -- --verbose

   # Check for parser warnings
   ```

### Issue: Generated tools have wrong types

**Symptoms:**
```
Parameter expects string but got number
```

**Diagnosis:**
```bash
# Check generated tool schema
npm run cli:test Finder -- --verbose

# Look for parameter types in output
```

**Solutions:**

1. **Type mapping issue:**
   - Edit `src/jitd/tool-generation/type-mapper.ts`
   - Add mapping for missing type
   - See [ARCHITECTURE.md](ARCHITECTURE.md#type-mapping)

2. **SDEF type ambiguity:**
   - Some SDEF types map to multiple JSON types
   - Check SDEF: `<parameter type="..."/>`
   - May need manual override

## Execution Issues

### Issue: Tool execution times out

**Symptoms:**
```
Error: Command timed out after 30000ms
```

**Solutions:**

1. **Increase timeout:**
   ```bash
   # Set timeout to 60 seconds
   export IAC_MCP_TIMEOUT=60000
   npm start
   ```

2. **App not responding:**
   - Force quit the app
   - Relaunch the app
   - Try command again

3. **Command is slow:**
   - Some AppleScript commands are inherently slow
   - Consider breaking into smaller operations

### Issue: "Application not running" error

**Symptoms:**
```
Error: Finder is not running
```

**Solutions:**

1. **Launch app first:**
   ```bash
   # Some apps must be running
   open -a Finder
   ```

2. **App crashed:**
   - Check Activity Monitor
   - Relaunch app
   - Check Console.app for crash logs

3. **Permissions:**
   - Grant Automation permissions
   - System Settings → Privacy & Security → Automation
   - Enable Terminal → Finder

### Issue: "Permission denied" error

**Symptoms:**
```
Error: Not authorized to send Apple events to Finder
```

**Solutions:**

1. **Grant Automation permission:**
   ```bash
   # System Settings → Privacy & Security → Automation
   # Enable Terminal (or your app) → Finder
   ```

2. **Reset permissions:**
   ```bash
   # Reset all permissions (macOS only)
   tccutil reset AppleEvents

   # Restart app
   npm start
   ```

3. **Code signing issue:**
   - Unsigned apps may be blocked
   - Use a signed terminal emulator
   - Or disable Gatekeeper (not recommended)

### Issue: Invalid parameter format

**Symptoms:**
```
Error: Expected file path, got string
```

**Solutions:**

1. **Check parameter type:**
   - Review tool schema: `npm run cli:test AppName -- --verbose`
   - Verify expected format

2. **Marshal parameter correctly:**
   - File paths: use absolute paths
   - Dates: use ISO 8601 format
   - Arrays: use JSON array syntax

3. **Escape special characters:**
   ```bash
   # Spaces in paths
   /Users/jake/My\ Documents

   # Or use quotes
   "/Users/jake/My Documents"
   ```

## MCP Integration Issues

### Issue: Claude Desktop doesn't see tools

**Symptoms:**
- Server starts but no tools appear in Claude Desktop
- "No tools available" message

**Diagnosis:**
```bash
# Check Claude Desktop config
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Expected:
{
  "mcpServers": {
    "iac-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/iac-mcp/dist/index.js"]
    }
  }
}
```

**Solutions:**

1. **Fix config path:**
   ```json
   {
     "mcpServers": {
       "iac-mcp": {
         "command": "node",
         "args": ["/Users/jake/dev/jsavin/iac-mcp/dist/index.js"]
       }
     }
   }
   ```

2. **Rebuild project:**
   ```bash
   npm run build
   ```

3. **Restart Claude Desktop:**
   - Quit Claude Desktop completely
   - Relaunch
   - Tools should appear

4. **Check server logs:**
   ```bash
   # Enable logging
   export IAC_MCP_LOG_LEVEL=debug
   npm start
   ```

### Issue: Tools listed but execution fails

**Symptoms:**
```
Tool call failed: Internal server error
```

**Diagnosis:**
```bash
# Check server logs in Claude Desktop
# View → Developer → Toggle Developer Tools → Console

# Look for errors
```

**Solutions:**

1. **Check error logs:**
   - Review error messages
   - Common issues: permissions, app not running, invalid parameters

2. **Test tool manually:**
   ```bash
   # Use MCP Inspector
   npx @modelcontextprotocol/inspector node dist/index.js

   # Try executing the tool
   ```

3. **Verify app is accessible:**
   ```bash
   # Test with osascript
   osascript -e 'tell application "Finder" to get name of startup disk'
   ```

## Performance Issues

### Issue: Slow startup (>10 seconds)

**Diagnosis:**
```bash
# Time startup
time npm start

# Should be <10s on first run, <2s on subsequent runs
```

**Solutions:**

1. **Cache not working:**
   ```bash
   # Check cache directory
   ls -la ~/.iac-mcp/cache/

   # Should see tool-cache.json
   ```

2. **Too many apps:**
   - Discovery scans all apps
   - Consider filtering to specific apps (future feature)

3. **Slow filesystem:**
   - SSD recommended
   - Check disk performance: `diskutil info /`

### Issue: High memory usage

**Symptoms:**
```
Memory usage >500MB
```

**Diagnosis:**
```bash
# Check memory usage
ps aux | grep node

# Expected: <100MB for typical usage
```

**Solutions:**

1. **Too many tools cached:**
   ```bash
   # Clear cache
   rm -rf ~/.iac-mcp/cache/

   # Restart
   npm start
   ```

2. **Memory leak:**
   - File issue on GitHub
   - Include memory profile
   - Restart server as workaround

## Platform-Specific Issues

### macOS

#### Issue: "osascript not found"

**Solution:**
```bash
# osascript is built-in on macOS
# If missing, reinstall macOS command-line tools
xcode-select --install
```

#### Issue: Gatekeeper blocks execution

**Solution:**
```bash
# Allow unsigned apps (temporary)
sudo spctl --master-disable

# After testing, re-enable
sudo spctl --master-enable
```

#### Issue: SIP (System Integrity Protection) issues

**Solution:**
- Don't disable SIP
- Grant proper permissions instead
- See [Security](QUICK-START.md#security--permissions)

### Windows (Future)

Placeholder for Windows-specific issues.

### Linux (Future)

Placeholder for Linux-specific issues.

## Debugging Tips

### Environment Variables

| Variable | Description | Values |
|----------|-------------|--------|
| `IAC_MCP_LOG_LEVEL` | General logging verbosity | `error`, `warn`, `info`, `debug` |
| `IAC_MCP_DEBUG_REFS` | Reference lifecycle logging | `true` to enable |
| `IAC_MCP_TIMEOUT` | Command execution timeout (ms) | Default: `30000` |
| `IAC_MCP_CACHE_DIR` | Cache directory location | Default: `~/.iac-mcp/cache` |

### Enable Verbose Logging

```bash
# Set log level
export IAC_MCP_LOG_LEVEL=debug

# Run with verbose flag
npm run cli:discover -- --verbose
```

### Enable Reference Lifecycle Logging

For debugging stateful query issues (reference creation, expiration, cleanup):

```bash
export IAC_MCP_DEBUG_REFS=true
npm start
```

This logs to stderr:
- `created`: reference ID, app, type, specifier type
- `not_found`: attempted ID lookup that failed
- `touched`: reference ID, age since creation
- `expired`: reference ID, TTL exceeded
- `cleanup_complete`: count removed, count remaining

### Use MCP Inspector

```bash
# Install inspector
npm install -g @modelcontextprotocol/inspector

# Run with inspector
npx @modelcontextprotocol/inspector node dist/index.js

# Test tools interactively
```

### Check System Logs

```bash
# macOS Console.app
open -a Console

# Filter for "iac-mcp" or "osascript"
```

### Test Individual Components

```bash
# Test discovery
npm run cli:discover

# Test tool generation
npm run cli:test Finder

# Test execution (via inspector)
npx @modelcontextprotocol/inspector node dist/index.js
```

### Verify Environment

```bash
# Check Node.js version
node --version  # Should be v20+

# Check npm version
npm --version

# Check platform
uname -a

# Check permissions
ls -la /Applications/Safari.app/Contents/Resources/
```

### Common Debug Workflow

1. **Identify component:**
   - Discovery? Tool generation? Execution?

2. **Enable verbose logging:**
   ```bash
   export IAC_MCP_LOG_LEVEL=debug
   ```

3. **Test in isolation:**
   ```bash
   npm run cli:discover  # Discovery
   npm run cli:test Finder  # Generation
   # Inspector for execution
   ```

4. **Check logs:**
   - Terminal output
   - Claude Desktop console
   - System logs (Console.app)

5. **File issue:**
   - Include logs
   - Include system info
   - Include reproduction steps

## Getting Help

### Before Filing an Issue

1. Check this troubleshooting guide
2. Review [QUICK-START.md](QUICK-START.md)
3. Search existing issues on GitHub
4. Test with MCP Inspector

### Filing an Issue

**Include:**
- Operating system and version
- Node.js version (`node --version`)
- IAC-MCP version (`npm run cli -- --version`)
- Error message (full text)
- Reproduction steps
- Relevant logs (with `--verbose`)

**Template:**
```markdown
## Environment
- OS: macOS 14.2.1
- Node.js: v20.10.0
- IAC-MCP: v0.1.0

## Issue
Brief description

## Steps to Reproduce
1. Run `npm run cli:discover`
2. ...

## Expected Behavior
Should discover 10+ apps

## Actual Behavior
Found 0 apps

## Logs
```
[paste logs here]
```

## Additional Context
Any other relevant information
```

### Community Support

- GitHub Discussions
- Issue tracker
- Documentation

## Appendix: Error Categories

| Category | Common Causes | Solutions |
|----------|---------------|-----------|
| Discovery | Permissions, missing apps | Check Full Disk Access |
| Parsing | Malformed SDEF | File bug with app name |
| Generation | Type mapping | Update type-mapper.ts |
| Execution | Permissions, timeout | Grant Automation access |
| MCP | Config, path | Check config.json |

## Appendix: Log Levels

- `error`: Critical errors only
- `warn`: Warnings and errors
- `info`: Normal operations (default)
- `debug`: Verbose debugging

Set with:
```bash
export IAC_MCP_LOG_LEVEL=debug
```
