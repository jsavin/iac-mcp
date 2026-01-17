# Manual Testing Checklist

This document provides comprehensive manual testing procedures for the iac-mcp server. Use this checklist to verify all functionality works correctly before releasing new versions.

## Prerequisites

Before testing:
- [ ] Project is built: `npm run build`
- [ ] Node.js 20+ is installed: `node --version`
- [ ] MCP Inspector is available: `npx @modelcontextprotocol/inspector`
- [ ] Claude Desktop is installed (for integration testing)

## Test Environment Setup

### 1. Build Verification
```bash
cd /path/to/iac-mcp
npm install
npm run build
```

**Expected Results:**
- [ ] No TypeScript compilation errors
- [ ] `dist/` directory created
- [ ] `dist/index.js` exists and is executable

### 2. MCP Inspector Setup
```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

**Expected Results:**
- [ ] Inspector opens in browser
- [ ] Server connects successfully
- [ ] No startup errors in console

## Core Functionality Tests

### Test Suite 1: Server Startup and Shutdown

#### Test 1.1: Server Starts Successfully
**Steps:**
1. Run: `node dist/index.js`
2. Observe stderr output

**Expected Results:**
- [ ] Logs show: "Starting iac-mcp server..."
- [ ] Logs show: "Server version: 0.1.0"
- [ ] Logs show: "Node version: [version]"
- [ ] Logs show: "Platform: darwin"
- [ ] Logs show: "iac-mcp server started successfully"
- [ ] Logs show: "Listening on stdio transport"
- [ ] Logs show: "Server ready to accept requests"
- [ ] No error messages appear
- [ ] Server remains running (doesn't exit)

#### Test 1.2: Graceful Shutdown (SIGINT)
**Steps:**
1. Start server: `node dist/index.js`
2. Press Ctrl+C

**Expected Results:**
- [ ] Logs show: "Received SIGINT, shutting down gracefully..."
- [ ] Logs show: "Server closed successfully"
- [ ] Process exits with code 0
- [ ] No error messages

#### Test 1.3: Graceful Shutdown (SIGTERM)
**Steps:**
1. Start server: `node dist/index.js`
2. In another terminal: `pkill -TERM -f "node dist/index.js"`

**Expected Results:**
- [ ] Logs show: "Received SIGTERM, shutting down gracefully..."
- [ ] Logs show: "Server closed successfully"
- [ ] Process exits cleanly

### Test Suite 2: MCP Protocol - ListTools

#### Test 2.1: List Tools via MCP Inspector
**Steps:**
1. Open MCP Inspector: `npx @modelcontextprotocol/inspector node dist/index.js`
2. Click "List Tools" button

**Expected Results:**
- [ ] Server logs: "ListTools request received"
- [ ] Server logs: "Returning 1 tool(s)"
- [ ] Inspector shows tool list
- [ ] Tool name: "example_tool"
- [ ] Tool description exists
- [ ] Input schema shows "message" parameter
- [ ] "message" parameter is required
- [ ] Parameter type is "string"

#### Test 2.2: Verify Tool Schema Structure
**Steps:**
1. In MCP Inspector, examine tool schema details

**Expected Results:**
- [ ] inputSchema.type = "object"
- [ ] inputSchema.properties.message exists
- [ ] inputSchema.properties.message.type = "string"
- [ ] inputSchema.properties.message.description exists
- [ ] inputSchema.required = ["message"]

### Test Suite 3: MCP Protocol - CallTool

#### Test 3.1: Call Example Tool (Valid Input)
**Steps:**
1. In MCP Inspector, select "example_tool"
2. Enter JSON: `{"message": "Hello World"}`
3. Click "Call Tool"

**Expected Results:**
- [ ] Server logs: "CallTool request: example_tool"
- [ ] Server logs include arguments: {"message": "Hello World"}
- [ ] Server logs: "Tool execution successful: example_tool"
- [ ] Inspector shows response
- [ ] Response content type is "text"
- [ ] Response text: "Echo: Hello World"
- [ ] No errors in logs

#### Test 3.2: Call Example Tool (Edge Cases)
**Steps:**
Test with various inputs:
- Empty string: `{"message": ""}`
- Long string: `{"message": "a".repeat(1000)}`
- Special characters: `{"message": "Hello \"World\" \n\t 你好"}`
- Unicode: `{"message": "🚀 🎉 ✨"}`

**Expected Results:**
- [ ] Empty string echoed correctly
- [ ] Long string echoed without truncation
- [ ] Special characters preserved correctly
- [ ] Unicode characters preserved correctly
- [ ] No crashes or errors

#### Test 3.3: Call Unknown Tool
**Steps:**
1. In MCP Inspector, manually send CallTool request
2. Use tool name: "nonexistent_tool"

**Expected Results:**
- [ ] Server logs: "CallTool request: nonexistent_tool"
- [ ] Server logs: "Unknown tool requested: nonexistent_tool"
- [ ] Inspector shows error response
- [ ] Error message: "Unknown tool: nonexistent_tool"
- [ ] Server continues running (doesn't crash)

#### Test 3.4: Call Tool with Missing Required Parameter
**Steps:**
1. In MCP Inspector, select "example_tool"
2. Send empty arguments: `{}`

**Expected Results:**
- [ ] Error response returned
- [ ] Error indicates missing "message" parameter
- [ ] Server continues running

#### Test 3.5: Call Tool with Invalid Parameter Type
**Steps:**
1. Send: `{"message": 123}` (number instead of string)

**Expected Results:**
- [ ] Error response or type coercion
- [ ] Server handles gracefully
- [ ] Server continues running

### Test Suite 4: Error Handling and Resilience

#### Test 4.1: Multiple Rapid Requests
**Steps:**
1. In MCP Inspector, call "example_tool" 10 times rapidly

**Expected Results:**
- [ ] All 10 requests processed successfully
- [ ] No dropped requests
- [ ] Responses in correct order
- [ ] No memory leaks (check with `ps aux | grep node`)

#### Test 4.2: Concurrent Requests
**Steps:**
1. Use multiple MCP Inspector tabs or write a test script
2. Send 5 simultaneous requests

**Expected Results:**
- [ ] All requests handled
- [ ] No race conditions
- [ ] Logs show all requests
- [ ] Server remains stable

#### Test 4.3: Large Payload
**Steps:**
1. Send message with 10KB string
2. Send message with 100KB string (if applicable)

**Expected Results:**
- [ ] 10KB handled successfully
- [ ] 100KB handled or gracefully rejected
- [ ] No crashes
- [ ] Memory usage reasonable

### Test Suite 5: Logging and Observability

#### Test 5.1: Log Format Verification
**Steps:**
1. Start server and trigger various operations
2. Examine stderr output

**Expected Results:**
- [ ] All logs have timestamp: [YYYY-MM-DDTHH:mm:ss.sssZ]
- [ ] All logs have level: [INFO], [WARN], or [ERROR]
- [ ] All logs have clear messages
- [ ] Data logged as JSON when present
- [ ] No logs to stdout (reserved for MCP protocol)

#### Test 5.2: Log Levels
**Steps:**
Trigger operations that should log at different levels:
- Normal operation → INFO
- Unknown tool → ERROR

**Expected Results:**
- [ ] INFO logs for normal operations
- [ ] ERROR logs for error conditions
- [ ] Log level appropriate for event

#### Test 5.3: Structured Data Logging
**Steps:**
1. Call tool with complex arguments
2. Check if arguments logged correctly

**Expected Results:**
- [ ] Arguments logged as JSON
- [ ] JSON is valid and parseable
- [ ] No sensitive data leaked

### Test Suite 6: Claude Desktop Integration

#### Test 6.1: Configuration File
**Steps:**
1. Copy `claude_desktop_config.json` template
2. Update absolute path to your `dist/index.js`
3. Place in `~/Library/Application Support/Claude/claude_desktop_config.json`
4. Restart Claude Desktop

**Expected Results:**
- [ ] Claude Desktop loads config without errors
- [ ] iac-mcp appears in available MCP servers
- [ ] No error messages in Claude Desktop console

#### Test 6.2: Tool Discovery in Claude Desktop
**Steps:**
1. Open Claude Desktop
2. Start new conversation
3. Check available tools (if visible in UI)

**Expected Results:**
- [ ] iac-mcp server connects
- [ ] example_tool is available
- [ ] Tool schema is correct

#### Test 6.3: Tool Execution in Claude Desktop
**Steps:**
1. In Claude Desktop, ask: "Use the example_tool to echo 'Testing from Claude'"
2. Observe response

**Expected Results:**
- [ ] Claude calls the tool
- [ ] Response: "Echo: Testing from Claude"
- [ ] No errors in Claude Desktop
- [ ] Server logs show the request

#### Test 6.4: Multiple Tool Calls
**Steps:**
1. Ask Claude to call example_tool multiple times with different messages

**Expected Results:**
- [ ] All calls succeed
- [ ] Responses are correct
- [ ] No degradation in performance

#### Test 6.5: Error Handling in Claude Desktop
**Steps:**
1. Try to make Claude call a non-existent tool (if possible)

**Expected Results:**
- [ ] Error handled gracefully
- [ ] Claude shows error message to user
- [ ] Server continues running

### Test Suite 7: Performance and Resource Usage

#### Test 7.1: Memory Usage
**Steps:**
1. Start server
2. Monitor memory: `ps aux | grep "node dist/index.js"`
3. Call tools 100 times
4. Check memory again

**Expected Results:**
- [ ] Initial memory < 100MB
- [ ] Memory doesn't grow significantly with requests
- [ ] No memory leaks detected

#### Test 7.2: Startup Time
**Steps:**
1. Time server startup: `time node dist/index.js`

**Expected Results:**
- [ ] Startup time < 2 seconds
- [ ] No unnecessary delays

#### Test 7.3: Response Time
**Steps:**
1. In MCP Inspector, measure tool call response time

**Expected Results:**
- [ ] example_tool responds < 100ms
- [ ] ListTools responds < 50ms
- [ ] Response time consistent across calls

### Test Suite 8: Platform Compatibility

#### Test 8.1: macOS Versions
**Steps:**
Test on different macOS versions if available:
- macOS 14 (Sonoma)
- macOS 13 (Ventura)
- macOS 12 (Monterey)

**Expected Results:**
- [ ] Works on macOS 14+
- [ ] No platform-specific errors

#### Test 8.2: Node.js Versions
**Steps:**
Test with:
- Node.js 20.x
- Node.js 22.x (if available)

**Expected Results:**
- [ ] Works on Node.js 20+
- [ ] No version-specific errors

### Test Suite 9: Security and Permissions

#### Test 9.1: File System Access
**Steps:**
1. Verify server doesn't access unexpected files
2. Check for any file system operations in logs

**Expected Results:**
- [ ] No unauthorized file access
- [ ] No unexpected file operations

#### Test 9.2: Network Access
**Steps:**
1. Verify server uses stdio only (no network ports)
2. Check: `lsof -p [pid]`

**Expected Results:**
- [ ] No network sockets opened
- [ ] Only stdio connections
- [ ] No unexpected network activity

### Test Suite 10: Regression Testing

#### Test 10.1: Verify Previous Features Still Work
**Steps:**
After any code changes, verify:
- [ ] Server starts successfully
- [ ] ListTools returns tools
- [ ] CallTool executes correctly
- [ ] Logging works
- [ ] Shutdown is graceful

#### Test 10.2: Build Process
**Steps:**
1. Clean build: `npm run clean && npm run build`

**Expected Results:**
- [ ] Clean succeeds
- [ ] Build succeeds
- [ ] dist/ recreated correctly
- [ ] No stale artifacts

## Test Execution Tracking

| Test Suite | Date Tested | Tester | Result | Notes |
|------------|-------------|--------|--------|-------|
| 1. Startup/Shutdown | | | | |
| 2. ListTools | | | | |
| 3. CallTool | | | | |
| 4. Error Handling | | | | |
| 5. Logging | | | | |
| 6. Claude Desktop | | | | |
| 7. Performance | | | | |
| 8. Platform | | | | |
| 9. Security | | | | |
| 10. Regression | | | | |

## Common Issues and Troubleshooting

### Issue: Server doesn't start

**Symptoms:** Process exits immediately or hangs

**Troubleshooting:**
1. Check Node.js version: `node --version` (must be 20+)
2. Verify build succeeded: `ls -la dist/index.js`
3. Check for syntax errors: `node --check dist/index.js`
4. Review error logs

### Issue: Tools not appearing in Claude Desktop

**Symptoms:** iac-mcp server not visible or no tools listed

**Troubleshooting:**
1. Verify config path is correct in `claude_desktop_config.json`
2. Check absolute path to `dist/index.js` is correct
3. Restart Claude Desktop completely
4. Check Claude Desktop logs/console
5. Test with MCP Inspector first to verify server works

### Issue: Tool calls fail

**Symptoms:** Errors when calling tools

**Troubleshooting:**
1. Check server logs for error messages
2. Verify tool input schema matches request
3. Test with MCP Inspector to isolate issue
4. Check for permissions issues

### Issue: Memory leaks

**Symptoms:** Memory usage grows over time

**Troubleshooting:**
1. Monitor with: `ps aux | grep node`
2. Check for unclosed resources
3. Review event listener management
4. Use Node.js profiling tools

## Release Testing Checklist

Before releasing a new version:

- [ ] All test suites pass
- [ ] No open critical bugs
- [ ] Performance acceptable
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version number bumped
- [ ] Git tag created
- [ ] Tested on clean install
- [ ] Tested with Claude Desktop
- [ ] Tested with MCP Inspector

## Notes

- Always test with MCP Inspector before testing with Claude Desktop
- Keep detailed notes of any failures or unexpected behavior
- Report issues with full logs and reproduction steps
- Update this checklist as new features are added
