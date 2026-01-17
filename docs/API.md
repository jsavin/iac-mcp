# API Reference

Complete API reference for IAC-MCP generated tools and resources.

## Table of Contents

1. [MCP Tools](#mcp-tools)
2. [Tool Naming Convention](#tool-naming-convention)
3. [Parameter Types](#parameter-types)
4. [Return Types](#return-types)
5. [Error Handling](#error-handling)
6. [Common Patterns](#common-patterns)
7. [Application-Specific APIs](#application-specific-apis)

## MCP Tools

IAC-MCP dynamically generates MCP tools from application SDEF files. Each tool represents a scriptable command from a native application.

### Tool Structure

```typescript
interface Tool {
  name: string;              // Unique tool identifier
  description: string;       // Human-readable description
  inputSchema: {            // JSON Schema for parameters
    type: "object";
    properties: Record<string, JSONSchema>;
    required?: string[];
  };
}
```

### Example Tool

```json
{
  "name": "finder_open",
  "description": "Open the specified item in Finder",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Path to the file or folder to open"
      }
    },
    "required": ["target"]
  }
}
```

### Using Tools

**From Claude Desktop:**
```
User: "Open my Desktop folder in Finder"
Claude: [calls finder_open tool with target="/Users/username/Desktop"]
```

**From MCP Inspector:**
```javascript
// Call tool
{
  "method": "tools/call",
  "params": {
    "name": "finder_open",
    "arguments": {
      "target": "/Users/jake/Desktop"
    }
  }
}

// Response
{
  "content": [
    {
      "type": "text",
      "text": "{\"result\": \"success\"}"
    }
  ]
}
```

## Tool Naming Convention

Tools follow a consistent naming pattern: `{app}_{command}`

### Format

```
<app-name>_<suite-name>_<command-name>
```

**Components:**
- `app-name`: Lowercase, hyphen-separated app name (e.g., `finder`, `safari`)
- `suite-name`: Optional, only if collision (e.g., `standard-suite`)
- `command-name`: Lowercase, underscore-separated command (e.g., `open`, `get_url`)

### Examples

| Original Command | Generated Tool Name | Reason |
|------------------|---------------------|---------|
| Finder → open | `finder_open` | Standard |
| Safari → GetURL | `safari_get_url` | Camel case → snake_case |
| Mail → save (standard suite) | `mail_standard_suite_save` | Collision detected |
| Notes → create note | `notes_create_note` | Space → underscore |

### Collision Resolution

When multiple suites have the same command name:

```typescript
// Before collision resolution
finder_save  // From StandardSuite
finder_save  // From FileSuite (COLLISION!)

// After collision resolution
finder_standard_suite_save
finder_file_suite_save
```

## Parameter Types

IAC-MCP maps SDEF parameter types to JSON Schema types.

### Type Mapping

| SDEF Type | JSON Schema Type | Format | Example |
|-----------|------------------|--------|---------|
| `text` | `string` | - | `"Hello World"` |
| `integer` | `number` | - | `42` |
| `real` | `number` | - | `3.14` |
| `boolean` | `boolean` | - | `true` |
| `file` | `string` | - | `"/Users/jake/file.txt"` |
| `alias` | `string` | - | `"/Applications/Safari.app"` |
| `date` | `string` | `date-time` | `"2026-01-16T10:30:00Z"` |
| `list of <type>` | `array` | items: `<type>` | `["item1", "item2"]` |
| `record` | `object` | - | `{"key": "value"}` |
| `type reference` | `object` | - | `{"name": "value"}` |

### Complex Types

**List of items:**
```json
{
  "type": "array",
  "items": {
    "type": "string"
  },
  "description": "List of file paths"
}
```

**Record (object):**
```json
{
  "type": "object",
  "description": "File properties",
  "properties": {
    "name": { "type": "string" },
    "size": { "type": "number" }
  }
}
```

**Type reference:**
```json
{
  "type": "object",
  "description": "Reference to application object",
  "properties": {
    "name": { "type": "string" },
    "id": { "type": "string" }
  }
}
```

### Optional vs Required

Parameters marked as `optional="yes"` in SDEF are not included in the `required` array:

```json
{
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": { "type": "string" },          // Required
      "options": { "type": "object" }          // Optional
    },
    "required": ["target"]
  }
}
```

## Return Types

Tool execution returns MCP content blocks.

### Success Response

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"result\": \"Desktop\", \"success\": true}"
    }
  ]
}
```

### Structured Results

Some commands return structured data:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"name\": \"Desktop\", \"path\": \"/Users/jake/Desktop\", \"kind\": \"folder\"}"
    }
  ]
}
```

### Multiple Results

Commands that return multiple items use JSON arrays:

```json
{
  "content": [
    {
      "type": "text",
      "text": "[{\"name\": \"file1.txt\"}, {\"name\": \"file2.txt\"}]"
    }
  ]
}
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "EXECUTION_ERROR",
    "message": "Command failed: Application Finder is not running",
    "details": {
      "appBundleId": "com.apple.finder",
      "command": "open",
      "originalError": "Application isn't running"
    }
  }
}
```

### Error Categories

| Category | Code | Description | Recovery |
|----------|------|-------------|----------|
| Discovery | `DISCOVERY_ERROR` | App not found | Install app or check path |
| Parsing | `PARSING_ERROR` | SDEF malformed | Report bug with app name |
| Generation | `GENERATION_ERROR` | Tool generation failed | Check SDEF format |
| Execution | `EXECUTION_ERROR` | Command failed | Check app is running |
| MCP | `MCP_ERROR` | Protocol error | Restart MCP server |

### Common Errors

**App not running:**
```json
{
  "error": {
    "code": "EXECUTION_ERROR",
    "message": "Application 'Safari' is not running"
  }
}
```

**Permission denied:**
```json
{
  "error": {
    "code": "EXECUTION_ERROR",
    "message": "Not authorized to send Apple events to Safari"
  }
}
```

**Invalid parameters:**
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Required parameter 'target' is missing"
  }
}
```

**Timeout:**
```json
{
  "error": {
    "code": "TIMEOUT_ERROR",
    "message": "Command timed out after 30000ms"
  }
}
```

## Common Patterns

### File Operations

**Open file:**
```javascript
{
  "name": "finder_open",
  "arguments": {
    "target": "/Users/jake/Documents/file.pdf"
  }
}
```

**Get file info:**
```javascript
{
  "name": "finder_get_properties",
  "arguments": {
    "target": "/Users/jake/Documents/file.pdf"
  }
}
```

**Create folder:**
```javascript
{
  "name": "finder_make",
  "arguments": {
    "type": "folder",
    "at": "/Users/jake/Documents",
    "with_properties": {
      "name": "NewFolder"
    }
  }
}
```

### Browser Automation

**Open URL:**
```javascript
{
  "name": "safari_open_location",
  "arguments": {
    "url": "https://example.com"
  }
}
```

**Get current URL:**
```javascript
{
  "name": "safari_get_url",
  "arguments": {}
}
```

**Close tab:**
```javascript
{
  "name": "safari_close",
  "arguments": {
    "target": "current tab"
  }
}
```

### Email Operations

**Send email:**
```javascript
{
  "name": "mail_send_message",
  "arguments": {
    "to": "recipient@example.com",
    "subject": "Test Email",
    "content": "Email body text"
  }
}
```

**Get unread count:**
```javascript
{
  "name": "mail_get_unread_count",
  "arguments": {}
}
```

## Application-Specific APIs

### Finder

**Common Commands:**
- `finder_open` - Open file or folder
- `finder_reveal` - Show item in Finder window
- `finder_get_selection` - Get selected items
- `finder_get_properties` - Get file/folder properties
- `finder_make` - Create new file/folder
- `finder_delete` - Move to trash
- `finder_duplicate` - Duplicate item

**Example Workflow:**
```javascript
// 1. Get desktop path
{ "name": "finder_get_desktop", "arguments": {} }
// Returns: {"path": "/Users/jake/Desktop"}

// 2. Create folder
{
  "name": "finder_make",
  "arguments": {
    "type": "folder",
    "at": "/Users/jake/Desktop",
    "with_properties": { "name": "MyFolder" }
  }
}

// 3. Open folder
{ "name": "finder_open", "arguments": { "target": "/Users/jake/Desktop/MyFolder" } }
```

### Safari

**Common Commands:**
- `safari_open_location` - Open URL
- `safari_get_url` - Get current URL
- `safari_do_javascript` - Execute JavaScript
- `safari_get_text` - Get page text
- `safari_close` - Close tab/window

**Example Workflow:**
```javascript
// 1. Open webpage
{ "name": "safari_open_location", "arguments": { "url": "https://example.com" } }

// 2. Execute JavaScript
{
  "name": "safari_do_javascript",
  "arguments": {
    "script": "document.title"
  }
}
// Returns: {"result": "Example Domain"}

// 3. Close tab
{ "name": "safari_close", "arguments": { "target": "current tab" } }
```

### Mail

**Common Commands:**
- `mail_send_message` - Send email
- `mail_get_unread_count` - Get unread count
- `mail_get_inbox` - Get inbox messages
- `mail_mark_as_read` - Mark message read
- `mail_delete_message` - Delete message

**Example Workflow:**
```javascript
// 1. Get unread count
{ "name": "mail_get_unread_count", "arguments": {} }
// Returns: {"count": 42}

// 2. Send email
{
  "name": "mail_send_message",
  "arguments": {
    "to": "friend@example.com",
    "subject": "Hello",
    "content": "How are you?"
  }
}
```

### Notes

**Common Commands:**
- `notes_create_note` - Create new note
- `notes_get_notes` - List all notes
- `notes_get_note` - Get specific note
- `notes_update_note` - Update note content
- `notes_delete_note` - Delete note

### Calendar

**Common Commands:**
- `calendar_create_event` - Create calendar event
- `calendar_get_events` - List events
- `calendar_delete_event` - Delete event

### Reminders

**Common Commands:**
- `reminders_create_reminder` - Create reminder
- `reminders_get_reminders` - List reminders
- `reminders_complete_reminder` - Mark complete

## Tool Discovery

### List All Tools

**Request:**
```json
{
  "method": "tools/list"
}
```

**Response:**
```json
{
  "tools": [
    {
      "name": "finder_open",
      "description": "Open the specified item",
      "inputSchema": { ... }
    },
    {
      "name": "safari_open_location",
      "description": "Open a URL in Safari",
      "inputSchema": { ... }
    }
    // ... more tools
  ]
}
```

### Filter Tools by App

Tools are prefixed with app name, so you can filter:

```javascript
// All Finder tools
tools.filter(t => t.name.startsWith('finder_'))

// All Safari tools
tools.filter(t => t.name.startsWith('safari_'))
```

## Best Practices

### Parameter Validation

Always validate parameters before calling:

```javascript
// ✅ GOOD: Validate first
if (!args.target || typeof args.target !== 'string') {
  throw new Error('target must be a string');
}

// ❌ BAD: No validation
callTool('finder_open', args);
```

### Error Handling

Handle errors gracefully:

```javascript
try {
  const result = await callTool('finder_open', { target: path });
  return result;
} catch (error) {
  if (error.code === 'EXECUTION_ERROR') {
    console.error('App not running:', error.message);
    // Try to launch app
    await callTool('finder_launch', {});
    return callTool('finder_open', { target: path });
  }
  throw error;
}
```

### Path Handling

Always use absolute paths:

```javascript
// ✅ GOOD: Absolute path
{ "target": "/Users/jake/Desktop/file.txt" }

// ❌ BAD: Relative path
{ "target": "Desktop/file.txt" }
```

### Timeouts

Set appropriate timeouts for long-running operations:

```javascript
// Default: 30 seconds
// For long operations, increase timeout via environment
export IAC_MCP_TIMEOUT=60000
```

## Limitations

### Current Limitations

1. **macOS only:** Currently only macOS is supported
2. **Scriptable apps only:** Requires SDEF file
3. **No GUI automation:** Can't interact with UI elements directly
4. **Single platform:** One adapter at a time
5. **Synchronous:** Commands execute sequentially

### Future Improvements

1. **Multi-platform:** Windows (VBA/COM), Linux (D-Bus)
2. **UI automation:** Accessibility API integration
3. **Async batching:** Execute multiple commands in parallel
4. **Streaming:** Stream large results
5. **Caching:** Cache command results

## Versioning

API follows semantic versioning (semver):

- **Major:** Breaking changes to tool names or parameters
- **Minor:** New tools or features (backward compatible)
- **Patch:** Bug fixes (backward compatible)

**Current version:** `0.1.0`

## Support

For API questions or issues:

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Review [examples](QUICK-START.md#examples)
3. Search GitHub issues
4. Create new issue with API tag

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for API changes by version.
