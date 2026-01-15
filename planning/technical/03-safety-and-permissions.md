# Safety and Permissions System

## Goals
- Prevent accidental data loss or system damage
- Give users control over what LLMs can do
- Learn from user preferences over time
- Centrally updatable security rules

## Permission Model

### Inspired by Claude Mac App / Claude Code
- **Per-operation, per-app permissions**
- **"Always allow" checkbox** for trusted operations
- **Session-based bypass** (optional: skip confirmations this session)
- **Audit log** of all operations performed

### Permission Levels

#### 1. Always Safe (No Confirmation)
- Read-only operations on app state
- Getting lists of items (windows, documents, etc.)
- Querying properties
- Getting app version/info

Examples:
```applescript
tell application "Finder" to get name of every folder of desktop
tell application "Safari" to get URL of current tab of front window
```

#### 2. Requires Confirmation (Default)
- Creating/modifying data
- Sending messages
- Opening files/URLs
- Changing app settings

Examples:
```applescript
tell application "Mail" to send message...
tell application "Finder" to move file...
tell application "Safari" to open location "https://..."
```

#### 3. Always Requires Confirmation (Cannot Bypass)
- Deleting files or data
- Quitting applications
- System-level operations
- Running shell scripts via AppleScript
- Operations with security/privacy implications

Examples:
```applescript
tell application "Finder" to delete file...
tell application "System Events" to shutdown
do shell script "rm -rf ..."
```

### Permission Storage

```typescript
interface PermissionStore {
  version: string;
  rules: {
    // User-granted permissions
    userRules: Array<{
      id: string;
      appBundleId: string;
      command: string; // AppleScript command pattern
      level: 'always_allow' | 'always_deny';
      granted: Date;
      expiresAt?: Date; // Optional expiration
    }>;

    // Centrally managed rules (updated from server)
    centralRules: Array<{
      id: string;
      pattern: string; // Regex pattern for dangerous commands
      level: 'block' | 'require_confirmation' | 'allow';
      reason: string;
      version: number;
    }>;
  };

  sessionBypass: boolean; // Temporary bypass for this session
  auditLog: Array<{
    timestamp: Date;
    appBundleId: string;
    command: string;
    allowed: boolean;
    userConfirmed?: boolean;
  }>;
}
```

**Storage**: `~/Library/Application Support/osa-mcp/permissions.json`

### Central Rules Update System

#### Architecture
1. **Rules Server**: HTTPS endpoint serving latest safety rules
2. **Update Check**: On startup and periodically (daily?)
3. **User Notification**: Alert when new rules available
4. **Auto-Apply**: Option to auto-apply security updates

#### Rule Format
```json
{
  "version": 2,
  "minClientVersion": "1.0.0",
  "rules": [
    {
      "id": "prevent-rm-rf",
      "pattern": "do shell script.*rm\\s+-rf",
      "level": "block",
      "reason": "Prevents destructive file deletion via shell",
      "severity": "critical"
    },
    {
      "id": "finder-delete-confirmation",
      "pattern": "tell application \"Finder\".*delete",
      "level": "require_confirmation",
      "reason": "Deletion requires user confirmation",
      "severity": "high"
    }
  ]
}
```

#### Update Flow
```
Startup → Check for Updates → Compare Versions →
  If New Rules:
    - Download new rules
    - Notify user (if non-critical)
    - Auto-apply (if user enabled)
    - OR prompt user to review changes
```

### Command Classification

#### Static Analysis
Before execution, analyze the AppleScript command for:
- Command verbs: `delete`, `remove`, `quit`, `shutdown`, `restart`
- Shell script execution: `do shell script`
- File operations: `move`, `duplicate`, `delete`
- Network operations: `open location`, `download`

#### Pattern Matching
Use regex patterns to classify risk:
```typescript
const DANGEROUS_PATTERNS = [
  /\bdelete\b/i,
  /\bremove\b/i,
  /\bquit\b/i,
  /do shell script/i,
  /\brm\s+-rf/i,
  /\bshutdown\b/i,
];
```

### User Experience

#### Permission Dialog
```
┌─────────────────────────────────────────────┐
│ OSA MCP Permission Request                  │
├─────────────────────────────────────────────┤
│                                             │
│ Application: Finder                         │
│ Operation: Move file to trash               │
│                                             │
│ Script:                                     │
│   tell application "Finder"                 │
│     delete file "document.txt"              │
│   end tell                                  │
│                                             │
│ ☐ Always allow "delete" for Finder         │
│ ☐ Skip confirmations this session          │
│                                             │
│         [Deny]  [Allow Once]  [Allow]      │
└─────────────────────────────────────────────┘
```

#### Audit Log Access
- Users can review what operations were performed
- Export audit log for security review
- Clear old entries after N days

## Open Questions

1. Should we rate-limit operations to prevent runaway scripts?
2. How granular should "always allow" be? (exact script vs. command type)
3. Should we sandbox AppleScript execution in any way?
4. What's the right balance between security and usability?
5. Should enterprises be able to deploy custom rule sets?
6. How do we handle the cold-start problem (everything requires confirmation initially)?
7. Should we use ML to learn safe patterns from user behavior?
