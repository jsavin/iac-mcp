# PermissionChecker Implementation Guide

This guide explains how to implement the PermissionChecker class based on the comprehensive test suite created at:

**Tests:** `/Users/jake/dev/jsavin/iac-mcp/tests/unit/permission-checker.test.ts` (62 tests)

---

## Overview

The `PermissionChecker` is responsible for deciding whether MCP tool commands should be executed based on:

1. **Safety Classification** - Is this a SAFE, REQUIRES_CONFIRMATION, or ALWAYS_CONFIRM operation?
2. **User Preferences** - Has the user already made a decision about this operation?
3. **Audit Trail** - Track all permission decisions for security and accountability

---

## Architecture

```
┌─────────────────────────────────┐
│      MCP Call Request           │
│  (tool + arguments)             │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│   PermissionChecker.check()     │
│  1. Classify command safety     │
│  2. Check user preferences      │
│  3. Return decision             │
│  4. Log to audit trail          │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│   PermissionDecision            │
│ {                               │
│   allowed: boolean              │
│   requiresPrompt: boolean       │
│   level: SafetyLevel            │
│   reason: string                │
│   alwaysAllow?: boolean         │
│ }                               │
└─────────────────────────────────┘
```

---

## Implementation Steps

### Step 1: Create the Class Structure

Create a new file: `src/permissions/permission-checker.ts`

```typescript
import { PermissionClassifier } from './permission-classifier.js';
import type { MCPTool } from '../types/mcp-tool.js';
import type {
  PermissionDecision,
  PermissionAuditEntry,
  SafetyLevel,
} from './types.js';

export class PermissionChecker {
  private classifier: PermissionClassifier;
  private preferences: Map<string, { alwaysAllow: boolean; blocked: boolean }>;
  private auditLog: PermissionAuditEntry[] = [];

  constructor() {
    this.classifier = new PermissionClassifier();
    this.preferences = new Map();
  }

  async check(tool: MCPTool, args: Record<string, any>): Promise<PermissionDecision> {
    // Implementation here
  }

  async recordDecision(decision: PermissionDecision): Promise<void> {
    // Implementation here
  }

  getAuditLog(): PermissionAuditEntry[] {
    return [...this.auditLog];
  }
}
```

### Step 2: Implement the `check()` Method

This is the core decision logic:

```typescript
async check(tool: MCPTool, args: Record<string, any>): Promise<PermissionDecision> {
  // 1. Classify the command
  const classification = this.classifier.classify(tool, args);
  const { level, reason } = classification;

  // 2. Get preference key
  const bundleId = tool._metadata?.bundleId || 'unknown';
  const commandName = tool._metadata?.commandName || tool.name;
  const preferenceKey = `${bundleId}:${commandName}`;

  // 3. Determine if we have a saved preference
  const preference = this.preferences.get(preferenceKey);

  // 4. Make decision based on safety level and preference
  let decision: PermissionDecision;

  if (level === 'ALWAYS_SAFE') {
    // Always allow, no prompt
    decision = {
      allowed: true,
      requiresPrompt: false,
      level,
      reason,
    };
  } else if (level === 'REQUIRES_CONFIRMATION') {
    if (preference) {
      // Use saved preference
      decision = {
        allowed: preference.alwaysAllow && !preference.blocked,
        requiresPrompt: false,
        level,
        reason,
        alwaysAllow: preference.alwaysAllow,
      };
    } else {
      // Ask user
      decision = {
        allowed: false,
        requiresPrompt: true,
        level,
        reason,
      };
    }
  } else {
    // ALWAYS_CONFIRM
    if (preference?.alwaysAllow) {
      // User explicitly allowed this
      decision = {
        allowed: true,
        requiresPrompt: false,
        level,
        reason,
        alwaysAllow: true,
      };
    } else {
      // Always prompt for dangerous operations
      decision = {
        allowed: false,
        requiresPrompt: true,
        level,
        reason,
      };
    }
  }

  // 5. Record in audit log
  const auditEntry: PermissionAuditEntry = {
    timestamp: new Date(),
    tool: tool.name,
    args,
    decision,
    executed: false, // Will be updated by caller
  };
  this.auditLog.push(auditEntry);

  return decision;
}
```

### Step 3: Implement the `recordDecision()` Method

Store user decisions for future checks:

```typescript
async recordDecision(decision: PermissionDecision): Promise<void> {
  // This method is called when:
  // 1. User responds to a prompt
  // 2. Tool execution completes (with result or error)

  // For simplicity in MVP, we don't store individual decisions here
  // Instead, preferences are updated when needed

  // If the decision indicates the user made a choice (alwaysAllow set),
  // we would store it like:
  // const key = makePreferenceKey(tool);
  // this.preferences.set(key, { alwaysAllow: decision.alwaysAllow || false });

  // For now, this mainly serves to log the final outcome
  if (this.auditLog.length > 0) {
    const lastEntry = this.auditLog[this.auditLog.length - 1];
    // Mark as executed or with result/error
    // This depends on how the calling code wants to integrate
  }
}
```

### Step 4: Helper Method for Preference Key

```typescript
private makePreferenceKey(bundleId: string, commandName: string): string {
  return `${bundleId}:${commandName}`;
}
```

---

## Key Decision Rules

Based on the test suite, implement this decision matrix:

### ALWAYS_SAFE
- **Always:** `allowed: true, requiresPrompt: false`
- **No prompt needed**
- **Cannot be blocked**
- **Examples:** list, get, find, count, search operations

### REQUIRES_CONFIRMATION
- **If preference saved:**
  - Use saved preference (`allowed: true` or `false`)
  - `requiresPrompt: false`
- **If no preference:**
  - `allowed: false, requiresPrompt: true`
  - User needs to decide
- **After user decides:** Store preference for future use
- **Examples:** set, move, copy, save, send operations

### ALWAYS_CONFIRM
- **Default:** `allowed: false, requiresPrompt: true`
- **Only allow if:**
  - `alwaysAllow: true` in user preference
  - `requiresPrompt: false` (user already decided)
- **Cannot auto-allow** without explicit user permission
- **Examples:** delete, quit, trash operations

---

## Preference Storage Format

Preferences are stored with this format:

```typescript
type PreferenceKey = `${string}:${string}`; // bundleId:commandName

interface StoredPreference {
  alwaysAllow: boolean;  // true = always allow, false = ask again
  blocked?: boolean;     // Optional: explicitly blocked by user
}

// In a Map:
const preferences = new Map<PreferenceKey, StoredPreference>();

// Example entries:
preferences.set('com.apple.finder:move', { alwaysAllow: true });
preferences.set('com.apple.finder:delete', { alwaysAllow: false, blocked: true });
```

---

## Audit Trail Format

The audit log tracks every permission decision:

```typescript
const auditEntry: PermissionAuditEntry = {
  timestamp: new Date(),           // When was the decision made?
  tool: 'finder_move',             // Which tool?
  args: { from: '...', to: '...' }, // What arguments?
  decision: {                        // What was decided?
    allowed: true,
    level: 'REQUIRES_CONFIRMATION',
    reason: 'Saved preference: user allowed',
    requiresPrompt: false,
  },
  executed: false,                  // Was it executed? (updated later)
  result?: { /* ... */ },           // If executed, what was the result?
  error?: 'error message',          // If failed, what error?
};
```

---

## Integration Points

### With PermissionClassifier

```typescript
private classifier: PermissionClassifier;

// In check():
const classification = this.classifier.classify(tool, args);
const { level, reason } = classification;
```

### With MCP Tools

```typescript
async check(tool: MCPTool, args: Record<string, any>): Promise<PermissionDecision> {
  // tool._metadata contains:
  // - bundleId: string (e.g., 'com.apple.finder')
  // - commandName: string (e.g., 'move')
  // - appName: string (e.g., 'Finder')
}
```

### With Calling Code (MCP Handler)

```typescript
// In MCP handler:
const decision = await permissionChecker.check(tool, args);

if (!decision.allowed) {
  if (decision.requiresPrompt) {
    // Show user prompt, get response
    // Call permissionChecker.recordDecision(userDecision)
  }
  return error('Permission denied');
}

// Execute the tool
const result = await adapter.execute(tool, args);
```

---

## Testing Strategy

### Unit Tests (Already Written)

Run the test suite as you implement:

```bash
npm test tests/unit/permission-checker.test.ts
```

The tests cover:
- ✓ All three safety levels
- ✓ Preference persistence
- ✓ Audit trail
- ✓ Edge cases
- ✓ Error handling

### What to Test While Implementing

1. **ALWAYS_SAFE**: Verify always returns allowed
2. **REQUIRES_CONFIRMATION**: Verify prompts first time, uses preference after
3. **ALWAYS_CONFIRM**: Verify blocks by default, allows only with permission
4. **Preferences**: Verify storage and retrieval
5. **Audit Log**: Verify entries are created and ordered correctly

### Running Tests

```bash
# Run all tests
npm test tests/unit/permission-checker.test.ts

# Run specific section
npm test tests/unit/permission-checker.test.ts -t "ALWAYS_SAFE"

# Run with verbose output
npm test tests/unit/permission-checker.test.ts --reporter=verbose
```

---

## Error Handling

The implementation should handle these gracefully:

1. **Tool without metadata**
   - Use `tool.name` as fallback for preference key
   - Don't crash, return reasonable default

2. **Null/undefined arguments**
   - Treat as empty object `{}`
   - Don't crash

3. **Invalid preferences**
   - Treat as missing preference
   - Prompt user instead of using invalid preference

4. **Storage errors** (future)
   - Log error but don't block execution
   - Fall back to prompting user

---

## Example Usage

Once implemented, this is how it will be used:

```typescript
const checker = new PermissionChecker();

// Check a read-only operation
let decision = await checker.check(finderListFolderTool, { path: '~/Desktop' });
// Result: { allowed: true, requiresPrompt: false, level: 'ALWAYS_SAFE' }

// Check a modifying operation (first time)
decision = await checker.check(finderMoveTool, { from: '...', to: '...' });
// Result: { allowed: false, requiresPrompt: true, level: 'REQUIRES_CONFIRMATION' }

// User decides to allow it
await checker.recordDecision({
  ...decision,
  allowed: true,
  alwaysAllow: true,
  requiresPrompt: false,
});

// Same operation again
decision = await checker.check(finderMoveTool, { from: '...', to: '...' });
// Result: { allowed: true, requiresPrompt: false, level: 'REQUIRES_CONFIRMATION', alwaysAllow: true }

// Check audit log
const log = checker.getAuditLog();
// Contains entries for both checks
```

---

## Next Steps After Implementation

1. **Verify all tests pass**
   ```bash
   npm test tests/unit/permission-checker.test.ts
   ```

2. **Integrate with MCP handler**
   - Import and instantiate PermissionChecker
   - Call `check()` before executing commands
   - Handle `requiresPrompt: true` cases

3. **Add to exports**
   - Update `src/permissions/index.ts` to export PermissionChecker

4. **Integration testing**
   - Test with real MCP tools
   - Verify audit log tracks correctly
   - Test edge cases with actual tools

5. **Polish**
   - Add logging for debugging
   - Optimize preference lookup
   - Consider persistence (Week 4+)

---

## Related Files

- **Types:** `src/permissions/types.ts`
- **Classifier:** `src/permissions/permission-classifier.ts`
- **Tests:** `tests/unit/permission-checker.test.ts`
- **MCP Tools:** `src/types/mcp-tool.ts`

---

## Key Implementation Notes

1. **Simplicity First**: MVP should be simple - in-memory storage, no fancy features
2. **Type Safety**: Use proper TypeScript types, especially for preferences
3. **Immutability**: Audit log should never be modified after entry
4. **Consistency**: Always make same decision for same input (idempotent)
5. **Logging**: Add console logging for debugging permission decisions
6. **Error Resilience**: Never throw, always return valid decision

---

## Performance Considerations

For MVP, performance isn't critical, but keep in mind:

- **Preference lookup**: O(1) with Map
- **Audit log**: Linear search would be slow for large logs (fine for MVP)
- **Classification**: Depends on PermissionClassifier performance
- **No external I/O**: Everything in-memory for MVP

For future optimization:
- Consider database for persistent storage
- Add indexes for audit log queries
- Cache classifier results

---

## Security Considerations

- **Audit Trail**: Never delete, always append (immutable)
- **Preferences**: Store securely (encrypted in future)
- **Error Messages**: Don't leak sensitive info
- **Logging**: Don't log sensitive arguments in future
- **User Intent**: Always respect user's saved preferences
