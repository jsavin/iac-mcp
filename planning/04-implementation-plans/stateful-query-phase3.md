# Phase 3: Property Setters - Implementation Plan

**Parent Plan:** [Stateful Query System](./stateful-query-system.md)
**Status:** Planning (blocked by Phase 1, optionally Phase 2)
**Priority:** Medium
**Estimated Effort:** 1-2 days
**Owner:** TBD
**Created:** 2026-01-27

---

## Goal

Enable property modification with permission checks, allowing Claude to perform actions like "mark email as read" or "rename file".

---

## Success Criteria

- ✅ Claude can mark email as read
- ✅ Claude can rename files
- ✅ Claude can update calendar event details
- ✅ Permission prompts for write operations
- ✅ Read-only properties rejected gracefully
- ✅ Atomic updates (set succeeds or fails completely)
- ✅ 100% test coverage maintained

---

## Deliverables

### 1. New MCP Tool

**File:** `src/jitd/tool-generator/query-tools.ts` (MODIFY)

**Add Tool:**
```typescript
{
  name: "iac_mcp_set_property",
  description: "Set a property value on a referenced object. Requires permission for write operations.",
  inputSchema: {
    type: "object",
    properties: {
      reference: {
        type: "string",
        description: "Object reference ID from query_object"
      },
      property: {
        type: "string",
        description: "Property name to set"
      },
      value: {
        description: "New value for the property"
      }
    },
    required: ["reference", "property", "value"]
  }
}
```

### 2. Query Executor Enhancement

**File:** `src/execution/query-executor.ts` (MODIFY)

**Add Method:**
```typescript
async setProperty(
  referenceId: string,
  property: string,
  value: any
): Promise<void> {
  // 1. Validate reference
  // 2. Check if property is read-write (from sdef)
  // 3. Check permissions (call permission system)
  // 4. Build JXA setter code
  // 5. Execute JXA
  // 6. Handle errors
}
```

### 3. Property Validation

**File:** `src/validation/property-validator.ts` (NEW)

**Class:** `PropertyValidator`

**Methods:**
- `isReadWrite(appId: string, objectType: string, property: string): boolean`
- `validateValue(property: string, value: any, expectedType: string): boolean`
- `getPropertyAccess(property: string): "read-only" | "read-write"`

**Uses:** SDEF parser to determine property access level

### 4. Permission Integration

**File:** `src/permissions/permission-checker.ts` (MODIFY)

**Add:**
- `checkPropertyWrite(app: string, objectType: string, property: string, oldValue: any, newValue: any): Promise<boolean>`

**Permission Prompt:**
```
iac-mcp wants to modify data in Mail.app

Property: read status
Object: Email from john@example.com ("Meeting tomorrow")
Old value: false
New value: true

[ Always Allow ]  [ Allow Once ]  [ Deny ]
```

### 5. Tests

**Unit Tests:**
- `tests/unit/validation/property-validator.test.ts` (NEW)
- `tests/unit/execution/query-executor-setters.test.ts` (NEW)
- `tests/unit/permissions/property-write-permissions.test.ts` (NEW)

**Integration Tests:**
- `tests/integration/set-property-mail.test.ts` (NEW)
- `tests/integration/set-property-finder.test.ts` (NEW)
- `tests/integration/set-property-calendar.test.ts` (NEW)

**Test Cases:**
- ✅ Set read-write property succeeds
- ✅ Set read-only property fails with clear error
- ✅ Permission denied prevents write
- ✅ Permission granted allows write
- ✅ Type validation (setting string to number fails)
- ✅ Invalid reference handled gracefully
- ✅ Atomic update (no partial writes on error)

---

## Implementation Tasks

### Task 1: Add Property Validator (0.5 days)
- Implement `PropertyValidator` class
- Query sdef for property access levels
- Write unit tests

### Task 2: Implement setProperty in QueryExecutor (0.5 days)
- Add `setProperty()` method
- Build JXA setter code
- Validate property before execution
- Write unit tests

### Task 3: Integrate Permission System (0.5 days)
- Add property write permission check
- Design permission prompt UI (or reuse existing)
- Write tests

### Task 4: Add set_property Tool (0.5 days)
- Generate tool schema
- Add handler in MCP server
- Write tests

### Task 5: Integration Testing (0.5 days)
- Test with Mail.app (mark as read, flag, delete status)
- Test with Finder.app (rename, label)
- Test with Calendar.app (update event title, location)

---

## Example Usage After Phase 3

**Mark email as read:**
```typescript
// Get message reference
const { elements } = await getElements(inboxRef, "message", 1);
const messageRef = elements[0];

// Set read status
await setProperty(messageRef.id, "read status", true);
```

**Rename file:**
```typescript
// Get file reference
const fileRef = await queryObject("com.apple.finder", {
  type: "element",
  element: "file",
  index: 0,
  container: {
    type: "named",
    element: "folder",
    name: "Documents",
    container: "application"
  }
});

// Rename file
await setProperty(fileRef.id, "name", "new-name.txt");
```

---

## JXA Generation for Setters

**Read status (boolean):**
```javascript
const app = Application("Mail");
const message = /* resolved path */;
message.readStatus = true;
```

**File name (string):**
```javascript
const app = Application("Finder");
const file = /* resolved path */;
file.name = "new-name.txt";
```

**Event location (string):**
```javascript
const app = Application("Calendar");
const event = /* resolved path */;
event.location = "Conference Room B";
```

---

## Error Handling

### Read-Only Property
```json
{
  "error": "property_read_only",
  "property": "size",
  "objectType": "file",
  "message": "The property 'size' is read-only and cannot be modified"
}
```

### Permission Denied
```json
{
  "error": "permission_denied",
  "property": "read status",
  "message": "User denied permission to modify property"
}
```

### Type Mismatch
```json
{
  "error": "type_mismatch",
  "property": "read status",
  "expectedType": "boolean",
  "providedType": "string",
  "message": "Expected boolean but received string"
}
```

---

## Security Considerations

### Always Prompt For:
- Deleting data (e.g., `deleted` status)
- Sending messages (e.g., `sender`, `recipient`)
- Executing commands (e.g., `run script`)

### Prompt Once (Can "Always Allow"):
- Marking as read/unread
- Renaming files/folders
- Updating event details
- Changing labels/tags

### Never Prompt (Safe):
- None (all writes require at least one prompt)

---

## Dependencies

**Requires:**
- ✅ Phase 1 complete (core query system)

**Optional:**
- Phase 2 (filtering) - Independent but useful for bulk operations

**Blocks:**
- None (this is a terminal phase for write operations)

---

## Open Questions

1. **Should we support batch property sets?**
   - Phase 3: No (one property at a time)
   - Phase 4: Consider for performance

2. **Should we support transactions (rollback on failure)?**
   - Phase 3: No (best-effort)
   - Future: Consider if users request

3. **Should we log all property writes?**
   - Phase 3: Yes (for debugging)
   - Add to reference metadata

---

**Document Version:** 1.0
**Last Updated:** 2026-01-27
**Status:** Planning (blocked by Phase 1)
