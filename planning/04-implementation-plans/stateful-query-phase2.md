# Phase 2: Filtering & Advanced Queries - Implementation Plan

**Parent Plan:** [Stateful Query System](./stateful-query-system.md)
**Status:** Planning (blocked by Phase 1)
**Priority:** High
**Estimated Effort:** 2-3 days
**Owner:** TBD
**Created:** 2026-01-27

---

## Goal

Enable filtered queries and complex nested object specifiers to support queries like "unread emails from John" or "files modified in the last week".

---

## Success Criteria

- ✅ Claude can query "unread emails from John"
- ✅ Claude can filter by date ranges
- ✅ Complex nested specifiers work correctly
- ✅ Filter operators work: `==`, `!=`, `<`, `>`, `contains`, `startsWith`, `endsWith`
- ✅ 100% test coverage maintained
- ✅ Performance remains acceptable (< 5 seconds for filtered queries)

---

## Deliverables

### 1. Enhanced Type System

**File:** `src/types/object-specifier.ts` (MODIFY)

**Add:**
```typescript
export interface FilterSpecifier {
  type: "filter";
  element: string;
  container: SpecifierContainer;
  where: FilterExpression;
  limit?: number;
}

export interface FilterExpression {
  property: string;
  op: "==" | "!=" | "<" | ">" | "<=" | ">=" | "contains" | "startsWith" | "endsWith";
  value: any;
}

// Compound filters (Phase 2.5, optional)
export interface CompoundFilterExpression {
  and?: FilterExpression[];
  or?: FilterExpression[];
}
```

### 2. Query Executor Enhancements

**File:** `src/execution/query-executor.ts` (MODIFY)

**Add:**
- Support for `FilterSpecifier` in `buildObjectPath()`
- JXA `whose()` clause generation
- Complex nested specifier resolution

**Example JXA Generation:**
```javascript
// Filter: unread messages
app.mailboxes.byName("inbox").messages.whose({ readStatus: false })

// Filter: messages from John
app.mailboxes.byName("inbox").messages.whose({
  _match: [ObjectSpecifier("sender"), "contains", "john"]
})
```

### 3. Updated Tool Schemas

**File:** `src/jitd/tool-generator/query-tools.ts` (MODIFY)

**Enhance `iac_mcp_get_elements`:**
- Add optional `filter` parameter (FilterExpression)

**New tool (optional):**
- `iac_mcp_query_filtered` - Convenience wrapper for filtered queries

### 4. Tests

**Unit Tests:**
- `tests/unit/types/filter-expression.test.ts` (NEW)
- `tests/unit/execution/query-executor-filters.test.ts` (NEW)

**Integration Tests:**
- `tests/integration/query-filtered-mail.test.ts` (NEW)
- `tests/integration/query-filtered-finder.test.ts` (NEW)

**Test Cases:**
- ✅ Filter by boolean property (read status)
- ✅ Filter by string property with `contains`
- ✅ Filter by date property with `>`, `<`
- ✅ Filter by numeric property with `==`, `!=`, `<=`, `>=`
- ✅ Complex nested specifiers with filters
- ✅ Filter with limit parameter

---

## Implementation Tasks

### Task 1: Add FilterSpecifier Type (0.5 days)
- Define `FilterSpecifier` and `FilterExpression` types
- Add type guards
- Write unit tests

### Task 2: Implement JXA Filter Generation (1 day)
- Extend `buildObjectPath()` to handle FilterSpecifier
- Generate JXA `whose()` clauses
- Handle different operators
- Write unit tests

### Task 3: Update get_elements Tool (0.5 days)
- Add `filter` parameter to tool schema
- Update handler to accept filter
- Write tests

### Task 4: Integration Testing (1 day)
- Test filtered queries with Mail.app (unread, sender, date)
- Test filtered queries with Finder.app (file type, size, date)
- Test performance with large result sets

---

## Example Queries After Phase 2

**Unread emails from John:**
```typescript
const { elements } = await getElements(
  { type: "named", element: "mailbox", name: "inbox", container: "application" },
  "message",
  {
    where: {
      property: "sender",
      op: "contains",
      value: "john"
    },
    limit: 10
  }
);
```

**Files modified in last week:**
```typescript
const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
const { elements } = await getElements(
  { type: "named", element: "folder", name: "Documents", container: "application" },
  "file",
  {
    where: {
      property: "modification date",
      op: ">",
      value: oneWeekAgo.toISOString()
    }
  }
);
```

---

## Dependencies

**Requires:**
- ✅ Phase 1 complete (core query system)

**Blocks:**
- Phase 3 (property setters may use filters)

---

## Open Questions

1. **Should we support compound filters (AND/OR)?**
   - Phase 2: No (simple filters only)
   - Phase 2.5 or Phase 4: Consider if user requests

2. **Should we support negation filters (NOT)?**
   - Phase 2: No (use `!=` operator)
   - Future: Consider `not` operator

3. **How to handle app-specific filter syntax?**
   - Phase 2: Start with common patterns
   - Iterate based on testing

---

**Document Version:** 1.0
**Last Updated:** 2026-01-27
**Status:** Planning (blocked by Phase 1)
