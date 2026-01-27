# Query Executor Test Documentation

**Created:** 2026-01-27
**Status:** Tests written, implementation pending
**Component:** Phase 1 Object Model Exposure - Query Executor

---

## Overview

Comprehensive test suite for the query executor component that will enable predefined queries against Calendar.app via JXA. Tests follow the 100% coverage requirement and are designed to fail initially until the component is implemented.

---

## Test Files Created

### 1. Unit Tests: `tests/unit/query-executor.test.ts`

**Coverage:** 100% of planned query executor functionality

**Test Suites:**

#### `generateJXAScript`
- ✅ Generate script for "today" time range
- ✅ Generate script for "this_week" time range
- ✅ Generate script for "this_month" time range
- ✅ Generate script for "all" time range
- ✅ Include calendar name filter when provided
- ✅ Access all calendars when no calendar name provided
- ✅ Map events to include required fields (summary, startDate, endDate, location)
- ✅ Include filter logic in generated script

#### `getFilterDate`
- ✅ Return start of today for "today"
- ✅ Return start of week for "this_week" (Sunday)
- ✅ Handle edge case: today is Sunday
- ✅ Handle edge case: today is Saturday
- ✅ Return start of month for "this_month"
- ✅ Return far past date for "all" (1900-01-01)
- ✅ Throw error for invalid time range
- ✅ Normalize time to midnight for "today"
- ✅ Handle dates at year boundaries (Dec 31)
- ✅ Handle leap year dates (Feb 29)
- ✅ Handle timezone-aware dates

#### `executeJXA`
- ✅ Execute JXA script successfully
- ✅ Trim whitespace from output
- ✅ Handle execution error
- ✅ Handle stderr in error message
- ✅ Use error message when stderr is empty
- ✅ Set timeout to 30 seconds
- ✅ Call osascript with correct arguments

#### `executeQuery`
- ✅ Execute query with timeRange="today"
- ✅ Execute query with calendar name filter
- ✅ Return array of events
- ✅ Handle empty result
- ✅ Handle app not found error
- ✅ Handle permission denied error
- ✅ Handle invalid JSON response
- ✅ Handle malformed JSON response
- ✅ Parse valid JSON with complex event data

#### Edge Cases
- ✅ Handle very long event summaries (1000+ chars)
- ✅ Handle special characters in calendar name
- ✅ Handle events with missing location

#### Error Scenarios
- ✅ Propagate network-like errors
- ✅ Handle script timeout
- ✅ Handle large result sets (1000+ events)

**Total Test Cases:** 42 unit tests

---

### 2. Integration Tests: `tests/integration/calendar-query.test.ts`

**Coverage:** End-to-end Calendar.app queries

**Prerequisites:**
- macOS system with Calendar.app installed
- Automation permissions granted to Terminal/process
- At least one calendar configured in Calendar.app

**Test Suites:**

#### Basic Calendar Access
- ✅ Access Calendar.app
- ✅ List calendars

#### Query Events - Today
- ✅ Query events for today
- ✅ Verify event structure (summary, startDate, endDate)
- ✅ Verify startDate is today or later

#### Query Events - This Week
- ✅ Query events for this week
- ✅ Verify all events are from this week or later

#### Query Events - This Month
- ✅ Query events for this month
- ✅ Verify all events are from this month or later

#### Query Events - All
- ✅ Query all events
- ✅ Verify structure regardless of date

#### Query Events - By Calendar Name
- ✅ Query events from specific calendar
- ✅ Verify all events are from specified calendar

#### Error Scenarios
- ✅ Handle non-existent calendar name
- ✅ Handle non-existent app
- ✅ Handle invalid bundle ID

#### Event Structure Validation
- ✅ Verify event properties are correctly typed (string, Date, etc.)

#### Performance and Limits
- ✅ Handle querying large number of events
- ✅ Handle empty calendars gracefully
- ✅ Verify query completes in reasonable time (<30s)

#### Date Filtering Accuracy
- ✅ Only return events from specified time range
- ✅ Verify filter date boundaries are correct

#### Special Characters and Edge Cases
- ✅ Handle events with special characters in summary (<>"'&)

**Total Test Cases:** 19 integration tests

**Note:** Integration tests may return empty arrays if no events exist in Calendar.app. This is expected behavior and does not indicate test failure.

---

## Component Design (From Planning Docs)

### Expected Implementation

**Location:** `src/jitd/query-executor/`

**Interface:**
```typescript
interface QueryParams {
  app: string;
  timeRange: 'today' | 'this_week' | 'this_month' | 'all';
  calendarName?: string;
}

interface CalendarEvent {
  summary: string;
  startDate: string;  // ISO 8601
  endDate: string;    // ISO 8601
  location?: string;
  calendar?: {
    name: string;
  };
}
```

**Functions:**
```typescript
// Execute predefined query against Calendar.app
async function executeQuery(params: QueryParams): Promise<CalendarEvent[]>

// Generate JXA script for query
function generateJXAScript(params: QueryParams): string

// Get filter date based on time range
function getFilterDate(timeRange: string, now: Date): Date

// Execute JXA script via osascript
async function executeJXA(script: string): Promise<string>
```

---

## Running the Tests

### Run Unit Tests
```bash
cd /Users/jake/dev/jsavin/iac-mcp-object-model-exposure
npm run test -- tests/unit/query-executor.test.ts
```

### Run Integration Tests
```bash
cd /Users/jake/dev/jsavin/iac-mcp-object-model-exposure
npm run test -- tests/integration/calendar-query.test.ts
```

### Run All Query Executor Tests
```bash
npm run test -- tests/unit/query-executor.test.ts tests/integration/calendar-query.test.ts
```

---

## Expected Test Results

### Before Implementation
- ✅ Tests compile successfully (TypeScript syntax valid)
- ❌ All tests FAIL (component not implemented)
- Expected error: Module not found or functions undefined

### After Implementation
- ✅ All unit tests PASS (100% coverage required)
- ✅ Integration tests PASS (if Calendar.app accessible)
- ✅ Coverage report shows 100% for all metrics:
  - Statements: 100%
  - Branches: 100%
  - Functions: 100%
  - Lines: 100%

---

## Test Strategy

### Unit Tests (Mocked)
- Mock `child_process.execFile` for JXA execution
- Test all code paths (happy path + error paths)
- Test edge cases (boundary conditions, special characters)
- Test error handling (app not found, permission denied, timeout)
- Verify JXA script generation logic
- Verify date filtering logic

### Integration Tests (Real Calendar.app)
- Test actual osascript execution
- Test real Calendar.app queries
- Verify JSON parsing works with real data
- Test with various time ranges
- Test with calendar name filters
- Handle cases where Calendar.app has no events (empty array is valid)

---

## Key Testing Principles

1. **Tests written BEFORE implementation** (TDD approach)
2. **100% coverage required** (unit + integration)
3. **Tests should fail initially** (no implementation yet)
4. **Tests document expected behavior**
5. **Edge cases explicitly tested** (leap years, year boundaries, timezones)
6. **Error paths thoroughly covered** (app not found, permission denied, invalid JSON)

---

## Coverage Requirements

Per [CODE-QUALITY.md](../CODE-QUALITY.md):

- **Statements:** 100%
- **Branches:** 100%
- **Functions:** 100%
- **Lines:** 100%

**CI Enforcement:** PRs will be blocked if coverage < 100%

---

## Next Steps

1. ✅ Tests written (this document)
2. 📝 Implement query executor component
3. 📝 Run tests to verify implementation
4. 📝 Fix any failing tests
5. 📝 Verify 100% coverage
6. 📝 Commit and create PR

---

## Related Documents

- **[02-design.md](../planning/04-implementation-plans/object-model-exposure/02-design.md)** - Component design
- **[CODE-QUALITY.md](../CODE-QUALITY.md)** - Testing standards
- **[README.md](../planning/04-implementation-plans/object-model-exposure/README.md)** - Feature overview

---

## Notes

### Why These Tests?

1. **generateJXAScript tests:** Ensure correct JXA syntax for all time ranges and filters
2. **getFilterDate tests:** Verify date logic handles all edge cases correctly
3. **executeJXA tests:** Ensure osascript execution works with proper error handling
4. **executeQuery tests:** End-to-end unit tests with mocked JXA execution
5. **Integration tests:** Verify real Calendar.app interaction works

### Known Limitations

1. **Integration tests require Calendar.app access** - Tests will skip if not accessible
2. **Integration tests may return empty arrays** - Not a failure if user has no events
3. **Integration tests require automation permissions** - System Preferences > Privacy & Security > Automation

### Test Maintenance

- Update tests if component interface changes
- Add new tests for new features (Phase 2: custom filters, Phase 3: validation)
- Keep integration tests aligned with unit test coverage
- Document any new edge cases discovered during implementation
