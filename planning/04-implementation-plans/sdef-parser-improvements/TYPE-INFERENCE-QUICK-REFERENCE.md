# SDEF Type Inference - Quick Reference

**Status:** Design Complete, Ready for Implementation
**Impact:** Unlocks 35 apps (Safari, Mail, Calendar, Photos, etc.)

---

## The Problem in 30 Seconds

**35 apps generate 0 tools** because their SDEF files use this pattern:
```xml
<parameter name="in" code="dcnm">
    <type type="document"/>  <!-- Child element, not attribute -->
</parameter>
```

Instead of:
```xml
<parameter name="in" code="dcnm" type="document"/>  <!-- Attribute -->
```

Parser expects attribute form, crashes on child element form.

---

## The Solution in 30 Seconds

**Two-part fix:**

1. **Support child `<type>` elements properly** (partially exists, needs fixes)
2. **Expand type inference** when type is missing entirely:
   - 9 four-char codes → **50+ codes**
   - 7 standard names → **25+ names**
   - Add command/suite context awareness
   - Add conflict detection

---

## Implementation Checklist

### File: `src/jitd/discovery/parse-sdef.ts`

**1. Expand CODE_TO_TYPE_MAP (line 122-132)**
```typescript
// ADD 40+ MORE CODES:
const CODE_TO_TYPE_MAP: Record<string, string> = {
  // Existing (keep all)
  kfil: 'file',
  insh: 'location specifier',
  // ... 7 more

  // NEW - Text types
  TEXT: 'text',
  utxt: 'text',
  'utf8': 'text',
  stxt: 'text',

  // NEW - Numeric types
  long: 'integer',
  shor: 'integer',
  comp: 'integer',
  doub: 'real',
  sing: 'real',

  // NEW - Boolean
  bool: 'boolean',

  // NEW - Date/Time
  ldt: 'date',
  isot: 'date',

  // NEW - Lists/Records
  reco: 'record',
  list: 'list',

  // NEW - Specifiers
  obj: 'specifier',
  insl: 'location specifier',

  // NEW - Special
  '****': 'any',  // Direct parameter wildcard
  msng: 'missing value',
  null: 'missing value',

  // See full list in design doc
};
```

**2. Expand STANDARD_PARAM_TYPES (line 136-146)**
```typescript
// ADD 15+ MORE NAMES:
const STANDARD_PARAM_TYPES: Record<string, string> = {
  // Existing (keep all)
  in: 'file',
  to: 'location specifier',
  // ... 6 more

  // NEW - File/path
  target: 'file',
  from: 'file',
  at: 'location specifier',
  into: 'location specifier',

  // NEW - Text
  text: 'text',
  message: 'text',
  content: 'text',
  body: 'text',
  name: 'text',
  title: 'text',

  // NEW - Object references
  of: 'specifier',
  for: 'specifier',

  // See full list in design doc
};
```

**3. Fix inferTypeFromElement() (line 809-850)**

**Current issue:** Falls back to `{ kind: 'any' }` if child types are malformed.

**Fix:**
```typescript
// REPLACE this block (line 846-849):
// Fallback
return { kind: 'any' };

// WITH:
// Fallback to inference with warning
this.warn({
  code: 'MALFORMED_TYPE_ELEMENTS',
  message: 'Multiple <type> elements but none have type attributes',
  location: { element: elementType, name: elementName, suite: this.currentSuite, command: this.currentCommand },
});
return this.inferType(elementName, element['@_code'], elementType as any);
```

**4. Add Command Context Inference (NEW - insert after line 901)**

**Insert between code mapping and standard names (PRIORITY 2.5):**
```typescript
// NEW: PRIORITY 2.5 - Command context inference
if (this.currentCommand) {
  const cmdName = this.currentCommand.toLowerCase();
  const elemName = elementName.toLowerCase();

  // Open/launch commands → file type
  if ((cmdName.includes('open') || cmdName.includes('launch')) &&
      (elemName === 'target' || context === 'direct-parameter')) {
    inferredType = { kind: 'file' };
    this.warn({
      code: 'TYPE_INFERRED_FROM_COMMAND_CONTEXT',
      message: `Type inferred from command context "${this.currentCommand}": file`,
      location: { element: context || 'unknown', name: elementName, suite: this.currentSuite, command: this.currentCommand },
      inferredValue: 'file',
    });
    return inferredType;
  }

  // Save commands → save options
  if (cmdName.includes('save') && elemName.includes('saving')) {
    inferredType = { kind: 'save_options' };
    this.warn({
      code: 'TYPE_INFERRED_FROM_COMMAND_CONTEXT',
      message: `Type inferred from command context "${this.currentCommand}": save options`,
      location: { element: context || 'unknown', name: elementName, suite: this.currentSuite, command: this.currentCommand },
      inferredValue: 'save options',
    });
    return inferredType;
  }

  // Move/copy commands → location specifier
  if ((cmdName.includes('move') || cmdName.includes('copy')) && elemName === 'to') {
    inferredType = { kind: 'location_specifier' };
    this.warn({
      code: 'TYPE_INFERRED_FROM_COMMAND_CONTEXT',
      message: `Type inferred from command context "${this.currentCommand}": location specifier`,
      location: { element: context || 'unknown', name: elementName, suite: this.currentSuite, command: this.currentCommand },
      inferredValue: 'location specifier',
    });
    return inferredType;
  }
}
```

**5. Expand Substring Patterns (line 924-997)**

**Add these to existing patterns:**
```typescript
// File-related (ADD to existing pattern)
if (
  lowerName.includes('path') ||
  lowerName.includes('file') ||
  lowerName.includes('folder') ||
  lowerName.includes('directory') ||
  lowerName.includes('url') ||      // NEW
  lowerName.includes('location') || // NEW
  lowerName === 'target'             // NEW: exact match
) {
  // ... existing code
}

// Text-related (ADD to existing or CREATE NEW)
if (
  lowerName.includes('text') ||
  lowerName.includes('name') ||     // NEW
  lowerName.includes('title') ||    // NEW
  lowerName.includes('message') ||  // NEW
  lowerName.includes('content')     // NEW
) {
  inferredType = { kind: 'primitive', type: 'text' };
  this.warn({
    code: 'TYPE_INFERRED_FROM_PATTERN',
    message: `Type inferred from name pattern "${elementName}": text`,
    location: { element: context || 'unknown', name: elementName, suite: this.currentSuite, command: this.currentCommand },
    inferredValue: 'text',
  });
  return inferredType;
}

// Object reference patterns (NEW - add before context defaults)
if (
  lowerName === 'of' ||
  lowerName === 'for' ||
  lowerName === 'from' ||
  lowerName === 'with' ||
  (lowerName.includes('object') && !lowerName.includes('count'))
) {
  inferredType = { kind: 'any' };
  this.warn({
    code: 'TYPE_INFERRED_FROM_PATTERN',
    message: `Type inferred from name pattern "${elementName}": any (object reference)`,
    location: { element: context || 'unknown', name: elementName, suite: this.currentSuite, command: this.currentCommand },
    inferredValue: 'any',
  });
  return inferredType;
}
```

---

## Testing Plan

### Unit Tests to Add

**File:** `tests/unit/parse-sdef.test.ts`

```typescript
describe('Type Inference Enhancements', () => {
  describe('CODE_TO_TYPE_MAP', () => {
    it('should map TEXT to text', () => {
      // Test new code mappings
    });

    it('should map long to integer', () => {
      // Test numeric code mappings
    });

    it('should map **** to any', () => {
      // Test wildcard code
    });

    // Test all 50+ codes
  });

  describe('STANDARD_PARAM_TYPES', () => {
    it('should map "target" to file', () => {
      // Test new name patterns
    });

    it('should map "message" to text', () => {
      // Test text name patterns
    });

    // Test all 25+ names
  });

  describe('Command Context Inference', () => {
    it('should infer file type for "open" command target', () => {
      // Test command context
    });

    it('should infer save options for "save" command saving param', () => {
      // Test save command context
    });
  });

  describe('inferTypeFromElement', () => {
    it('should handle multiple child types with valid attributes', () => {
      // Test union type handling
    });

    it('should fall back to inference when child types are malformed', () => {
      // Test malformed type element handling
    });
  });
});
```

---

### Integration Tests to Add

**File:** `tests/integration/real-sdef-parsing.test.ts`

```typescript
describe('Real SDEF Parsing - Previously Failing Apps', () => {
  it('should parse Safari.sdef successfully', async () => {
    const sdefPath = '/Applications/Safari.app/Contents/Resources/Safari.sdef';
    const dict = await parser.parse(sdefPath);

    expect(dict.suites.length).toBeGreaterThan(0);

    // Find "do JavaScript" command
    const safariSuite = dict.suites.find(s => s.name === 'Safari suite');
    expect(safariSuite).toBeDefined();

    const doJSCmd = safariSuite?.commands.find(c => c.name === 'do JavaScript');
    expect(doJSCmd).toBeDefined();

    // Verify parameter types
    const inParam = doJSCmd?.parameters.find(p => p.name === 'in');
    expect(inParam?.type).toEqual({ kind: 'class', className: 'document' });
  });

  it('should parse Mail.sdef successfully', async () => {
    // Similar test for Mail
  });

  it('should parse Calendar.sdef successfully', async () => {
    // Similar test for Calendar
  });

  it('should parse Photos.sdef successfully', async () => {
    // Similar test for Photos
  });
});

describe('Tool Count Verification', () => {
  it('should generate tools for 100 apps (up from 65)', async () => {
    // Run full discovery
    // Count apps with tools > 0
    // Verify count >= 100
  });
});
```

---

## Success Metrics

**Before:**
- Apps with tools: 65
- Apps with 0 tools: 35 (Safari, Mail, Calendar, etc.)

**After:**
- Apps with tools: 100 ✅
- Apps with 0 tools: 0 ✅

**Target:** **100% of apps with SDEF files generate at least 1 tool**

---

## Risk Mitigation

**Risk:** False positives in type inference
**Mitigation:** Comprehensive tests + conservative defaults + warnings

**Risk:** Performance regression
**Mitigation:** No algorithmic changes + caching already exists

**Risk:** Breaking existing behavior
**Mitigation:** All changes additive + regression tests

---

## What NOT to Change

- ❌ Don't modify strict mode behavior (keep throwing errors)
- ❌ Don't change existing warning codes
- ❌ Don't remove existing inference logic
- ❌ Don't modify type system (`SDEFType` union) - future enhancement

---

## Priority Order for Implementation

1. **Expand CODE_TO_TYPE_MAP** (highest impact, lowest risk)
2. **Expand STANDARD_PARAM_TYPES** (high impact, low risk)
3. **Fix inferTypeFromElement()** (medium impact, medium risk)
4. **Add command context inference** (medium impact, low risk)
5. **Expand substring patterns** (low impact, low risk)

---

## Files Modified

- ✅ `src/jitd/discovery/parse-sdef.ts` (only file to change)
- ✅ `tests/unit/parse-sdef.test.ts` (add tests)
- ✅ `tests/integration/real-sdef-parsing.test.ts` (add tests)

---

## References

- **Full Design:** `SDEF-TYPE-INFERENCE-DESIGN.md` (this directory)
- **SDEF Spec:** [SDEF Man Page](https://keith.github.io/xcode-man-pages/sdef.5.html)
- **Apple Event Codes:** AEDataModel.h (Carbon framework)

---

**Ready to implement? See full design doc for complete code changes and edge cases.**
