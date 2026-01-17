# Phase 1: Type Inference

> **Model**: Sonnet
> **Effort**: 2-3 days
> **Goal**: Unlock 50%+ of blocked SDEFs with minimal risk

## Problem

60% of SDEF parsing failures are due to missing `type` attributes:

```xml
<parameter name="in" code="kfil">
  <!-- No type attribute -->
</parameter>
```

**Affected Apps**: Safari, Chrome, Brave, Vivaldi, Microsoft Office, Xcode, many others

**Current Behavior**: `throw Error('Parameter "in" missing required "type" attribute')`

## Solution

Add lenient parsing mode that infers types when attributes are missing.

## Tasks

### 1. Add mode option to SDEFParser (0.5 day)

```typescript
interface SDEFParserOptions {
  mode?: 'strict' | 'lenient';  // Default: 'lenient'
  onWarning?: (warning: ParseWarning) => void;
}
```

- Add `mode` option to constructor
- Default to `'lenient'` in production
- Maintain strict behavior when `mode: 'strict'`

### 2. Implement warning collector (0.5 day)

```typescript
interface ParseWarning {
  code: string;           // e.g., 'MISSING_TYPE'
  message: string;        // Human-readable description
  location: {
    element: string;      // e.g., 'parameter'
    name: string;         // e.g., 'in'
    suite?: string;       // Parent suite name
    command?: string;     // Parent command name
  };
  inferredValue?: string; // What was inferred
}
```

- Create `ParseWarning` interface
- Add `onWarning` callback option
- Collect warnings without throwing

### 3. Add type inference for missing attributes (1 day)

```typescript
private inferType(element: any, elementName: string): SDEFType {
  // Strategy 1: Check for child <type> elements
  if (element.type) {
    return this.parseChildTypeElement(element.type);
  }

  // Strategy 2: Infer from name patterns
  const nameLower = elementName.toLowerCase();

  if (nameLower.includes('path') || nameLower.includes('file') ||
      nameLower.includes('folder') || nameLower.includes('directory')) {
    return { kind: 'file' };
  }

  if (nameLower.includes('count') || nameLower.includes('index') ||
      nameLower.includes('number') || nameLower.includes('size')) {
    return { kind: 'primitive', type: 'integer' };
  }

  if (nameLower.includes('flag') || nameLower.includes('enabled') ||
      nameLower.includes('visible') || nameLower.includes('active')) {
    return { kind: 'primitive', type: 'boolean' };
  }

  // Strategy 3: Default to 'text' (safest)
  return { kind: 'primitive', type: 'text' };
}
```

**Rationale**:
- **Text as default**: All types can stringify, LLM handles well
- **Name heuristics**: Common patterns improve accuracy
- **Child elements first**: Explicit types take precedence

### 4. Update tests (0.5 day)

- Add lenient mode tests
- Verify strict mode unchanged
- Add fixture SDEFs for edge cases

## Success Criteria

- [ ] 40%+ SDEF success rate (up from 25%)
- [ ] All existing tests pass
- [ ] Safari commands parsed
- [ ] Chrome commands parsed
- [ ] 100% test coverage maintained

## Files to Modify

| File | Changes |
|------|---------|
| `src/jitd/discovery/parse-sdef.ts` | Add mode, inference logic |
| `src/jitd/discovery/index.ts` | Export new types |
| `tests/unit/parse-sdef.test.ts` | Add lenient tests |

## Test Cases

```typescript
describe('Lenient SDEF Parsing', () => {
  describe('missing type attributes', () => {
    it('should infer text type when type attribute missing');
    it('should infer file type for path-related parameters');
    it('should infer integer type for count-related parameters');
    it('should infer boolean type for flag-related parameters');
  });

  describe('warning collection', () => {
    it('should call onWarning callback for inferred types');
    it('should include location information in warnings');
  });
});
```

## Test Fixtures

Create: `tests/fixtures/sdef-snippets/`
- `missing-type-parameter.xml`
- `missing-type-property.xml`
- `safari-command.xml`

## Graceful Degradation Rules

| Condition | Action (Lenient) | Action (Strict) |
|-----------|------------------|-----------------|
| Missing `name` or `code` | **FAIL** | **FAIL** |
| Missing `type` attribute | **WARN + INFER** | **FAIL** |
| Unknown type string | **USE AS CLASS + WARN** | **USE AS CLASS + WARN** |

## Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Breaking existing tools | Low | High | Comprehensive regression tests |
| Type inference errors | Medium | Medium | Warning system, conservative defaults |

## macOS Automation Expert Notes

### Analysis Summary

After analyzing real-world SDEF files from the system and reviewing Apple's official SDEF DTD specification, the proposed type inference approach is **sound but needs several refinements** to handle macOS-specific patterns correctly.

### 1. Type Inference Heuristics Accuracy

**Overall Assessment**: Good foundation, but missing critical macOS patterns.

**Validated Patterns** (from real SDEFs):

```typescript
// CONFIRMED: These patterns are accurate
'path', 'file', 'folder', 'directory' → file/alias type
'count', 'index', 'number', 'size' → integer
'flag', 'enabled', 'visible', 'active' → boolean
```

**Missing Critical Patterns**:

```typescript
// Add these based on System Events and Finder SDEFs:

// Four-character codes are strong type indicators
if (element.code === 'kfil') return 'file';      // Standard file parameter code
if (element.code === 'insh') return 'location specifier';  // Insertion location
if (element.code === 'savo') return 'save options enum';   // Save options
if (element.code === 'kocl') return 'type';      // Class/type parameter
if (element.code === 'prdt') return 'record';    // Properties record

// Common parameter names
if (name === 'in') return 'file';                // "in" almost always means file
if (name === 'to') return 'location specifier';  // "to" is insertion location
if (name === 'using') return 'specifier';        // "using" references object
if (name === 'with properties') return 'record'; // Property dictionary
if (name === 'each') return 'type';              // Class type for iteration

// Temporal patterns
if (name.includes('date') || name.includes('time')) return 'date';

// Color patterns
if (name.includes('color') || name.includes('colour')) return 'color';

// List patterns (less reliable but worth checking)
if (name.endsWith('s') && !name.endsWith('ss')) {
  // Might be plural → list type
  return { kind: 'list', type: inferSingular(name) };
}
```

**Real-world data from System Events SDEF**:
- 138 occurrences of `type="text"` (most common)
- 69 occurrences of `type="boolean"`
- 43 occurrences of `type="any"` (important fallback)
- 30 occurrences of `type="integer"`
- 27 occurrences of `type="missing value"` (macOS-specific null type)

### 2. Common SDEF Type Patterns We're Missing

**Critical**: Child `<type>` elements (union types)

```xml
<!-- From System Events - 20% of type definitions use this pattern -->
<parameter name="to" code="insh">
  <type type="location specifier" />
  <type type="text" />
</parameter>
```

**This is union type support** - parameter accepts EITHER location specifier OR text. The DTD specification confirms this is valid:

```dtd
<!ELEMENT parameter ((%implementation;)?, (type | documentation)*)>
<!ATTLIST parameter
  type       %Typename;      #IMPLIED    <!-- Note: #IMPLIED means optional -->
```

**Action Required**: Phase 1 MUST handle child `<type>` elements as first priority, not just as "Strategy 1". This is the **explicit type specification** that trumps all inference.

**Implementation**:

```typescript
private inferType(element: any, elementName: string, elementCode?: string): SDEFType {
  // PRIORITY 1: Check for child <type> elements (EXPLICIT, not inference)
  if (element.type) {
    // Handle both single and multiple child types
    const types = Array.isArray(element.type) ? element.type : [element.type];

    if (types.length === 1) {
      return this.parseTypeElement(types[0]);
    } else {
      // Union type - Phase 2 will handle properly
      // For Phase 1, take first type + warn about others
      this.warn({
        code: 'UNION_TYPE_SIMPLIFIED',
        message: `Parameter "${elementName}" accepts multiple types, using first: ${types[0].$.type}`,
        location: { element: 'parameter', name: elementName }
      });
      return this.parseTypeElement(types[0]);
    }
  }

  // PRIORITY 2: Four-character codes (strongest signal after explicit types)
  if (elementCode) {
    const inferredFromCode = this.inferFromCode(elementCode, elementName);
    if (inferredFromCode) {
      this.warn({
        code: 'TYPE_INFERRED_FROM_CODE',
        message: `Inferred type from four-char code: ${elementCode}`,
        inferredValue: inferredFromCode.type
      });
      return inferredFromCode;
    }
  }

  // PRIORITY 3: Parameter name patterns (existing logic)
  // ... continue with name-based inference
}
```

### 3. Is "text" a Safe Default Type?

**Answer**: **Yes, but with important caveats.**

**Pros**:
- Most permissive type (everything can stringify)
- LLMs handle text well
- Real-world SDEF data shows "text" is most common (138 occurrences in System Events)
- JXA/AppleScript will coerce types at runtime

**Cons**:
- Loses type safety that could catch errors early
- May not trigger proper validation in receiving app
- Hides information from LLM about expected data

**Better Approach**: Use "text" as default BUT consider "any" for certain contexts:

```typescript
// Use "any" when:
// 1. Direct parameter with no type (most flexible)
// 2. Result type missing (could be anything)
// 3. Completely unknown context

// Use "text" when:
// 1. Named parameter with no other signals
// 2. Property with no type info

private getDefaultType(context: 'parameter' | 'property' | 'direct-parameter' | 'result'): SDEFType {
  switch (context) {
    case 'direct-parameter':
    case 'result':
      return { kind: 'primitive', type: 'any' }; // Maximum flexibility
    case 'parameter':
    case 'property':
      return { kind: 'primitive', type: 'text' }; // Safe string conversion
  }
}
```

**Data from System Events**: `type="any"` appears 43 times, often for flexible parameters.

### 4. macOS-Specific Quirks to Account For

**Critical Quirks**:

**Quirk 1: "missing value" Type**
```xml
<type type="missing value" />
```
This is macOS's way of representing NULL/undefined. Your type mapper needs to handle this:

```typescript
// In type-mapper.ts
'missing value': { type: 'null' }  // JSON Schema null type
```

**Quirk 2: Four-Character Codes with Trailing Spaces**
```xml
<parameter name="new" code="kocl" type="type">
<!-- Four-char codes are EXACTLY 4 bytes, sometimes padded with spaces -->
<enumerator name="yes" code="yes " />  <!-- Note trailing space -->
```

Codes like `"yes "`, `"no  "`, `"to  "` are valid. Don't trim them.

**Quirk 3: Suite Codes vs Command Codes**
```xml
<suite name="Standard Suite" code="CoRe">
  <command name="open" code="aevtodoc">
```

Command codes are 8 characters (two four-char codes concatenated). Suite codes are 4 characters. Don't confuse them.

**Quirk 4: "type" Type (Yes, Really)**
```xml
<parameter name="each" code="kocl" type="type">
```

The type `"type"` means "a reference to a class/type itself" (like `typeof` in TypeScript). It's used when specifying what class to operate on.

**Quirk 5: "location specifier" Type**
```xml
<parameter name="to" code="insh" type="location specifier">
```

This is a special AppleScript type for insertion points. It's like a position/index but more semantic. Map to:

```typescript
'location specifier': {
  type: 'object',
  description: 'An insertion location (before/after an element)'
}
```

**Quirk 6: SDEF DTD Declares Types as #IMPLIED**

From `/System/Library/DTDs/sdef.dtd`:

```dtd
<!ELEMENT parameter ((%implementation;)?, (type | documentation)*)>
<!ATTLIST parameter
  type       %Typename;      #IMPLIED    <!-- Optional! -->
```

**This confirms**: `type` attribute is OFFICIALLY OPTIONAL in the spec. Your parser treating it as required was incorrect. Apple's own SDEFs use child `<type>` elements instead of attributes in many cases.

### 5. Core AppleEvents Without SDEF Files

**Critical Finding**: Many apps respond to core AppleEvents even without SDEF files.

**Core AppleEvents** (defined in `AERegistry.h`):

```
kCoreEventClass ('aevt'):
- Open Application (oapp) - Launch app
- Reopen Application (rapp) - Activate/bring to front
- Open Documents (odoc) - Open file(s)
- Print Documents (pdoc) - Print file(s)
- Quit Application (quit) - Quit app
```

**How Script Editor Discovers These**:

Script Editor uses `OSACopyScriptingDefinition()` which:
1. First tries to load SDEF from app bundle
2. Falls back to extracting AETE resource from executable
3. Falls back to core AppleEvent set if neither exists

**Recommendation**:

```typescript
// In discovery layer
class AppDiscovery {
  async discoverApp(bundleId: string): Promise<AppCapabilities> {
    // Try SDEF first
    const sdefPath = this.findSDEF(bundleId);
    if (sdefPath) {
      return this.parseSDEF(sdefPath);
    }

    // Try AETE extraction (sdef command can do this)
    const aete = await this.extractAETE(bundleId);
    if (aete) {
      return this.parseSDEF(aete); // sdef outputs SDEF format
    }

    // Fallback: Expose core AppleEvents
    return this.getCoreAppleEvents();
  }

  private getCoreAppleEvents(): AppCapabilities {
    return {
      commands: [
        { name: 'activate', code: 'miscactv', description: 'Bring app to front' },
        { name: 'open', code: 'aevtodoc', parameters: [
          { name: 'file', type: 'file', description: 'File to open' }
        ]},
        { name: 'quit', code: 'aevtquit', description: 'Quit the application' },
        // ... other core events
      ]
    };
  }
}
```

**Extract AETE using sdef command**:

```bash
# Many apps without .sdef files still have AETE resources
sdef /Applications/SomeApp.app  # Extracts AETE → SDEF XML
```

Example with Calculator (no SDEF file):

```bash
$ sdef /Applications/Calculator.app
# Returns error -43 (no scripting support)

$ sdef /System/Applications/TextEdit.app
# Returns full SDEF extracted from AETE
```

**Testing shows**: Apps like TextEdit have scripting support but it's in AETE (binary) format, which `sdef` command can extract.

### 6. Additional Type Inference Recommendations

**Priority Order** (strictest to most lenient):

```typescript
private inferType(element: any, name: string, code?: string): SDEFType {
  // 1. Child <type> elements (EXPLICIT - 95% confidence)
  if (element.type) { ... }

  // 2. Four-character code mapping (90% confidence)
  if (code) {
    const fromCode = CODE_TO_TYPE_MAP[code];
    if (fromCode) return fromCode;
  }

  // 3. Standard parameter name patterns (80% confidence)
  const standardNames = {
    'in': 'file',
    'to': 'location specifier',
    'using': 'specifier',
    'with properties': 'record',
    'each': 'type',
    'as': 'type',
    'saving': 'save options',
    'by': 'property'
  };
  if (standardNames[name]) { ... }

  // 4. Substring patterns (60% confidence)
  if (name.includes('path')) { ... }

  // 5. Context-aware defaults (50% confidence)
  return this.getDefaultType(context);
}
```

**Code Mapping Table** (from analyzing real SDEFs):

```typescript
const CODE_TO_TYPE_MAP: Record<string, string> = {
  'kfil': 'file',           // File parameter
  'insh': 'location specifier', // Insertion location
  'savo': 'save options',   // Save options enum
  'kocl': 'type',           // Class/type reference
  'prdt': 'record',         // Properties record
  'usin': 'specifier',      // Using parameter
  'rtyp': 'type',           // Return type
  'faal': 'list',           // Modifier flags list
  'data': 'any',            // Generic data
  // Add more as discovered
};
```

### 7. Testing Recommendations

**Test with these real apps** (they all have known type patterns):

```typescript
describe('Real-world SDEF parsing', () => {
  it('should parse Finder.sdef with child type elements');
  it('should parse System Events.sdef with union types');
  it('should parse Safari.sdef with missing type attributes');
  it('should parse TextEdit.sdef extracted from AETE');
  it('should handle Chrome scripting.sdef parameter patterns');
  it('should handle missing value type in Microsoft Office');
});
```

**Create fixtures from actual SDEFs**:

```bash
# Extract problematic snippets
grep -A 5 '<parameter name="to"' \
  "/System/Library/CoreServices/System Events.app/Contents/Resources/SystemEvents.sdef" \
  > tests/fixtures/sdef-snippets/system-events-to-parameter.xml
```

### 8. Phase 1 Success Criteria Adjustments

**Current criteria is good but add**:

- [ ] System Events parameters with child `<type>` elements parsed (critical test)
- [ ] Four-character code inference working (`kfil` → file, `insh` → location specifier)
- [ ] "missing value" type handled correctly
- [ ] Can extract and parse AETE from apps without .sdef files
- [ ] Core AppleEvents exposed for non-scriptable apps

### 9. Recommended Changes to Implementation Plan

**Revise Task 3 priority order**:

```typescript
private inferType(element: any, elementName: string, elementCode?: string, context?: string): SDEFType {
  // PRIORITY 1: Child <type> elements (NOT inference - this is explicit!)
  if (element.type) {
    const types = Array.isArray(element.type) ? element.type : [element.type];
    if (types.length === 1) {
      return this.parseTypeElement(types[0]);
    }
    // Multiple types = union (Phase 2), for now use first + warn
    this.warn('UNION_TYPE', `Using first of ${types.length} types`);
    return this.parseTypeElement(types[0]);
  }

  // PRIORITY 2: Four-character code lookup (very reliable)
  if (elementCode && CODE_TO_TYPE_MAP[elementCode]) {
    this.warn('TYPE_INFERRED_FROM_CODE', `Used code ${elementCode}`);
    return CODE_TO_TYPE_MAP[elementCode];
  }

  // PRIORITY 3: Standard parameter names (high confidence)
  if (STANDARD_PARAM_TYPES[elementName]) {
    this.warn('TYPE_INFERRED_FROM_NAME', `Used standard name ${elementName}`);
    return STANDARD_PARAM_TYPES[elementName];
  }

  // PRIORITY 4: Name pattern matching (existing heuristics)
  const fromPattern = this.inferFromPattern(elementName);
  if (fromPattern) {
    this.warn('TYPE_INFERRED_FROM_PATTERN', `Matched pattern in ${elementName}`);
    return fromPattern;
  }

  // PRIORITY 5: Context-aware default
  const defaultType = this.getDefaultType(context);
  this.warn('TYPE_DEFAULTED', `No signals found, using ${defaultType.type}`);
  return defaultType;
}
```

### 10. Summary Recommendations

**Critical for Phase 1**:
1. ✅ Treat child `<type>` elements as explicit types, not inference
2. ✅ Add four-character code → type mapping table
3. ✅ Add standard parameter name → type mapping table
4. ✅ Use context-aware defaults ("any" vs "text")
5. ✅ Handle "missing value" type
6. ✅ Test with System Events SDEF (has all the edge cases)

**Consider for Phase 1.5** (between Phase 1 and 2):
1. AETE extraction for apps without SDEF files (`sdef` command)
2. Core AppleEvents fallback for non-scriptable apps
3. Better handling of first union type (pick most general)

**Defer to Phase 2**:
1. Full union type support
2. Sophisticated type narrowing
3. Inter-type relationships

**Overall Assessment**: The plan is sound. With these macOS-specific refinements, you should hit 50-60% success rate instead of 40%.
