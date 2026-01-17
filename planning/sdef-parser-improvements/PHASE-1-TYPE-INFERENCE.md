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
