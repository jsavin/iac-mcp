# Phase 2: Multi-Type Support

> **Model**: Sonnet
> **Effort**: 1-2 days
> **Goal**: Handle union types for System Events

## Problem

20% of SDEF parsing failures are due to child `<type>` elements:

```xml
<property name="home directory" code="home" access="r">
  <type type="text" />
  <type type="file" />
</property>
```

**Affected Apps**: System Events (109KB SDEF with 100+ commands)

**Current Behavior**: Parser only looks for `type` attribute, ignores child elements

## Solution

Parse child `<type>` elements and create union types or use first type as primary.

## Tasks

### 1. Extend SDEFType union (0.5 day)

```typescript
// In src/types/sdef.ts
export type SDEFType =
  | { kind: 'primitive'; type: string }
  | { kind: 'class'; className: string }
  | { kind: 'file' }
  | { kind: 'list'; elementType: SDEFType }
  | { kind: 'union'; types: SDEFType[] };  // NEW
```

### 2. Parse child `<type>` elements (0.5 day)

```typescript
private parseTypeFromElement(element: any): SDEFType {
  // Check for type attribute first
  if (element['@_type']) {
    return this.parseTypeString(element['@_type']);
  }

  // Check for child <type> elements
  if (element.type) {
    const typeElements = Array.isArray(element.type)
      ? element.type
      : [element.type];

    const types = typeElements.map((t: any) =>
      this.parseTypeString(t['@_type'])
    );

    if (types.length === 1) {
      return types[0];
    }

    // Multiple types: create union
    return { kind: 'union', types };
  }

  // No type info: use inference (Phase 1)
  return this.inferType(element, element['@_name']);
}
```

### 3. Update TypeMapper for unions (0.5 day)

```typescript
// In src/jitd/tool-generator/type-mapper.ts
export function mapSDEFTypeToJSONSchema(sdefType: SDEFType): JSONSchema {
  switch (sdefType.kind) {
    case 'union':
      // Use first type as primary for JSON Schema
      // Document alternatives in description
      const primaryType = mapSDEFTypeToJSONSchema(sdefType.types[0]);
      const alternatives = sdefType.types
        .slice(1)
        .map(t => describeType(t))
        .join(', ');

      return {
        ...primaryType,
        description: primaryType.description
          ? `${primaryType.description} (also accepts: ${alternatives})`
          : `Also accepts: ${alternatives}`
      };

    // ... other cases
  }
}
```

### 4. Test with System Events (0.5 day)

- Parse System Events SDEF
- Verify tools generated
- Check type mappings correct

## Success Criteria

- [ ] System Events parsed successfully
- [ ] 50+ new tools from System Events
- [ ] Union types correctly mapped
- [ ] 60%+ SDEF success rate

## Files to Modify

| File | Changes |
|------|---------|
| `src/types/sdef.ts` | Add union type |
| `src/jitd/discovery/parse-sdef.ts` | Parse child types |
| `src/jitd/tool-generator/type-mapper.ts` | Map unions |
| `tests/unit/parse-sdef.test.ts` | Union tests |

## Test Cases

```typescript
describe('child type elements', () => {
  it('should parse single child type element');
  it('should create union from multiple child types');
  it('should use first type for JSON Schema mapping');
  it('should document alternatives in description');
});
```

## Test Fixtures

Create in `tests/fixtures/sdef-snippets/`:
- `child-type-single.xml`
- `child-type-multiple.xml`
- `system-events-property.xml`

## Graceful Degradation Rules

| Condition | Action |
|-----------|--------|
| Single child `<type>` | Parse as primary type |
| Multiple child `<type>` | Create union, use first as primary |
| Both attribute and children | Prefer attribute (explicit wins) |

## Example: System Events Property

**Input SDEF**:
```xml
<property name="home directory" code="home" access="r">
  <type type="text" />
  <type type="file" />
</property>
```

**Generated JSON Schema**:
```json
{
  "type": "string",
  "description": "The home directory path (also accepts: file)"
}
```

## Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Union type complexity | Low | Low | Use first type as primary |
| Performance degradation | Low | Low | Minimal additional parsing |
