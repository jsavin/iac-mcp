# SDEF Parser

The SDEF (Scripting Definition) Parser extracts structured data from macOS SDEF XML files, which define the scriptable capabilities of applications.

## Overview

This module provides a robust XML parser that converts SDEF files into structured TypeScript objects that can be used to generate MCP tools dynamically.

## Features

- **Full SDEF Support**: Parses all SDEF elements (commands, classes, properties, enumerations, etc.)
- **Type Mapping**: Converts AppleScript types to structured SDEFType discriminated union
- **Error Handling**: Comprehensive validation with descriptive error messages
- **Caching**: Automatically caches parsed results for performance
- **Fast**: Parses large SDEF files (like Finder's ~200KB file) in ~7ms

## Usage

### Basic Usage

```typescript
import { SDEFParser } from './parse-sdef.js';

const parser = new SDEFParser();

// Parse from file
const result = await parser.parse('/path/to/app.sdef');

// Parse from XML content
const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="My App">
  <suite name="Standard Suite" code="CoRe">
    <command name="open" code="aevtodoc">
      <direct-parameter type="file"/>
    </command>
  </suite>
</dictionary>`;

const result = await parser.parseContent(xmlContent);
```

### Using the Singleton

```typescript
import { sdefParser } from './parse-sdef.js';

// Singleton instance with caching
const result = await sdefParser.parse('/path/to/app.sdef');
```

### Accessing Parsed Data

```typescript
const result = await sdefParser.parse('/path/to/Finder.app/Contents/Resources/Finder.sdef');

console.log(result.title); // "Untitled" (Finder doesn't have a title)
console.log(result.suites.length); // 9

// Iterate through suites
for (const suite of result.suites) {
  console.log(`Suite: ${suite.name} (${suite.code})`);

  // Commands
  for (const command of suite.commands) {
    console.log(`  Command: ${command.name} (${command.code})`);
    console.log(`    Parameters: ${command.parameters.length}`);

    if (command.directParameter) {
      console.log(`    Direct parameter: ${command.directParameter.type.kind}`);
    }

    if (command.result) {
      console.log(`    Returns: ${command.result.kind}`);
    }
  }

  // Classes
  for (const cls of suite.classes) {
    console.log(`  Class: ${cls.name} (${cls.code})`);
    console.log(`    Properties: ${cls.properties.length}`);
    console.log(`    Elements: ${cls.elements.length}`);
  }

  // Enumerations
  for (const enumeration of suite.enumerations) {
    console.log(`  Enum: ${enumeration.name} (${enumeration.code})`);
    console.log(`    Values: ${enumeration.enumerators.length}`);
  }
}
```

## Type System

The parser converts SDEF types to a discriminated union (`SDEFType`) for type safety:

```typescript
type SDEFType =
  | { kind: 'primitive'; type: 'text' | 'integer' | 'real' | 'boolean' }
  | { kind: 'file' }
  | { kind: 'list'; itemType: SDEFType }
  | { kind: 'record'; properties: Record<string, SDEFType> }
  | { kind: 'class'; className: string }
  | { kind: 'enumeration'; enumerationName: string };
```

### Type Mapping

| SDEF Type | SDEFType |
|-----------|----------|
| `text`, `string` | `{ kind: 'primitive', type: 'text' }` |
| `integer`, `number` | `{ kind: 'primitive', type: 'integer' }` |
| `real`, `double` | `{ kind: 'primitive', type: 'real' }` |
| `boolean` | `{ kind: 'primitive', type: 'boolean' }` |
| `file`, `alias` | `{ kind: 'file' }` |
| `list of X` | `{ kind: 'list', itemType: parseType(X) }` |
| `record` | `{ kind: 'record', properties: {...} }` |
| Custom class | `{ kind: 'class', className: 'ClassName' }` |
| Custom enum | `{ kind: 'enumeration', enumerationName: 'EnumName' }` |

## Data Structure

### SDEFDictionary

Top-level structure containing all parsed data:

```typescript
interface SDEFDictionary {
  title: string;          // "Untitled" if not specified
  suites: SDEFSuite[];
}
```

### SDEFSuite

Group of related commands, classes, and enumerations:

```typescript
interface SDEFSuite {
  name: string;
  code: string;                 // 4-character code
  description?: string;
  commands: SDEFCommand[];
  classes: SDEFClass[];
  enumerations: SDEFEnumeration[];
}
```

### SDEFCommand

Operation that can be performed:

```typescript
interface SDEFCommand {
  name: string;
  code: string;                 // 8-character code (two 4-char codes)
  description?: string;
  parameters: SDEFParameter[];
  result?: SDEFType;
  directParameter?: SDEFParameter;
}
```

### SDEFParameter

Input to a command:

```typescript
interface SDEFParameter {
  name: string;
  code: string;                 // 4-character code
  type: SDEFType;
  description?: string;
  optional?: boolean;
}
```

Note: Direct parameters use `name: 'direct-parameter'` and `code: '----'`.

### SDEFClass

Object type in the app's object model:

```typescript
interface SDEFClass {
  name: string;
  code: string;                 // 4-character code
  description?: string;
  properties: SDEFProperty[];
  elements: SDEFElement[];
}
```

### SDEFProperty

Attribute of a class:

```typescript
interface SDEFProperty {
  name: string;
  code: string;                 // 4-character code (may have trailing spaces)
  type: SDEFType;
  description?: string;
  access: 'r' | 'w' | 'rw';    // read, write, read-write
}
```

### SDEFEnumeration

Set of named values:

```typescript
interface SDEFEnumeration {
  name: string;
  code: string;                 // 4-character code
  enumerators: SDEFEnumerator[];
}

interface SDEFEnumerator {
  name: string;
  code: string;                 // 4-character code
  description?: string;
}
```

## Four-Character Codes

AppleScript uses four-character codes to identify elements:

- **Commands**: 8 characters (two 4-character codes combined)
  - Example: `"aevtodoc"` = `"aevt"` (Apple Event) + `"odoc"` (Open Document)
- **Parameters**: 4 characters
  - Example: `"usin"` (using)
- **Properties**: 4 characters (may have trailing spaces)
  - Example: `"ID  "` (ID with spaces)
- **Classes**: 4 characters
  - Example: `"capp"` (application)
- **Enumerations**: 4 characters
  - Example: `"savo"` (save options)

## Error Handling

The parser provides descriptive errors for common issues:

```typescript
try {
  const result = await parser.parseContent(xmlContent);
} catch (error) {
  // Error messages include:
  // - "Invalid SDEF format: missing <dictionary> root element"
  // - "Dictionary missing required 'title' attribute"
  // - "Invalid code 'xyz' for command 'test': must be exactly 8 characters"
  // - "Parameter 'count' missing required 'type' attribute"
  console.error(error.message);
}
```

## Performance

- **Fast parsing**: ~7ms for Finder.sdef (~200KB, 9 suites, 25+ commands)
- **Automatic caching**: Parsed results are cached by file path
- **Memory efficient**: Uses streaming XML parser

### Cache Management

```typescript
const parser = new SDEFParser();

// Parse (caches result)
await parser.parse('/path/to/app.sdef');

// Parse again (uses cache)
await parser.parse('/path/to/app.sdef');

// Clear cache
parser.clearCache();
```

## XML Parser Configuration

Uses `fast-xml-parser` with these settings:

- **No attribute trimming**: Preserves trailing spaces in four-character codes
- **String-only values**: Prevents automatic type conversion
- **Namespace-agnostic**: Ignores XML namespaces
- **DOCTYPE ignored**: Skips DTD validation

## Examples

### Example 1: List all commands in an app

```typescript
import { sdefParser } from './parse-sdef.js';

const result = await sdefParser.parse('/path/to/app.sdef');

for (const suite of result.suites) {
  for (const command of suite.commands) {
    console.log(`${suite.name}.${command.name}`);
  }
}
```

### Example 2: Find commands with optional parameters

```typescript
import { sdefParser } from './parse-sdef.js';

const result = await sdefParser.parse('/path/to/app.sdef');

for (const suite of result.suites) {
  for (const command of suite.commands) {
    const optionalParams = command.parameters.filter(p => p.optional);
    if (optionalParams.length > 0) {
      console.log(`${command.name}: ${optionalParams.map(p => p.name).join(', ')}`);
    }
  }
}
```

### Example 3: Extract all enumerations

```typescript
import { sdefParser } from './parse-sdef.js';

const result = await sdefParser.parse('/path/to/app.sdef');

for (const suite of result.suites) {
  for (const enumeration of suite.enumerations) {
    console.log(`${enumeration.name}:`);
    for (const enumerator of enumeration.enumerators) {
      console.log(`  - ${enumerator.name} (${enumerator.code})`);
    }
  }
}
```

## Testing

The parser includes comprehensive unit tests:

```bash
npm test -- sdef-parser.test.ts
```

Tests cover:
- Basic XML parsing
- Dictionary extraction
- Suite extraction
- Command extraction with parameters and results
- Class extraction with properties and elements
- Enumeration extraction
- Type mapping (all SDEFType variants)
- Error handling (malformed XML, missing attributes)
- Real-world parsing (Finder.sdef)
- Edge cases (Unicode, CDATA, comments)

## Implementation Notes

### XML Parsing

- Uses `fast-xml-parser` for robust XML parsing
- Handles malformed XML with descriptive errors
- Preserves whitespace in attribute values (important for four-character codes)

### Validation

- Validates required attributes (name, code, type)
- Validates four-character code format
- Validates access rights format (`r`, `w`, `rw`)
- Provides clear error messages with element context

### Direct Parameters

Direct parameters are special parameters that don't have explicit name/code attributes:

```xml
<direct-parameter type="file" description="the file to open"/>
```

The parser assigns them:
- `name: 'direct-parameter'`
- `code: '----'` (standard direct parameter code)

### Type Resolution

The parser performs basic type resolution:

- Primitive types are mapped to `SDEFType` variants
- Unknown types are treated as class references
- More sophisticated type resolution (cross-referencing classes/enums) can be added later

## Future Enhancements

Potential improvements:

1. **Type validation**: Cross-reference type names with defined classes/enums
2. **Inheritance resolution**: Handle class inheritance hierarchies
3. **Response type inference**: Infer return types from class properties
4. **Documentation extraction**: Extract detailed documentation from descriptions
5. **Schema validation**: Validate against SDEF DTD

## See Also

- [Type Definitions](../../types/sdef.ts) - Complete TypeScript type definitions
- [SDEF Discovery](./find-sdef.ts) - Finding SDEF files in app bundles
- [Apple SDEF Documentation](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ScriptingDefinitions/)
