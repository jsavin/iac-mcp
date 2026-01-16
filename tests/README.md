# SDEF Parser Tests

Comprehensive test suite for the SDEF (Scripting Definition) parser implementation.

## Test Structure

```
tests/
├── unit/
│   ├── sdef-discovery.test.ts    # SDEF file discovery tests (22 tests)
│   └── sdef-parser.test.ts       # SDEF XML parsing tests (78 tests)
├── integration/                   # Integration tests (future)
└── fixtures/
    └── sdef/
        ├── minimal-valid.sdef     # Minimal but complete SDEF for testing
        └── malformed.sdef         # Malformed XML for error testing
```

## Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run unit tests only
npm run test:unit

# Run integration tests only
npm run test:integration
```

## Test Coverage

### SDEF Discovery Tests (`sdef-discovery.test.ts`)

Tests for finding and validating SDEF files in macOS application bundles.

**Coverage (22 tests):**
- Finding SDEF files at known paths
- Error handling for non-existent paths
- File readability validation
- Invalid path handling
- Application discovery across common directories
- Permission error handling
- SDEF path construction
- Caching and performance
- Platform-specific behavior
- Edge cases

**Key test groups:**
1. `findSDEFFile` - Locate SDEF file for a specific app
2. `discoverApplicationSDEFs` - Find all scriptable apps
3. `getSDEFPath` - Construct SDEF file path from app bundle
4. Caching and performance
5. Error handling and edge cases
6. Platform-specific behavior

### SDEF Parser Tests (`sdef-parser.test.ts`)

Tests for parsing SDEF XML and extracting structured data.

**Coverage (78 tests):**
- XML parsing (valid and malformed)
- Dictionary extraction
- Suite extraction (name, code, description)
- Command extraction (parameters, results, direct parameters)
- Parameter extraction (types, optional flags)
- Class extraction (properties, elements)
- Property extraction (access rights)
- Enumeration extraction
- Type mapping (primitive, file, list, record, class, enumeration)
- Finder.sdef parsing (real-world example)
- Error handling
- Performance
- Data validation
- Edge cases

**Key test groups:**
1. Basic XML parsing
2. Dictionary extraction
3. Suite extraction
4. Command extraction
5. Parameter extraction
6. Class extraction
7. Property extraction
8. Enumeration extraction
9. Type mapping (SDEF types → TypeScript types)
10. Parsing Finder.sdef (real-world validation)
11. Error handling
12. Performance
13. Data validation
14. Edge cases

## Test Fixtures

### `minimal-valid.sdef`

A minimal but complete SDEF file containing:
- 2 suites: "Standard Suite" and "Test Suite"
- 3 commands: "open", "quit", "test command"
- 3 classes: "application", "window", "test object"
- 2 enumerations: "save options", "print error handling"
- Various parameter types: text, integer, boolean, list, file
- Direct parameters, optional parameters, result types
- Properties with different access rights (r, w, rw)
- Elements

Used for testing all basic parsing functionality without requiring a full app installation.

### `malformed.sdef`

An intentionally malformed SDEF file with:
- Unclosed XML tags
- Missing required closing tags
- Invalid XML structure

Used for testing error handling and graceful failure.

## Type Definitions

All tests use types from `/Users/jake/dev/jsavin/iac-mcp-sdef-parser/src/types/sdef.ts`:
- `SDEFDictionary` - Top-level dictionary structure
- `SDEFSuite` - Suite containing commands, classes, enumerations
- `SDEFCommand` - Command with parameters and result
- `SDEFParameter` - Command parameter
- `SDEFClass` - Object class with properties and elements
- `SDEFProperty` - Class property
- `SDEFEnumeration` - Enumeration with enumerators
- `SDEFType` - Type system (primitive, file, list, record, class, enum)

## Test Philosophy

These tests follow Test-Driven Development (TDD) principles:

1. **Tests written first** - Before implementation
2. **Comprehensive coverage** - Happy path and error cases
3. **Real-world validation** - Tests against actual Finder.sdef
4. **Clear test names** - Describe exactly what they test
5. **Fixtures for consistency** - Controlled test data
6. **Edge case coverage** - Handle unexpected input

## Current Status

**Status:** Tests complete, implementation pending

All 100 tests currently pass with placeholder implementations. As the actual SDEF parser is implemented, these tests will validate the functionality.

**Expected behavior:**
- Tests will initially fail when implementation is added
- Implementation should make tests pass one by one
- All tests passing = parser implementation complete

## Implementation Guidance

When implementing the SDEF parser, focus on making tests pass in this order:

1. **Basic XML parsing** - Parse valid SDEF XML
2. **Dictionary extraction** - Extract title and suites
3. **Suite extraction** - Extract suite metadata
4. **Command extraction** - Extract commands with parameters
5. **Class extraction** - Extract classes with properties
6. **Enumeration extraction** - Extract enumerations
7. **Type mapping** - Map SDEF types to TypeScript types
8. **Error handling** - Handle malformed XML and missing data
9. **Real-world validation** - Parse Finder.sdef successfully
10. **Performance** - Optimize for large SDEF files

## Week 1 Scope

These tests cover **Week 1 of Phase 0** (Technical Validation):
- SDEF file discovery
- SDEF XML parsing
- Data extraction

**NOT covered (future weeks):**
- Tool generation (Week 2)
- JXA execution (Week 2)
- MCP integration (Week 3)
- End-to-end workflows (Week 4)

## Additional Resources

- Type definitions: `/Users/jake/dev/jsavin/iac-mcp-sdef-parser/src/types/sdef.ts`
- Planning docs: `/Users/jake/dev/jsavin/iac-mcp-sdef-parser/planning/`
- Real SDEF example: `/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef`
- SDEF specification: See `planning/ideas/jitd-concept.md`
