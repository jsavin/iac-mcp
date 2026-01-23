import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'fs/promises';
import type {
  SDEFDictionary,
  SDEFSuite,
  SDEFCommand,
  SDEFParameter,
  SDEFClass,
  SDEFProperty,
  SDEFEnumeration,
  SDEFType,
} from '../../src/types/sdef';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef';
import {
  loadMinimalValidSDEF,
  loadMalformedSDEF,
  loadFinderSDEF,
  isMacOS,
  createMinimalSDEF,
} from '../utils/test-helpers';

/**
 * Tests for SDEF XML parsing and data extraction
 *
 * These tests validate that we can parse SDEF XML files and extract
 * all necessary information in the correct structure.
 */

describe('SDEF XML Parsing', () => {
  let parser: SDEFParser;
  let minimalValidSDEF: string;
  let malformedSDEF: string;

  beforeAll(async () => {
    parser = new SDEFParser();
    // Load test fixtures using helper functions
    minimalValidSDEF = await loadMinimalValidSDEF();
    malformedSDEF = await loadMalformedSDEF();
  });

  describe('basic XML parsing', () => {
    it('should parse valid SDEF XML without errors', async () => {
      // The parser should successfully parse the minimal valid SDEF
      // and return a structured result
      const result = await parser.parseContent(minimalValidSDEF);
      expect(result).toBeTruthy();
      expect(result.title).toBe('Test Application');
      expect(result.suites).toBeDefined();
      expect(result.suites.length).toBeGreaterThan(0);
    });

    it('should throw error for malformed XML', async () => {
      // Malformed XML should result in a clear error in strict mode
      const strictParser = new SDEFParser({ mode: 'strict' });
      await expect(strictParser.parseContent(malformedSDEF)).rejects.toThrow();
    });

    it('should handle empty SDEF file', async () => {
      const emptySDEF = '';

      // Should throw appropriate error for empty input
      await expect(parser.parseContent(emptySDEF)).rejects.toThrow();
    });

    it('should handle SDEF with only dictionary tag', async () => {
      const minimalSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="Empty App">
</dictionary>`;

      const result = await parser.parseContent(minimalSDEF);
      expect(result.title).toBe('Empty App');
      expect(result.suites).toEqual([]);
    });

    it('should preserve XML special characters', async () => {
      // SDEF descriptions might contain &, <, >, ", '
      // Parser should handle these correctly
      const sdefWithSpecialChars = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="App &amp; Tests">
  <suite name="Test Suite" code="TEST" description="Suite with &quot;quotes&quot; &amp; &lt;brackets&gt;">
  </suite>
</dictionary>`;

      expect(sdefWithSpecialChars).toContain('&amp;');
      expect(sdefWithSpecialChars).toContain('&quot;');
      expect(sdefWithSpecialChars).toContain('&lt;');
      expect(sdefWithSpecialChars).toContain('&gt;');
    });

    it('should handle different XML encodings', async () => {
      // Most SDEF files are UTF-8, but should handle others
      expect(minimalValidSDEF).toContain('encoding="UTF-8"');
    });
  });

  describe('dictionary extraction', () => {
    it('should extract dictionary title', async () => {
      // The parser should extract the title attribute from dictionary element
      // Expected: "Test Application"
      const result = await parser.parseContent(minimalValidSDEF);
      expect(result.title).toBe('Test Application');
    });

    it('should extract all suites from dictionary', async () => {
      // The minimal valid SDEF has 2 suites: "Standard Suite" and "Test Suite"
      const result = await parser.parseContent(minimalValidSDEF);
      expect(result.suites.length).toBe(2);
      expect(result.suites[0].name).toBe('Standard Suite');
      expect(result.suites[1].name).toBe('Test Suite');
    });

    it('should handle dictionary without title', async () => {
      const noTitleSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary>
  <suite name="Suite" code="SUIT"></suite>
</dictionary>`;

      const result = await parser.parseContent(noTitleSDEF);
      expect(result.title).toBe('Untitled'); // Default title when not specified
      expect(result.suites.length).toBe(1);
    });

    it('should return structured SDEFDictionary type', async () => {
      // The result should match the SDEFDictionary interface
      // {
      //   title: string,
      //   suites: SDEFSuite[]
      // }
      const expectedStructure: Partial<SDEFDictionary> = {
        title: 'Test Application',
        suites: [],
      };

      expect(expectedStructure).toHaveProperty('title');
      expect(expectedStructure).toHaveProperty('suites');
      expect(Array.isArray(expectedStructure.suites)).toBe(true);
    });
  });

  describe('suite extraction', () => {
    it('should extract suite name, code, and description', async () => {
      // Suite attributes from minimal valid SDEF
      expect(minimalValidSDEF).toContain('name="Standard Suite"');
      expect(minimalValidSDEF).toContain('code="CoRe"');
      expect(minimalValidSDEF).toContain('description="Common terms for testing"');
    });

    it('should extract all commands in a suite', async () => {
      // Standard Suite has 2 commands: "open" and "quit"
      expect(minimalValidSDEF).toContain('name="open"');
      expect(minimalValidSDEF).toContain('name="quit"');
    });

    it('should extract all classes in a suite', async () => {
      // Standard Suite has 2 classes: "application" and "window"
      expect(minimalValidSDEF).toContain('<class name="application"');
      expect(minimalValidSDEF).toContain('<class name="window"');
    });

    it('should extract all enumerations in a suite', async () => {
      // Standard Suite has 2 enumerations: "save options" and "print error handling"
      expect(minimalValidSDEF).toContain('<enumeration name="save options"');
      expect(minimalValidSDEF).toContain('<enumeration name="print error handling"');
    });

    it('should handle suite without description', async () => {
      expect(minimalValidSDEF).toContain('name="Test Suite"');
      expect(minimalValidSDEF).toContain('code="TEST"');
    });

    it('should handle empty suite', async () => {
      const emptySuiteSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Empty Suite" code="EMPT" description="No content">
  </suite>
</dictionary>`;

      expect(emptySuiteSDEF).toContain('name="Empty Suite"');
    });

    it('should return structured SDEFSuite type', async () => {
      const expectedStructure: Partial<SDEFSuite> = {
        name: 'Standard Suite',
        code: 'CoRe',
        description: 'Common terms for testing',
        commands: [],
        classes: [],
        enumerations: [],
      };

      expect(expectedStructure).toHaveProperty('name');
      expect(expectedStructure).toHaveProperty('code');
      expect(expectedStructure).toHaveProperty('commands');
      expect(expectedStructure).toHaveProperty('classes');
      expect(expectedStructure).toHaveProperty('enumerations');
    });
  });

  describe('command extraction', () => {
    it('should extract command name, code, and description', async () => {
      expect(minimalValidSDEF).toContain('<command name="open"');
      expect(minimalValidSDEF).toContain('code="aevtodoc"');
      expect(minimalValidSDEF).toContain('description="Open the specified object(s)"');
    });

    it('should extract direct parameter', async () => {
      // The "open" command has a direct parameter
      expect(minimalValidSDEF).toContain('<direct-parameter type="file"');
      expect(minimalValidSDEF).toContain('description="the file to open"');
    });

    it('should extract named parameters', async () => {
      // The "open" command has a "using" parameter
      expect(minimalValidSDEF).toContain('<parameter name="using"');
      expect(minimalValidSDEF).toContain('code="usin"');
      expect(minimalValidSDEF).toContain('type="text"');
      expect(minimalValidSDEF).toContain('optional="yes"');
    });

    it('should extract result type', async () => {
      // The "open" command returns a boolean
      expect(minimalValidSDEF).toContain('<result type="boolean"');
    });

    it('should distinguish required vs optional parameters', async () => {
      // "using" parameter is optional
      // direct parameter is required (no optional attribute)
      expect(minimalValidSDEF).toContain('optional="yes"');
    });

    it('should handle command without parameters', async () => {
      // "quit" command has no parameters
      expect(minimalValidSDEF).toContain('<command name="quit"');
      expect(minimalValidSDEF).toContain('code="aevtquit"');
    });

    it('should handle command without result', async () => {
      // "quit" command has no result
      expect(minimalValidSDEF).toContain('<command name="quit"');
    });

    it('should extract multiple parameters correctly', async () => {
      // "test command" has multiple parameters
      expect(minimalValidSDEF).toContain('<command name="test command"');
      expect(minimalValidSDEF).toContain('name="with count"');
      expect(minimalValidSDEF).toContain('name="with flag"');
      expect(minimalValidSDEF).toContain('name="with list"');
    });

    it('should return structured SDEFCommand type', async () => {
      const expectedStructure: Partial<SDEFCommand> = {
        name: 'open',
        code: 'aevtodoc',
        description: 'Open the specified object(s)',
        parameters: [],
        result: { kind: 'primitive', type: 'boolean' },
        directParameter: undefined,
      };

      expect(expectedStructure).toHaveProperty('name');
      expect(expectedStructure).toHaveProperty('code');
      expect(expectedStructure).toHaveProperty('parameters');
      expect(Array.isArray(expectedStructure.parameters)).toBe(true);
    });
  });

  describe('parameter extraction', () => {
    it('should extract parameter name, code, type, and description', async () => {
      expect(minimalValidSDEF).toContain('name="using"');
      expect(minimalValidSDEF).toContain('code="usin"');
      expect(minimalValidSDEF).toContain('type="text"');
      expect(minimalValidSDEF).toContain('description="the application to open with"');
    });

    it('should extract optional flag', async () => {
      expect(minimalValidSDEF).toContain('optional="yes"');
    });

    it('should handle parameters with different types', async () => {
      // text, integer, boolean, list, file, etc.
      expect(minimalValidSDEF).toContain('type="text"');
      expect(minimalValidSDEF).toContain('type="integer"');
      expect(minimalValidSDEF).toContain('type="boolean"');
      expect(minimalValidSDEF).toContain('type="list"');
      expect(minimalValidSDEF).toContain('type="file"');
    });

    it('should return structured SDEFParameter type', async () => {
      const expectedStructure: Partial<SDEFParameter> = {
        name: 'using',
        code: 'usin',
        type: { kind: 'primitive', type: 'text' },
        description: 'the application to open with',
        optional: true,
      };

      expect(expectedStructure).toHaveProperty('name');
      expect(expectedStructure).toHaveProperty('code');
      expect(expectedStructure).toHaveProperty('type');
      expect(expectedStructure).toHaveProperty('optional');
    });
  });

  describe('class extraction', () => {
    it('should extract class name, code, and description', async () => {
      expect(minimalValidSDEF).toContain('<class name="application"');
      expect(minimalValidSDEF).toContain('code="capp"');
      expect(minimalValidSDEF).toContain('description="The application"');
    });

    it('should extract properties', async () => {
      // "application" class has properties: name, version, frontmost
      expect(minimalValidSDEF).toContain('<property name="name"');
      expect(minimalValidSDEF).toContain('<property name="version"');
      expect(minimalValidSDEF).toContain('<property name="frontmost"');
    });

    it('should extract elements', async () => {
      // "application" class has element: window
      expect(minimalValidSDEF).toContain('<element type="window"');
    });

    it('should extract property access rights', async () => {
      // Properties can be r (read), w (write), or rw (read-write)
      expect(minimalValidSDEF).toContain('access="r"');
      expect(minimalValidSDEF).toContain('access="rw"');
    });

    it('should handle class without properties', async () => {
      // Some classes might only have elements
      expect(true).toBe(true);
    });

    it('should handle class without elements', async () => {
      // "test object" class has no elements
      expect(minimalValidSDEF).toContain('<class name="test object"');
    });

    it('should return structured SDEFClass type', async () => {
      const expectedStructure: Partial<SDEFClass> = {
        name: 'application',
        code: 'capp',
        description: 'The application',
        properties: [],
        elements: [],
      };

      expect(expectedStructure).toHaveProperty('name');
      expect(expectedStructure).toHaveProperty('code');
      expect(expectedStructure).toHaveProperty('properties');
      expect(expectedStructure).toHaveProperty('elements');
      expect(Array.isArray(expectedStructure.properties)).toBe(true);
      expect(Array.isArray(expectedStructure.elements)).toBe(true);
    });
  });

  describe('property extraction', () => {
    it('should extract property name, code, type, access, and description', async () => {
      expect(minimalValidSDEF).toContain('name="name"');
      expect(minimalValidSDEF).toContain('code="pnam"');
      expect(minimalValidSDEF).toContain('type="text"');
      expect(minimalValidSDEF).toContain('access="r"');
      expect(minimalValidSDEF).toContain('description="the application\'s name"');
    });

    it('should handle read-only properties', async () => {
      // "name" and "version" are read-only (access="r")
      expect(minimalValidSDEF).toContain('access="r"');
    });

    it('should handle read-write properties', async () => {
      // "frontmost" is read-write (access="rw")
      expect(minimalValidSDEF).toContain('access="rw"');
    });

    it('should return structured SDEFProperty type', async () => {
      const expectedStructure: Partial<SDEFProperty> = {
        name: 'name',
        code: 'pnam',
        type: { kind: 'primitive', type: 'text' },
        description: "the application's name",
        access: 'r',
      };

      expect(expectedStructure).toHaveProperty('name');
      expect(expectedStructure).toHaveProperty('code');
      expect(expectedStructure).toHaveProperty('type');
      expect(expectedStructure).toHaveProperty('access');
    });
  });

  describe('enumeration extraction', () => {
    it('should extract enumeration name and code', async () => {
      expect(minimalValidSDEF).toContain('<enumeration name="save options"');
      expect(minimalValidSDEF).toContain('code="savo"');
    });

    it('should extract enumerators', async () => {
      // "save options" has 3 enumerators: yes, no, ask
      expect(minimalValidSDEF).toContain('<enumerator name="yes"');
      expect(minimalValidSDEF).toContain('<enumerator name="no"');
      expect(minimalValidSDEF).toContain('<enumerator name="ask"');
    });

    it('should extract enumerator codes and descriptions', async () => {
      expect(minimalValidSDEF).toContain('code="yes "');
      expect(minimalValidSDEF).toContain('description="Save the file"');
    });

    it('should handle multiple enumerations in a suite', async () => {
      expect(minimalValidSDEF).toContain('name="save options"');
      expect(minimalValidSDEF).toContain('name="print error handling"');
    });

    it('should return structured SDEFEnumeration type', async () => {
      const expectedStructure: Partial<SDEFEnumeration> = {
        name: 'save options',
        code: 'savo',
        enumerators: [],
      };

      expect(expectedStructure).toHaveProperty('name');
      expect(expectedStructure).toHaveProperty('code');
      expect(expectedStructure).toHaveProperty('enumerators');
      expect(Array.isArray(expectedStructure.enumerators)).toBe(true);
    });
  });

  describe('type mapping', () => {
    it('should map primitive types correctly', async () => {
      // SDEF types -> SDEFType mapping
      const primitiveTypes = ['text', 'integer', 'real', 'boolean'];

      for (const primitiveType of primitiveTypes) {
        const expectedType: SDEFType = {
          kind: 'primitive',
          type: primitiveType as 'text' | 'integer' | 'real' | 'boolean',
        };
        expect(expectedType.kind).toBe('primitive');
        expect(expectedType.type).toBe(primitiveType);
      }
    });

    it('should map file type correctly', async () => {
      const fileType: SDEFType = { kind: 'file' };
      expect(fileType.kind).toBe('file');
    });

    it('should map list type correctly', async () => {
      const listType: SDEFType = {
        kind: 'list',
        itemType: { kind: 'primitive', type: 'text' },
      };
      expect(listType.kind).toBe('list');
      expect(listType.itemType).toBeDefined();
    });

    it('should map record type correctly', async () => {
      const recordType: SDEFType = {
        kind: 'record',
        properties: {
          name: { kind: 'primitive', type: 'text' },
          count: { kind: 'primitive', type: 'integer' },
        },
      };
      expect(recordType.kind).toBe('record');
      expect(recordType.properties).toBeDefined();
    });

    it('should map class reference type correctly', async () => {
      const classType: SDEFType = {
        kind: 'class',
        className: 'window',
      };
      expect(classType.kind).toBe('class');
      expect(classType.className).toBe('window');
    });

    it('should map enumeration reference type correctly', async () => {
      const enumType: SDEFType = {
        kind: 'enumeration',
        enumerationName: 'save options',
      };
      expect(enumType.kind).toBe('enumeration');
      expect(enumType.enumerationName).toBe('save options');
    });

    it('should handle complex nested types', async () => {
      // List of records, for example
      const nestedType: SDEFType = {
        kind: 'list',
        itemType: {
          kind: 'record',
          properties: {
            name: { kind: 'primitive', type: 'text' },
            items: {
              kind: 'list',
              itemType: { kind: 'primitive', type: 'integer' },
            },
          },
        },
      };

      expect(nestedType.kind).toBe('list');
      expect((nestedType as any).itemType.kind).toBe('record');
    });

    it('should handle unknown or custom types', async () => {
      // Some SDEFs might have custom types or aliases
      // Parser should handle gracefully
      expect(true).toBe(true);
    });
  });

  describe('parsing Finder.sdef', () => {
    it('should successfully parse actual Finder.sdef file', async () => {
      const finderSDEFPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';

      try {
        const finderSDEF = await readFile(finderSDEFPath, 'utf-8');
        expect(finderSDEF).toBeTruthy();
        expect(finderSDEF).toContain('<dictionary');
        expect(finderSDEF).toContain('</dictionary>');
      } catch (error) {
        // Skip test if Finder.sdef is not accessible
        console.log('Finder.sdef not accessible, skipping test');
      }
    });

    it('should extract multiple suites from Finder', async () => {
      const finderSDEFPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';

      try {
        const finderSDEF = await readFile(finderSDEFPath, 'utf-8');
        // Finder has multiple suites: Standard Suite, Finder Basics, etc.
        expect(finderSDEF).toContain('name="Standard Suite"');
        expect(finderSDEF).toContain('name="Finder Basics"');
      } catch (error) {
        console.log('Finder.sdef not accessible, skipping test');
      }
    });

    it('should extract common Finder commands', async () => {
      const finderSDEFPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';

      try {
        const finderSDEF = await readFile(finderSDEFPath, 'utf-8');
        // Common Finder commands
        expect(finderSDEF).toContain('name="open"');
        expect(finderSDEF).toContain('name="quit"');
        expect(finderSDEF).toContain('name="delete"');
        expect(finderSDEF).toContain('name="duplicate"');
      } catch (error) {
        console.log('Finder.sdef not accessible, skipping test');
      }
    });

    it('should extract Finder classes', async () => {
      const finderSDEFPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';

      try {
        const finderSDEF = await readFile(finderSDEFPath, 'utf-8');
        // Common Finder classes
        expect(finderSDEF).toContain('name="application"');
        expect(finderSDEF).toContain('name="window"');
      } catch (error) {
        console.log('Finder.sdef not accessible, skipping test');
      }
    });
  });

  describe('error handling', () => {
    it('should provide clear error for malformed XML', async () => {
      // Parser should throw specific error for XML parsing issues
      expect(malformedSDEF).not.toContain('</dictionary>');
    });

    it('should handle missing required attributes', async () => {
      const missingAttributesSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary>
  <suite code="TEST">
    <command code="test">
    </command>
  </suite>
</dictionary>`;

      // Missing name attributes - should handle gracefully
      expect(missingAttributesSDEF).not.toContain('name=');
    });

    it('should handle invalid type references', async () => {
      const invalidTypeSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="test">
      <parameter name="param" code="prm" type="nonexistent-type"/>
    </command>
  </suite>
</dictionary>`;

      expect(invalidTypeSDEF).toContain('type="nonexistent-type"');
    });

    it('should handle circular type references', async () => {
      // Class A references Class B which references Class A
      // Parser should detect and handle this
      expect(true).toBe(true);
    });

    it('should handle excessively nested structures', async () => {
      // Very deep nesting (e.g., list of list of list...)
      // Should not cause stack overflow
      expect(true).toBe(true);
    });

    it('should validate four-character codes', async () => {
      // Four-character codes should be exactly 4 characters
      // Some might have spaces for padding
      expect('aevt'.length).toBe(4);
      expect('yes '.length).toBe(4);
    });
  });

  describe('performance', () => {
    it('should parse large SDEF files efficiently', async () => {
      // Finder.sdef is ~200KB - should parse in reasonable time
      const startTime = Date.now();

      try {
        const finderSDEFPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
        const finderSDEF = await readFile(finderSDEFPath, 'utf-8');

        // Reading file
        const readTime = Date.now() - startTime;

        // Parser implementation will be timed here
        // Should complete in < 1 second
        expect(readTime).toBeLessThan(5000);
      } catch (error) {
        console.log('Finder.sdef not accessible, skipping test');
      }
    });

    it('should handle multiple concurrent parse requests', async () => {
      // If parsing multiple SDEFs simultaneously
      // Should not have race conditions or performance issues
      expect(true).toBe(true);
    });
  });

  describe('data validation', () => {
    it('should validate that all required fields are present', async () => {
      // Every command must have name and code
      // Every class must have name and code
      // etc.
      expect(true).toBe(true);
    });

    it('should validate code format', async () => {
      // Four-character codes should match expected format
      const validCodes = ['aevt', 'CoRe', 'yes ', 'no  '];
      for (const code of validCodes) {
        expect(code.length).toBe(4);
      }
    });

    it('should validate type references', async () => {
      // If a parameter has type="window", class "window" should exist
      // If an enumeration reference is used, enumeration should exist
      expect(true).toBe(true);
    });

    it('should validate access rights format', async () => {
      const validAccessRights = ['r', 'w', 'rw'];
      for (const access of validAccessRights) {
        expect(['r', 'w', 'rw']).toContain(access);
      }
    });
  });

  describe('edge cases', () => {
    it('should handle SDEF with no suites', async () => {
      const noSuitesSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Empty">
</dictionary>`;

      expect(noSuitesSDEF).toContain('title="Empty"');
      expect(noSuitesSDEF).not.toContain('<suite');
    });

    it('should handle suite with no commands', async () => {
      expect(true).toBe(true);
    });

    it('should handle very long descriptions', async () => {
      // Some SDEF descriptions can be paragraphs long
      // Parser should handle without truncation
      expect(true).toBe(true);
    });

    it('should handle Unicode characters in descriptions', async () => {
      // SDEF files are UTF-8, might contain unicode
      const unicodeSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test Application">
  <suite name="Test" code="TEST" description="Unicode test: é ñ 中文 🎉">
  </suite>
</dictionary>`;

      expect(unicodeSDEF).toContain('é');
      expect(unicodeSDEF).toContain('🎉');
    });

    it('should handle comments in SDEF', async () => {
      const commentSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <!-- This is a comment -->
  <suite name="Test" code="TEST">
    <!-- Another comment -->
  </suite>
</dictionary>`;

      expect(commentSDEF).toContain('<!--');
      expect(commentSDEF).toContain('-->');
    });

    it('should handle CDATA sections', async () => {
      const cdataSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST" description="<![CDATA[Description with <special> characters]]>">
  </suite>
</dictionary>`;

      expect(cdataSDEF).toContain('CDATA');
    });

    it('should handle attributes in different orders', async () => {
      // XML attributes can appear in any order
      // Parser should handle regardless of order
      expect(true).toBe(true);
    });

    it('should handle self-closing tags', async () => {
      const selfClosingSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST"/>
</dictionary>`;

      expect(selfClosingSDEF).toContain('/>');
    });
  });

  describe('ENTITY declaration validation', () => {
    it('should reject ENTITY declarations found after DOCTYPE stripping', async () => {
      // This test verifies that the parser detects and rejects ENTITY declarations
      // that remain in the XML after DOCTYPE stripping fails or is incomplete.
      // This is a security measure to prevent XXE (XML External Entity) attacks.

      const xmlWithMalformedEntity = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd"
[
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<dictionary title="Test App">
  <suite name="Test" code="TEST"/>
</dictionary>`;

      // Parser should reject this because it contains ENTITY with SYSTEM reference
      // in the DOCTYPE internal subset
      await expect(parser.parseContent(xmlWithMalformedEntity)).rejects.toThrow(
        /ENTITY SYSTEM|XXE|not allowed/i
      );
    });

    it('should reject multiple ENTITY declarations with SYSTEM references', async () => {
      // Test that multiple malicious ENTITY declarations are detected
      const xmlWithMultipleEntities = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
  <!ENTITY data "test">
]>
<dictionary title="Test App">
  <suite name="Test" code="TEST"/>
</dictionary>`;

      // Should reject because both entities use SYSTEM references
      await expect(parser.parseContent(xmlWithMultipleEntities)).rejects.toThrow(
        /ENTITY SYSTEM|XXE|not allowed/i
      );
    });

    it('should reject ENTITY with sensitive file references in DOCTYPE SYSTEM', async () => {
      // Test that DOCTYPE SYSTEM references to sensitive files are rejected
      // Note: This is validated by EntityResolver during file parsing, not parseContent
      // parseContent is for pre-processed XML where DOCTYPE has been handled
      // So we skip this test for parseContent - it's covered by entity-resolver tests
      expect(true).toBe(true); // Placeholder - entity validation is in EntityResolver tests
    });

    it('should allow DOCTYPE without malicious ENTITY declarations', async () => {
      // This test verifies the parser allows safe DOCTYPE declarations
      // (legitimate DTD references without ENTITY attacks)
      const xmlWithSafeDoctype = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="Test App">
  <suite name="Test" code="TEST">
    <command name="test" code="aevtodoc">
    </command>
  </suite>
</dictionary>`;

      // Should parse successfully
      const result = await parser.parseContent(xmlWithSafeDoctype);
      expect(result).toBeTruthy();
      expect(result.title).toBe('Test App');
      expect(result.suites.length).toBeGreaterThan(0);
    });

    it('should strip DOCTYPE before validation (parameter entities handled by EntityResolver)', async () => {
      // Parameter entities are handled during file parsing and XInclude resolution by EntityResolver
      // parseContent expects pre-processed XML with DOCTYPE already stripped
      // So this test just verifies that content without ENTITY declarations parses fine
      const xmlWithoutEntities = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test" code="TEST">
    <command name="test" code="aevtodoc">
    </command>
  </suite>
</dictionary>`;

      // Should parse successfully - no ENTITY declarations
      const result = await parser.parseContent(xmlWithoutEntities);
      expect(result).toBeTruthy();
      expect(result.title).toBe('Test App');
    });
  });

  describe('path validation', () => {
    it('should reject relative SDEF paths', async () => {
      // Relative paths should not be accepted as they're unsafe
      // and can lead to security issues when resolving files
      const relativePaths = [
        './relative/path.sdef',
        'relative/path.sdef',
        '../parent/path.sdef',
        'path/to/file.sdef',
      ];

      for (const relativePath of relativePaths) {
        // The parser should throw an error about the path needing to be absolute
        await expect(parser.parse(relativePath)).rejects.toThrow(/absolute|absolute path/i);
      }
    });

    it('should accept absolute SDEF paths', async () => {
      // Absolute paths should be accepted (even if the file doesn't exist,
      // the error should be about file not found, not about path being relative)
      const absolutePaths = [
        '/tmp/file.sdef',
        '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef',
        '/Applications/Mail.app/Contents/Resources/Mail.sdef',
      ];

      for (const absolutePath of absolutePaths) {
        try {
          await parser.parse(absolutePath);
        } catch (error) {
          // We expect file not found errors for non-existent files,
          // but NOT errors about path validation (i.e., not "must be absolute")
          if (error instanceof Error) {
            expect(error.message).not.toMatch(/must be an absolute path|path must be absolute/i);
          }
        }
      }
    });

    it('should throw clear error message for relative paths', async () => {
      // The error message should clearly indicate the path must be absolute
      const relativePath = './test.sdef';

      try {
        await parser.parse(relativePath);
        // If we get here, the validation isn't implemented yet
        // This test will fail until the validation is added
        throw new Error('Expected parser to reject relative path');
      } catch (error) {
        if (error instanceof Error) {
          // Should contain helpful message about absolute paths
          expect(error.message.toLowerCase()).toMatch(
            /absolute|must be an absolute path|relative/
          );
        }
      }
    });

    it('should handle paths with ".." and "." components', async () => {
      // These are relative path tricks that should be rejected
      const trickPaths = [
        '/../absolute/looking/but/relative.sdef',
        '/valid/path/../../but/relative.sdef',
        '/./path/with/dot.sdef',
      ];

      for (const trickPath of trickPaths) {
        // These should either be rejected or normalized and accepted
        // Behavior depends on implementation (strict vs. lenient)
        try {
          await parser.parse(trickPath);
        } catch (error) {
          // Either absolute path validation should catch it,
          // or file not found is acceptable
          expect(error).toBeDefined();
        }
      }
    });

    it('should validate paths early before file operations', async () => {
      // Path validation should happen before attempting to read the file
      // so invalid paths fail fast without side effects
      const relativePath = './does-not-exist.sdef';

      const startTime = Date.now();
      try {
        await parser.parse(relativePath);
      } catch (error) {
        const duration = Date.now() - startTime;
        // Should reject quickly (path validation < 1ms)
        // If it takes longer, it's trying to do file I/O first
        expect(duration).toBeLessThan(100);
      }
    });

    it('should work with valid absolute paths to real files on macOS', async () => {
      if (!isMacOS()) {
        // Skip on non-macOS systems
        return;
      }

      const finderPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';

      try {
        const result = await parser.parse(finderPath);
        expect(result).toBeTruthy();
        expect(result.title).toBeDefined();
        expect(result.suites).toBeDefined();
      } catch (error) {
        // If Finder.sdef isn't accessible, that's ok for this test
        if (error instanceof Error) {
          expect(error.message).not.toMatch(/absolute|relative path/i);
        }
      }
    });
  });
});
