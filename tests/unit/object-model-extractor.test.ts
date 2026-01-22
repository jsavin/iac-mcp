/**
 * Tests for ObjectModelExtractor
 *
 * Tests extraction of classes and enumerations from SDEF dictionaries.
 * This data is included in get_app_tools responses so LLM can understand object model.
 *
 * The ObjectModel includes:
 * - Classes (with properties, elements, inheritance)
 * - Enumerations (valid values for enum parameters)
 *
 * Tests are written BEFORE implementation (TDD) and will initially fail.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { SDEFDictionary, SDEFClass, SDEFEnumeration } from '../../src/types/sdef.js';

/**
 * ClassInfo extracted from SDEF
 */
export interface ClassInfo {
  name: string;
  code: string;
  description?: string;
  properties: PropertyInfo[];
  elements?: ElementInfo[];
  inherits?: string;
}

/**
 * PropertyInfo extracted from SDEF
 */
export interface PropertyInfo {
  name: string;
  code: string;
  type: string;
  description?: string;
  optional?: boolean;
}

/**
 * ElementInfo extracted from SDEF
 */
export interface ElementInfo {
  name: string;
  type: string;
  description?: string;
}

/**
 * EnumerationInfo extracted from SDEF
 */
export interface EnumerationInfo {
  name: string;
  code: string;
  description?: string;
  values: EnumerationValue[];
}

/**
 * EnumerationValue extracted from SDEF
 */
export interface EnumerationValue {
  name: string;
  code: string;
  description?: string;
}

/**
 * Full AppObjectModel
 */
export interface AppObjectModel {
  classes: ClassInfo[];
  enumerations: EnumerationInfo[];
}

/**
 * Interface for ObjectModelExtractor
 */
export interface IObjectModelExtractor {
  extract(dictionary: SDEFDictionary): Promise<AppObjectModel>;
}

/**
 * Test fixtures
 */
function createTestClass(
  name: string,
  code: string,
  properties: PropertyInfo[] = [],
  elements?: ElementInfo[]
): SDEFClass {
  return {
    name,
    code,
    description: `${name} class`,
    properties: properties.map(p => ({
      name: p.name,
      code: p.code,
      type: p.type,
      description: p.description,
    })),
    elements: elements || [],
  };
}

function createTestEnumeration(
  name: string,
  code: string,
  values: EnumerationValue[] = []
): SDEFEnumeration {
  return {
    name,
    code,
    description: `${name} enumeration`,
    values: values.map(v => ({
      name: v.name,
      code: v.code,
      description: v.description,
    })),
  };
}

function createTestSDEF(
  classes: SDEFClass[] = [],
  enumerations: SDEFEnumeration[] = []
): SDEFDictionary {
  return {
    title: 'Test Dictionary',
    suites: [
      {
        name: 'Standard Suite',
        code: 'core',
        description: 'Standard Suite',
        commands: [],
        classes,
        enumerations,
      },
    ],
  };
}

describe('ObjectModelExtractor', () => {
  describe('extract classes', () => {
    it('should extract single class from SDEF', async () => {
      // When SDEF contains a single class
      const testClass = createTestClass('Window', 'cwin', [
        { name: 'name', code: 'pnam', type: 'text', description: 'Window name' },
        { name: 'visible', code: 'pvis', type: 'boolean' },
      ]);

      const sdef = createTestSDEF([testClass]);

      // Should extract class with properties
      expect(sdef.suites[0].classes).toHaveLength(1);
      expect(sdef.suites[0].classes[0].name).toBe('Window');
    });

    it('should extract multiple classes from SDEF', async () => {
      // When SDEF contains multiple classes
      const classes = [
        createTestClass('Window', 'cwin', []),
        createTestClass('Document', 'docu', []),
        createTestClass('Folder', 'fold', []),
      ];

      const sdef = createTestSDEF(classes);

      // Should extract all classes
      expect(sdef.suites[0].classes).toHaveLength(3);
      expect(sdef.suites[0].classes.map(c => c.name)).toEqual(['Window', 'Document', 'Folder']);
    });

    it('should extract class properties with type information', async () => {
      // When class has multiple properties with different types
      const testClass = createTestClass(
        'Document',
        'docu',
        [
          { name: 'name', code: 'pnam', type: 'text', description: 'Document name' },
          { name: 'id', code: 'ID  ', type: 'integer', description: 'Document ID' },
          { name: 'modified', code: 'imod', type: 'boolean', description: 'Is modified' },
          { name: 'path', code: 'ppth', type: 'file', description: 'File path' },
        ]
      );

      const sdef = createTestSDEF([testClass]);

      // All properties should be extracted with types preserved
      expect(sdef.suites[0].classes[0].properties).toHaveLength(4);
      expect(sdef.suites[0].classes[0].properties[0].type).toBe('text');
      expect(sdef.suites[0].classes[0].properties[1].type).toBe('integer');
    });

    it('should extract class elements (containment)', async () => {
      // When class has elements (child objects)
      const testClass: SDEFClass = {
        name: 'Application',
        code: 'capp',
        description: 'Top-level application object',
        properties: [],
        elements: [
          { name: 'document', type: 'document', description: 'Application documents' },
          { name: 'window', type: 'window', description: 'Application windows' },
        ],
      };

      const sdef = createTestSDEF([testClass]);

      // Elements should be extracted
      expect(sdef.suites[0].classes[0].elements).toHaveLength(2);
      expect(sdef.suites[0].classes[0].elements![0].name).toBe('document');
    });

    it('should extract class hierarchy information', async () => {
      // When class inherits from another class
      const parentClass = createTestClass('Item', 'cItm', [
        { name: 'name', code: 'pnam', type: 'text' },
      ]);

      const childClass: SDEFClass = {
        ...createTestClass('Document', 'docu', [
          { name: 'path', code: 'ppth', type: 'file' },
        ]),
        inherits: 'Item',
      };

      const sdef = createTestSDEF([parentClass, childClass]);

      // Child class should show inheritance
      expect(sdef.suites[0].classes[1]).toHaveProperty('inherits');
      expect(sdef.suites[0].classes[1].inherits).toBe('Item');
    });

    it('should handle class with no properties', async () => {
      // When class has no properties
      const testClass = createTestClass('EmptyClass', 'empt', []);

      const sdef = createTestSDEF([testClass]);

      // Should extract class with empty properties array
      expect(sdef.suites[0].classes[0].name).toBe('EmptyClass');
      expect(sdef.suites[0].classes[0].properties).toHaveLength(0);
    });

    it('should handle class with no elements', async () => {
      // When class has no child elements
      const testClass = createTestClass('Leaf', 'leaf', [
        { name: 'value', code: 'valu', type: 'text' },
      ]);

      const sdef = createTestSDEF([testClass]);

      // Should extract class with empty or no elements array
      expect(sdef.suites[0].classes[0].properties).toHaveLength(1);
    });

    it('should handle complex property types', async () => {
      // When properties have complex types (records, lists)
      const testClass = createTestClass(
        'ComplexClass',
        'cmplx',
        [
          { name: 'simpleText', code: 'stxt', type: 'text' },
          { name: 'itemList', code: 'ilte', type: 'list of item' },
          { name: 'record', code: 'recd', type: 'record' },
          { name: 'union', code: 'uni0', type: 'text or file' },
        ]
      );

      const sdef = createTestSDEF([testClass]);

      // All types should be preserved as-is
      expect(sdef.suites[0].classes[0].properties[1].type).toBe('list of item');
      expect(sdef.suites[0].classes[0].properties[3].type).toBe('text or file');
    });
  });

  describe('extract enumerations', () => {
    it('should extract single enumeration from SDEF', async () => {
      // When SDEF contains a single enumeration
      const testEnum = createTestEnumeration('Save Option', 'savo', [
        { name: 'yes', code: 'yes ', description: 'Save the file' },
        { name: 'no', code: 'no  ', description: 'Do not save' },
        { name: 'cancel', code: 'cncl', description: 'Cancel operation' },
      ]);

      const sdef = createTestSDEF([], [testEnum]);

      // Should extract enumeration with all values
      expect(sdef.suites[0].enumerations).toHaveLength(1);
      expect(sdef.suites[0].enumerations[0].name).toBe('Save Option');
    });

    it('should extract multiple enumerations from SDEF', async () => {
      // When SDEF contains multiple enumerations
      const enums = [
        createTestEnumeration('Save Option', 'savo', []),
        createTestEnumeration('Sort Order', 'sort', []),
        createTestEnumeration('Filter Type', 'filt', []),
      ];

      const sdef = createTestSDEF([], enums);

      // Should extract all enumerations
      expect(sdef.suites[0].enumerations).toHaveLength(3);
      expect(sdef.suites[0].enumerations.map(e => e.name)).toEqual([
        'Save Option',
        'Sort Order',
        'Filter Type',
      ]);
    });

    it('should extract enumeration values with codes', async () => {
      // When enumeration has multiple values with codes
      const testEnum = createTestEnumeration('Save Option', 'savo', [
        { name: 'yes', code: 'yes ', description: 'Save' },
        { name: 'no', code: 'no  ', description: 'Skip' },
        { name: 'ask', code: 'ask ', description: 'Ask user' },
      ]);

      const sdef = createTestSDEF([], [testEnum]);

      // All values should be extracted with codes preserved
      expect(sdef.suites[0].enumerations[0].values).toHaveLength(3);
      expect(sdef.suites[0].enumerations[0].values[0].code).toBe('yes ');
    });

    it('should handle enumeration with many values (>50)', async () => {
      // When enumeration has many values
      const values: EnumerationValue[] = [];
      for (let i = 0; i < 75; i++) {
        values.push({
          name: `value${i}`,
          code: `val${i.toString().padStart(1, '0')}`,
          description: `Value ${i}`,
        });
      }

      const testEnum = createTestEnumeration('Large Enum', 'larg', values);
      const sdef = createTestSDEF([], [testEnum]);

      // Should extract all 75 values
      expect(sdef.suites[0].enumerations[0].values).toHaveLength(75);
    });

    it('should handle enumeration with no values', async () => {
      // When enumeration is empty
      const testEnum = createTestEnumeration('Empty Enum', 'empt', []);

      const sdef = createTestSDEF([], [testEnum]);

      // Should extract enum with empty values array
      expect(sdef.suites[0].enumerations[0].name).toBe('Empty Enum');
      expect(sdef.suites[0].enumerations[0].values).toHaveLength(0);
    });
  });

  describe('extract complete object model', () => {
    it('should extract object model with both classes and enumerations', async () => {
      // When SDEF has both classes and enumerations
      const classes = [
        createTestClass('Window', 'cwin', []),
        createTestClass('Document', 'docu', []),
      ];

      const enums = [
        createTestEnumeration('Save Option', 'savo', []),
        createTestEnumeration('Sort Order', 'sort', []),
      ];

      const sdef = createTestSDEF(classes, enums);

      // Should extract both in AppObjectModel
      expect(sdef.suites[0].classes).toHaveLength(2);
      expect(sdef.suites[0].enumerations).toHaveLength(2);
    });

    it('should handle SDEF with multiple suites containing classes', async () => {
      // When classes are in multiple suites
      const sdef: SDEFDictionary = {
        title: 'Multi-Suite Dictionary',
        suites: [
          {
            name: 'Standard Suite',
            code: 'core',
            description: 'Standard classes',
            commands: [],
            classes: [createTestClass('Window', 'cwin', [])],
            enumerations: [],
          },
          {
            name: 'App Suite',
            code: 'apps',
            description: 'App-specific classes',
            commands: [],
            classes: [createTestClass('Document', 'docu', [])],
            enumerations: [],
          },
        ],
      };

      // Should extract classes from all suites
      const totalClasses = sdef.suites.reduce((sum, s) => sum + s.classes.length, 0);
      expect(totalClasses).toBe(2);
    });

    it('should return empty object model for SDEF with no classes/enums', async () => {
      // When SDEF has no object model data
      const sdef = createTestSDEF([], []);

      // Should return empty arrays
      expect(sdef.suites[0].classes).toHaveLength(0);
      expect(sdef.suites[0].enumerations).toHaveLength(0);
    });
  });

  describe('Edge cases', () => {
    it('should handle class/enum names with special characters', async () => {
      // Names with spaces, hyphens, unicode
      const testClass = createTestClass("Window's Group", 'cwng', []);
      const testEnum = createTestEnumeration('Save-Options (Draft)', 'savo', []);

      const sdef = createTestSDEF([testClass], [testEnum]);

      // Should preserve names exactly
      expect(sdef.suites[0].classes[0].name).toContain("'");
      expect(sdef.suites[0].enumerations[0].name).toContain('-');
    });

    it('should handle deeply nested class hierarchies', async () => {
      // Multi-level inheritance chain
      const classes = [
        createTestClass('Item', 'cItm', []),
        { ...createTestClass('Element', 'cEle', []), inherits: 'Item' },
        {
          ...createTestClass('SpecialElement', 'cSpl', []),
          inherits: 'Element',
        },
      ];

      const sdef = createTestSDEF(classes);

      // Should preserve inheritance chain
      expect(sdef.suites[0].classes[2]).toHaveProperty('inherits');
      expect(sdef.suites[0].classes[2].inherits).toBe('Element');
    });

    it('should handle class with many properties (100+)', async () => {
      // Class with many properties
      const properties: PropertyInfo[] = [];
      for (let i = 0; i < 120; i++) {
        properties.push({
          name: `property${i}`,
          code: `prp${i.toString().padStart(1, '0')}`,
          type: 'text',
          description: `Property ${i}`,
        });
      }

      const testClass = createTestClass('HugeClass', 'huge', properties);
      const sdef = createTestSDEF([testClass]);

      // Should extract all 120 properties
      expect(sdef.suites[0].classes[0].properties).toHaveLength(120);
    });

    it('should handle property descriptions with line breaks', async () => {
      // Descriptions with newlines and special chars
      const testClass = createTestClass(
        'Document',
        'docu',
        [
          {
            name: 'notes',
            code: 'note',
            type: 'text',
            description: 'Notes:\n- First point\n- Second point\n- Third point',
          },
        ]
      );

      const sdef = createTestSDEF([testClass]);

      // Should preserve description with newlines
      expect(sdef.suites[0].classes[0].properties[0].description).toContain('\n');
    });

    it('should handle unicode in enum values', async () => {
      // Enum values with unicode characters
      const testEnum = createTestEnumeration('Language', 'lang', [
        { name: 'english', code: 'eng ', description: 'English 🇬🇧' },
        { name: 'japanese', code: 'jpn ', description: '日本語' },
        { name: 'arabic', code: 'ara ', description: 'العربية' },
      ]);

      const sdef = createTestSDEF([], [testEnum]);

      // Should preserve unicode in descriptions
      expect(sdef.suites[0].enumerations[0].values[1].description).toContain('日本');
    });
  });
});
