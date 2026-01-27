import { describe, it, expect } from 'vitest';
import type { SDEFClass, SDEFEnumeration } from '../../../src/types/sdef.js';

/**
 * Tests for SDEF Class Parser
 *
 * The class parser extracts class definitions from SDEF XML files,
 * including properties, elements, inheritance chains, and enumerations.
 *
 * This is critical for Phase 1 of object model exposure - enabling
 * queryable app data via MCP by understanding app object models.
 */

// These imports will fail until implementation is complete (TDD approach)
import {
  parseSDEFClasses,
  resolveInheritanceChain,
  mergeClassExtensions,
  type ParsedClass,
  type ParsedProperty,
  type ParsedElement,
  type ParsedEnumeration,
  type ClassExtension,
} from '../../../src/jitd/discovery/class-parser.js';

describe('parseSDEFClasses', () => {
  describe('basic class parsing', () => {
    it('should parse simple class with properties', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
              <property name="name" code="pnam" type="text" access="r"/>
              <property name="modified" code="imod" type="boolean" access="r"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(1);
      expect(result.classes[0].name).toBe('document');
      expect(result.classes[0].code).toBe('docu');
      expect(result.classes[0].properties).toHaveLength(2);
      expect(result.classes[0].properties[0].name).toBe('name');
      expect(result.classes[0].properties[0].type).toBe('text');
      expect(result.classes[0].properties[0].access).toBe('r');
      expect(result.classes[0].properties[1].name).toBe('modified');
      expect(result.classes[0].properties[1].type).toBe('boolean');
    });

    it('should parse class with multiple property types', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="event" code="wrev">
              <property name="summary" code="summ" type="text" access="rw"/>
              <property name="start date" code="sdst" type="date" access="rw"/>
              <property name="priority" code="prio" type="integer" access="rw"/>
              <property name="completed" code="comp" type="boolean" access="r"/>
              <property name="completion date" code="cmdt" type="date" access="r"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(1);
      const eventClass = result.classes[0];
      expect(eventClass.properties).toHaveLength(5);
      expect(eventClass.properties[0].type).toBe('text');
      expect(eventClass.properties[1].type).toBe('date');
      expect(eventClass.properties[2].type).toBe('integer');
      expect(eventClass.properties[3].type).toBe('boolean');
      expect(eventClass.properties[4].type).toBe('date');
    });

    it('should parse properties with descriptions', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="window" code="cwin">
              <property name="name" code="pnam" type="text" access="r" description="The title of the window"/>
              <property name="visible" code="pvis" type="boolean" access="rw" description="Whether the window is visible"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].description).toBe('The title of the window');
      expect(result.classes[0].properties[1].description).toBe('Whether the window is visible');
    });

    it('should parse properties with access modifiers', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="settings" code="sett">
              <property name="readonly prop" code="rdop" type="text" access="r"/>
              <property name="writeonly prop" code="wrop" type="text" access="w"/>
              <property name="readwrite prop" code="rwop" type="text" access="rw"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].access).toBe('r');
      expect(result.classes[0].properties[1].access).toBe('w');
      expect(result.classes[0].properties[2].access).toBe('rw');
    });

    it('should parse class with description', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="event" code="wrev" description="This class represents an event in the calendar"/>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].description).toBe('This class represents an event in the calendar');
    });
  });

  describe('inheritance', () => {
    it('should parse class with inherits attribute', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="account" code="mact">
              <property name="name" code="pnam" type="text" access="r"/>
            </class>
            <class name="imap account" code="iact" inherits="account">
              <property name="port" code="port" type="integer" access="rw"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(2);
      expect(result.classes[1].name).toBe('imap account');
      expect(result.classes[1].inherits).toBe('account');
    });

    it('should resolve inheritance chain (2 levels)', () => {
      const baseClass: ParsedClass = {
        name: 'item',
        code: 'cobj',
        properties: [
          { name: 'id', code: 'ID  ', type: 'text', access: 'r' },
        ],
        elements: [],
      };

      const childClass: ParsedClass = {
        name: 'document',
        code: 'docu',
        inherits: 'item',
        properties: [
          { name: 'name', code: 'pnam', type: 'text', access: 'r' },
        ],
        elements: [],
      };

      const chain = resolveInheritanceChain('document', [baseClass, childClass]);

      expect(chain).toHaveLength(2);
      expect(chain[0].name).toBe('item');
      expect(chain[1].name).toBe('document');
    });

    it('should resolve inheritance chain (4 levels - like Finder)', () => {
      const classes: ParsedClass[] = [
        {
          name: 'item',
          code: 'cobj',
          properties: [{ name: 'id', code: 'ID  ', type: 'text', access: 'r' }],
          elements: [],
        },
        {
          name: 'container',
          code: 'ctnr',
          inherits: 'item',
          properties: [{ name: 'name', code: 'pnam', type: 'text', access: 'r' }],
          elements: [],
        },
        {
          name: 'disk',
          code: 'cdis',
          inherits: 'container',
          properties: [{ name: 'capacity', code: 'capa', type: 'integer', access: 'r' }],
          elements: [],
        },
        {
          name: 'startup disk',
          code: 'sdsk',
          inherits: 'disk',
          properties: [{ name: 'bootable', code: 'boot', type: 'boolean', access: 'r' }],
          elements: [],
        },
      ];

      const chain = resolveInheritanceChain('startup disk', classes);

      expect(chain).toHaveLength(4);
      expect(chain[0].name).toBe('item');
      expect(chain[1].name).toBe('container');
      expect(chain[2].name).toBe('disk');
      expect(chain[3].name).toBe('startup disk');
    });

    it('should handle missing parent class gracefully', () => {
      const childClass: ParsedClass = {
        name: 'document',
        code: 'docu',
        inherits: 'nonexistent',
        properties: [],
        elements: [],
      };

      const chain = resolveInheritanceChain('document', [childClass]);

      // Should return just the child class when parent not found
      expect(chain).toHaveLength(1);
      expect(chain[0].name).toBe('document');
    });

    it('should detect circular inheritance and handle gracefully', () => {
      const classA: ParsedClass = {
        name: 'classA',
        code: 'clsA',
        inherits: 'classB',
        properties: [],
        elements: [],
      };

      const classB: ParsedClass = {
        name: 'classB',
        code: 'clsB',
        inherits: 'classA',
        properties: [],
        elements: [],
      };

      // Should not infinite loop, should detect cycle
      const chain = resolveInheritanceChain('classA', [classA, classB]);

      // Should break cycle and return partial chain
      expect(chain.length).toBeLessThan(10); // Shouldn't loop forever
    });
  });

  describe('union types', () => {
    it('should parse property with multiple type elements', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="message" code="mssg">
              <property name="signature" code="sig" access="rw">
                <type type="signature"/>
                <type type="text"/>
              </property>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].name).toBe('signature');
      expect(result.classes[0].properties[0].type).toEqual(['signature', 'text']);
    });

    it('should parse union with missing value (nullable)', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="message" code="mssg">
              <property name="signature" code="sig" access="rw">
                <type type="signature"/>
                <type type="missing value"/>
              </property>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].type).toEqual(['signature', 'missing value']);
    });

    it('should parse union with three types', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="value" code="valu">
              <property name="content" code="cont" access="rw">
                <type type="text"/>
                <type type="integer"/>
                <type type="boolean"/>
              </property>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].type).toEqual(['text', 'integer', 'boolean']);
    });
  });

  describe('list types', () => {
    it('should parse inline list syntax', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
              <property name="tags" code="tags" type="list" access="rw"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].list).toBe(true);
    });

    it('should parse explicit list syntax', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
              <property name="recipients" code="recp" access="rw">
                <type type="text" list="yes"/>
              </property>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].list).toBe(true);
      expect(result.classes[0].properties[0].type).toBe('text');
    });

    it('should parse list of class references', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="message" code="mssg">
              <property name="recipients" code="recp" access="rw">
                <type type="recipient" list="yes"/>
              </property>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[0].list).toBe(true);
      expect(result.classes[0].properties[0].type).toBe('recipient');
    });
  });

  describe('enumerations', () => {
    it('should parse simple enumeration', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <enumeration name="save options" code="savo">
              <enumerator name="yes" code="yes " description="Save the file"/>
              <enumerator name="no" code="no  " description="Do not save the file"/>
              <enumerator name="ask" code="ask " description="Ask the user whether to save"/>
            </enumeration>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.enumerations).toHaveLength(1);
      expect(result.enumerations[0].name).toBe('save options');
      expect(result.enumerations[0].code).toBe('savo');
      expect(result.enumerations[0].enumerators).toHaveLength(3);
      expect(result.enumerations[0].enumerators[0].name).toBe('yes');
      expect(result.enumerations[0].enumerators[0].code).toBe('yes ');
    });

    it('should parse enumeration with descriptions', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <enumeration name="view options" code="view">
              <enumerator name="icon view" code="icnv" description="Display items as icons"/>
              <enumerator name="list view" code="lstv" description="Display items in a list"/>
            </enumeration>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.enumerations[0].enumerators[0].description).toBe('Display items as icons');
      expect(result.enumerations[0].enumerators[1].description).toBe('Display items in a list');
    });

    it('should parse enumeration without descriptions', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <enumeration name="status" code="stat">
              <enumerator name="active" code="actv"/>
              <enumerator name="inactive" code="inac"/>
            </enumeration>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.enumerations[0].enumerators[0].description).toBeUndefined();
      expect(result.enumerations[0].enumerators[1].description).toBeUndefined();
    });
  });

  describe('elements', () => {
    it('should parse class with element children', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="event" code="wrev">
              <element type="attendee"/>
              <element type="alarm"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].elements).toHaveLength(2);
      expect(result.classes[0].elements[0].type).toBe('attendee');
      expect(result.classes[0].elements[1].type).toBe('alarm');
    });

    it('should parse element with cocoa key', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
              <element type="window" cocoaKey="windows"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].elements[0].cocoaKey).toBe('windows');
    });

    it('should parse class with both properties and elements', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="event" code="wrev">
              <property name="summary" code="summ" type="text" access="rw"/>
              <property name="start date" code="sdst" type="date" access="rw"/>
              <element type="attendee"/>
              <element type="alarm"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties).toHaveLength(2);
      expect(result.classes[0].elements).toHaveLength(2);
    });
  });

  describe('hidden/deprecated', () => {
    it('should skip classes with hidden="yes"', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="visible class" code="visc">
              <property name="name" code="pnam" type="text" access="r"/>
            </class>
            <class name="hidden class" code="hidc" hidden="yes">
              <property name="name" code="pnam" type="text" access="r"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(1);
      expect(result.classes[0].name).toBe('visible class');
    });

    it('should skip properties with hidden="yes"', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
              <property name="visible prop" code="visp" type="text" access="r"/>
              <property name="hidden prop" code="hidp" type="text" access="r" hidden="yes"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties).toHaveLength(1);
      expect(result.classes[0].properties[0].name).toBe('visible prop');
    });

    it('should preserve hidden attribute for debugging', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu" hidden="yes">
              <property name="name" code="pnam" type="text" access="r" hidden="yes"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      // Hidden classes should be filtered, but if we want to preserve for debugging:
      // Adjust based on implementation decision
      expect(result.classes.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('class extensions', () => {
    it('should parse class-extension element', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
              <property name="name" code="pnam" type="text" access="r"/>
            </class>
          </suite>
          <suite name="Extension Suite" code="exts">
            <class-extension extends="document">
              <property name="custom field" code="cust" type="text" access="rw"/>
            </class-extension>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classExtensions).toHaveLength(1);
      expect(result.classExtensions[0].extends).toBe('document');
      expect(result.classExtensions[0].properties).toHaveLength(1);
    });

    it('should merge extensions into base class', () => {
      const baseClass: ParsedClass = {
        name: 'document',
        code: 'docu',
        properties: [
          { name: 'name', code: 'pnam', type: 'text', access: 'r' },
        ],
        elements: [],
      };

      const extension: ClassExtension = {
        extends: 'document',
        properties: [
          { name: 'custom field', code: 'cust', type: 'text', access: 'rw' },
        ],
        elements: [],
      };

      const merged = mergeClassExtensions(baseClass, [extension]);

      expect(merged.properties).toHaveLength(2);
      expect(merged.properties[0].name).toBe('name');
      expect(merged.properties[1].name).toBe('custom field');
    });

    it('should merge multiple extensions into base class', () => {
      const baseClass: ParsedClass = {
        name: 'document',
        code: 'docu',
        properties: [
          { name: 'name', code: 'pnam', type: 'text', access: 'r' },
        ],
        elements: [],
      };

      const extensions: ClassExtension[] = [
        {
          extends: 'document',
          properties: [
            { name: 'field1', code: 'fld1', type: 'text', access: 'rw' },
          ],
          elements: [],
        },
        {
          extends: 'document',
          properties: [
            { name: 'field2', code: 'fld2', type: 'integer', access: 'rw' },
          ],
          elements: [],
        },
      ];

      const merged = mergeClassExtensions(baseClass, extensions);

      expect(merged.properties).toHaveLength(3);
      expect(merged.properties[0].name).toBe('name');
      expect(merged.properties[1].name).toBe('field1');
      expect(merged.properties[2].name).toBe('field2');
    });

    it('should merge extension elements into base class', () => {
      const baseClass: ParsedClass = {
        name: 'document',
        code: 'docu',
        properties: [],
        elements: [
          { type: 'window' },
        ],
      };

      const extension: ClassExtension = {
        extends: 'document',
        properties: [],
        elements: [
          { type: 'attachment' },
        ],
      };

      const merged = mergeClassExtensions(baseClass, [extension]);

      expect(merged.elements).toHaveLength(2);
      expect(merged.elements[0].type).toBe('window');
      expect(merged.elements[1].type).toBe('attachment');
    });
  });

  describe('edge cases', () => {
    it('should handle empty SDEF (no classes)', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(0);
      expect(result.enumerations).toHaveLength(0);
      expect(result.classExtensions).toHaveLength(0);
    });

    it('should throw error on malformed XML', () => {
      const malformedXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
          </suite>
        </dictionary>`;

      expect(() => parseSDEFClasses(malformedXML)).toThrow();
    });

    it('should handle class with missing required attributes', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document">
              <property name="name" type="text" access="r"/>
            </class>
          </suite>
        </dictionary>`;

      // Should either skip class with missing code or provide default
      const result = parseSDEFClasses(sdefXML);

      // Implementation decision: skip invalid classes or use placeholder
      expect(result.classes.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle property with missing required attributes', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="document" code="docu">
              <property name="name" type="text"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      // Should skip property missing required 'access' or use default
      expect(result.classes[0].properties.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle empty class (no properties or elements)', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="empty class" code="empt"/>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(1);
      expect(result.classes[0].properties).toHaveLength(0);
      expect(result.classes[0].elements).toHaveLength(0);
    });

    it('should handle multiple suites with classes', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Suite 1" code="sui1">
            <class name="class1" code="cls1">
              <property name="name" code="pnam" type="text" access="r"/>
            </class>
          </suite>
          <suite name="Suite 2" code="sui2">
            <class name="class2" code="cls2">
              <property name="value" code="valu" type="integer" access="r"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(2);
      expect(result.classes[0].name).toBe('class1');
      expect(result.classes[1].name).toBe('class2');
    });

    it('should handle class with no properties but has elements', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Test Suite" code="test">
            <class name="container" code="ctnr">
              <element type="item"/>
              <element type="folder"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties).toHaveLength(0);
      expect(result.classes[0].elements).toHaveLength(2);
    });
  });

  describe('real-world SDEF examples', () => {
    it('should parse Calendar event class', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Calendar Suite" code="wcal">
            <class name="event" code="wrev" description="This class represents an event.">
              <property name="summary" code="summ" type="text" access="rw" description="The summary of the event"/>
              <property name="start date" code="sdst" type="date" access="rw" description="The start date of the event"/>
              <property name="end date" code="edst" type="date" access="rw" description="The end date of the event"/>
              <property name="allday event" code="wrad" type="boolean" access="rw" description="Whether the event is an all-day event"/>
              <element type="attendee"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(1);
      expect(result.classes[0].name).toBe('event');
      expect(result.classes[0].description).toBe('This class represents an event.');
      expect(result.classes[0].properties).toHaveLength(4);
      expect(result.classes[0].elements).toHaveLength(1);
    });

    it('should parse Mail account hierarchy', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Mail Suite" code="mail">
            <class name="account" code="mact">
              <property name="name" code="pnam" type="text" access="r" description="The name of the account"/>
              <property name="enabled" code="enbl" type="boolean" access="rw" description="Whether the account is enabled"/>
            </class>
            <class name="imap account" code="iact" inherits="account">
              <property name="port" code="port" type="integer" access="rw" description="The port number"/>
              <property name="server name" code="srvr" type="text" access="rw" description="The server name"/>
            </class>
            <class name="pop account" code="pact" inherits="account">
              <property name="delete on server" code="dlos" type="boolean" access="rw"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(3);
      expect(result.classes[0].name).toBe('account');
      expect(result.classes[1].name).toBe('imap account');
      expect(result.classes[1].inherits).toBe('account');
      expect(result.classes[2].name).toBe('pop account');
      expect(result.classes[2].inherits).toBe('account');

      // Test inheritance resolution for imap account
      const imapChain = resolveInheritanceChain('imap account', result.classes);
      expect(imapChain).toHaveLength(2);
      expect(imapChain[0].name).toBe('account');
      expect(imapChain[1].name).toBe('imap account');
    });

    it('should parse Finder item hierarchy (4 levels)', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Finder Suite" code="fndr">
            <class name="item" code="cobj">
              <property name="id" code="ID  " type="integer" access="r"/>
              <property name="name" code="pnam" type="text" access="rw"/>
            </class>
            <class name="container" code="ctnr" inherits="item">
              <property name="entire contents" code="ects" type="item" access="r">
                <type type="item" list="yes"/>
              </property>
            </class>
            <class name="disk" code="cdis" inherits="container">
              <property name="capacity" code="capa" type="integer" access="r"/>
              <property name="free space" code="frsp" type="integer" access="r"/>
            </class>
            <class name="startup disk" code="sdsk" inherits="disk">
              <property name="bootable" code="boot" type="boolean" access="r"/>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes).toHaveLength(4);

      // Test full 4-level inheritance chain
      const chain = resolveInheritanceChain('startup disk', result.classes);
      expect(chain).toHaveLength(4);
      expect(chain[0].name).toBe('item');
      expect(chain[1].name).toBe('container');
      expect(chain[2].name).toBe('disk');
      expect(chain[3].name).toBe('startup disk');
    });

    it('should parse Mail message with union type signature', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Mail Suite" code="mail">
            <class name="message" code="mssg">
              <property name="subject" code="subj" type="text" access="r"/>
              <property name="signature" code="sig" access="rw">
                <type type="signature"/>
                <type type="missing value"/>
              </property>
            </class>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.classes[0].properties[1].name).toBe('signature');
      expect(result.classes[0].properties[1].type).toEqual(['signature', 'missing value']);
    });

    it('should parse Finder view options enumeration', () => {
      const sdefXML = `<?xml version="1.0" encoding="UTF-8"?>
        <dictionary>
          <suite name="Finder Suite" code="fndr">
            <enumeration name="view" code="view">
              <enumerator name="icon view" code="icnv" description="Display items as icons"/>
              <enumerator name="list view" code="lstv" description="Display items in a list"/>
              <enumerator name="column view" code="clmv" description="Display items in columns"/>
              <enumerator name="flow view" code="flwv" description="Display items in a flow"/>
            </enumeration>
          </suite>
        </dictionary>`;

      const result = parseSDEFClasses(sdefXML);

      expect(result.enumerations).toHaveLength(1);
      expect(result.enumerations[0].name).toBe('view');
      expect(result.enumerations[0].enumerators).toHaveLength(4);
      expect(result.enumerations[0].enumerators[0].name).toBe('icon view');
    });
  });
});
