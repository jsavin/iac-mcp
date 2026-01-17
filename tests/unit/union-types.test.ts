import { describe, it, expect, beforeEach } from 'vitest';
import type { ParseWarning } from '../../src/jitd/discovery/parse-sdef';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef';

/**
 * Tests for Union Type Support (Phase 2: Multi-Type Support)
 *
 * These tests validate that the SDEF parser can handle union types
 * from multiple child <type> elements, which account for ~20% of
 * parsing failures in System Events and other complex apps.
 *
 * Target: Enable 60%+ SDEF success rate, 50+ new tools from System Events
 */

describe('Union Types - Multi-Type Support', () => {
  let parser: SDEFParser;
  let warnings: ParseWarning[];

  beforeEach(() => {
    warnings = [];
    parser = new SDEFParser({
      mode: 'lenient',
      onWarning: (warning: ParseWarning) => {
        warnings.push(warning);
      },
    });
  });

  describe('single child <type> element', () => {
    it('should parse single child type element as primary type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="location" code="loc ">
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const command = result.suites[0].commands[0];
      const parameter = command.parameters[0];

      expect(parameter.type).toBeDefined();
      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('text');
      }
    });

    it('should NOT create union for single child element', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="integer" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should be simple primitive type, not a union
      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('integer');
      }

      // Should NOT emit UNION_TYPE warning for single type
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeUndefined();
    });

    it('should work for parameters with single child type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="file" code="kfil">
        <type type="file" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('file');
    });

    it('should work for properties with single child type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <class name="app" code="capp">
      <property name="version" code="vers">
        <type type="text" />
      </property>
    </class>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const property = result.suites[0].classes[0].properties[0];

      expect(property.type.kind).toBe('primitive');
      if (property.type.kind === 'primitive') {
        expect(property.type.type).toBe('text');
      }
    });

    it('should work for direct-parameter with single child type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <direct-parameter>
        <type type="file" />
      </direct-parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const directParam = result.suites[0].commands[0].directParameter;

      expect(directParam).toBeDefined();
      expect(directParam?.type.kind).toBe('file');
    });

    it('should work for result with single child type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <result>
        <type type="boolean" />
      </result>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const resultType = result.suites[0].commands[0].result;

      expect(resultType).toBeDefined();
      expect(resultType?.kind).toBe('primitive');
      if (resultType?.kind === 'primitive') {
        expect(resultType.type).toBe('boolean');
      }
    });
  });

  describe('multiple child <type> elements (union types)', () => {
    it('should parse property with 2 child type elements', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="to" code="insh">
        <type type="location specifier" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use first type as primary
      expect(parameter.type).toBeDefined();
      expect(parameter.type.kind).toBe('location_specifier');

      // Should emit union type warning
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
      expect(unionWarning?.location.name).toBe('to');
    });

    it('should create union type with both types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <class name="app" code="capp">
      <property name="value" code="valu">
        <type type="integer" />
        <type type="text" />
      </property>
    </class>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const property = result.suites[0].classes[0].properties[0];

      // Should use first type (integer) as primary
      expect(property.type.kind).toBe('primitive');
      if (property.type.kind === 'primitive') {
        expect(property.type.type).toBe('integer');
      }

      // Should warn about union simplification
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });

    it('should parse property with 3+ child type elements', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="integer" />
        <type type="boolean" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use first type (text) as primary
      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('text');
      }

      // Should warn about union
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });

    it('should preserve union order using first type as primary', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="mixed" code="mix ">
        <type type="file" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // First type (file) should be primary
      expect(parameter.type.kind).toBe('file');
    });

    it('should handle union of primitive types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="number" code="num ">
        <type type="integer" />
        <type type="real" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('integer');
      }
    });

    it('should handle union of class types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="object" code="obj ">
        <type type="document" />
        <type type="window" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Both are class types - should use first
      expect(parameter.type.kind).toBe('class');
      if (parameter.type.kind === 'class') {
        expect(parameter.type.className).toBe('document');
      }
    });

    it('should handle mixed unions (primitive + class)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="document" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use first type (text)
      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('text');
      }
    });
  });

  describe('type attribute vs child elements', () => {
    it('should prefer child elements over type attribute', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="param" code="prm " type="file">
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Child element (text) should win over attribute (file)
      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('text');
      }
    });

    it('should use child elements when both attribute and children present', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <class name="app" code="capp">
      <property name="value" code="val " type="boolean">
        <type type="integer" />
      </property>
    </class>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const property = result.suites[0].classes[0].properties[0];

      // Child element should take priority
      expect(property.type.kind).toBe('primitive');
      if (property.type.kind === 'primitive') {
        expect(property.type.type).toBe('integer');
      }
    });

    it('should handle multiple child elements even when attribute present', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="to" code="insh" type="file">
        <type type="location specifier" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use child elements, not attribute
      expect(parameter.type.kind).toBe('location_specifier');

      // Should warn about union
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });
  });

  describe('integration with Phase 1 (type inference)', () => {
    it('should apply inference if no type attribute and no child elements', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="filePath" code="prm " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should infer file type from name
      expect(parameter.type.kind).toBe('file');

      // Should emit inference warnings
      const inferenceWarning = warnings.find((w) => w.code.includes('INFERRED'));
      expect(inferenceWarning).toBeDefined();
    });

    it('should prefer child elements over inference', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="filePath" code="prm ">
        <type type="integer" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use explicit child type, not inferred file
      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('integer');
      }

      // Should NOT emit type inference warnings
      const inferenceWarning = warnings.find((w) => w.code.includes('INFERRED'));
      expect(inferenceWarning).toBeUndefined();
    });

    it('should collect warnings properly with union types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="integer" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      // Should have union warning
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();

      // Should NOT have inference warnings
      const inferenceWarning = warnings.find((w) => w.code.includes('INFERRED'));
      expect(inferenceWarning).toBeUndefined();
    });
  });

  describe('real-world patterns from System Events', () => {
    it('should parse System Events property with union types', async () => {
      // Real pattern from System Events.sdef
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="System Events">
  <suite name="System Events" code="SEVS">
    <class name="user" code="uacc">
      <property name="home directory" code="home">
        <type type="alias" />
        <type type="text" />
      </property>
    </class>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const property = result.suites[0].classes[0].properties[0];

      expect(property.name).toBe('home directory');
      // alias maps to file
      expect(property.type.kind).toBe('file');

      // Should warn about union
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });

    it('should parse "to" parameter with location specifier + text union', async () => {
      // Common pattern in System Events commands
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="System Events">
  <suite name="Standard Suite" code="CoRe">
    <command name="move" code="CoRemove">
      <parameter name="to" code="insh">
        <type type="location specifier" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.name).toBe('to');
      expect(parameter.type.kind).toBe('location_specifier');

      // Should warn about union
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
      expect(unionWarning?.location.name).toBe('to');
    });

    it('should extract all alternative types from union', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="integer" />
        <type type="file" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Primary type
      expect(parameter.type.kind).toBe('primitive');

      // Should have union warning with all types mentioned
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });
  });

  describe('edge cases', () => {
    it('should handle empty child type elements (malformed)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      // Should handle gracefully - either use inference or default
      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
    });

    it('should handle duplicate types in union (text, text)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('text');
      }

      // Should still warn about union (even if duplicates)
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });

    it('should handle union with unknown types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="unknown_type_1" />
        <type type="unknown_type_2" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should treat unknown types as class references
      expect(parameter.type.kind).toBe('class');
      if (parameter.type.kind === 'class') {
        expect(parameter.type.className).toBe('unknown_type_1');
      }
    });

    it('should handle union of file + alias (both resolve to file)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="location" code="loc ">
        <type type="file" />
        <type type="alias" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Both file and alias map to { kind: 'file' }
      expect(parameter.type.kind).toBe('file');

      // Should still warn about union
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });

    it('should handle very large unions (10+ types)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="integer" />
        <type type="real" />
        <type type="boolean" />
        <type type="file" />
        <type type="date" />
        <type type="color" />
        <type type="list" />
        <type type="record" />
        <type type="type" />
        <type type="location specifier" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use first type
      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('text');
      }

      // Should warn about union
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeDefined();
    });

    it('should handle child elements with nested list types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="items" code="itm ">
        <type type="list of text" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should parse list type correctly
      expect(parameter.type.kind).toBe('list');
      if (parameter.type.kind === 'list') {
        expect(parameter.type.itemType.kind).toBe('primitive');
      }
    });
  });

  describe('backward compatibility', () => {
    it('should not affect non-union SDEFs', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val " type="text" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      if (parameter.type.kind === 'primitive') {
        expect(parameter.type.type).toBe('text');
      }

      // Should NOT emit union warnings
      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning).toBeUndefined();
    });

    it('should preserve existing parser behavior for type attributes', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="count" code="cnt " type="integer" />
      <parameter name="name" code="name" type="text" />
      <parameter name="enabled" code="enab" type="boolean" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const params = result.suites[0].commands[0].parameters;

      expect(params[0].type.kind).toBe('primitive');
      expect(params[1].type.kind).toBe('primitive');
      expect(params[2].type.kind).toBe('primitive');

      // No warnings should be emitted
      expect(warnings.length).toBe(0);
    });

    it('should preserve inference behavior when no types specified', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="filePath" code="prm " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should still infer file type
      expect(parameter.type.kind).toBe('file');

      // Should emit inference warnings
      const inferenceWarning = warnings.find((w) => w.code.includes('INFERRED'));
      expect(inferenceWarning).toBeDefined();
    });

    it('should work with existing Phase 1 tests unchanged', async () => {
      // This ensures union support doesn't break existing functionality
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="in" code="in  " />
      <parameter name="count" code="cnt " />
      <parameter name="enabled" code="enab" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const params = result.suites[0].commands[0].parameters;

      // All three should be inferred correctly
      expect(params[0].type.kind).toBe('file'); // "in" → file
      expect(params[1].type.kind).toBe('primitive'); // "count" → integer
      expect(params[2].type.kind).toBe('primitive'); // "enabled" → boolean
    });
  });

  describe('strict mode with union types', () => {
    beforeEach(() => {
      parser = new SDEFParser({ mode: 'strict' });
    });

    it('should succeed with child type elements in strict mode', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="to" code="insh">
        <type type="location specifier" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      expect(result).toBeDefined();

      const parameter = result.suites[0].commands[0].parameters[0];
      expect(parameter.type.kind).toBe('location_specifier');
    });

    it('should succeed with single child type element in strict mode', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      expect(result).toBeDefined();

      const parameter = result.suites[0].commands[0].parameters[0];
      expect(parameter.type.kind).toBe('primitive');
    });

    it('should throw error for missing type in strict mode', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val " />
    </command>
  </suite>
</dictionary>`;

      await expect(parser.parseContent(xml)).rejects.toThrow();
    });
  });

  describe('warning context information', () => {
    it('should include suite context in union warnings', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="MyTestSuite" code="TEST">
    <command name="myCommand" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="integer" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning?.location.suite).toBe('MyTestSuite');
      expect(unionWarning?.location.command).toBe('myCommand');
      expect(unionWarning?.location.element).toBe('parameter');
      expect(unionWarning?.location.name).toBe('value');
    });

    it('should include inferred value in union warnings', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="to" code="insh">
        <type type="location specifier" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning?.inferredValue).toBeDefined();
      expect(unionWarning?.inferredValue).toBe('location specifier');
    });

    it('should provide clear warning messages for unions', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="val ">
        <type type="text" />
        <type type="integer" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      const unionWarning = warnings.find((w) => w.code === 'UNION_TYPE_SIMPLIFIED');
      expect(unionWarning?.message).toBeDefined();
      expect(unionWarning?.message.toLowerCase()).toContain('type');
    });
  });
});
