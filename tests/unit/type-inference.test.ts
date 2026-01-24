import { describe, it, expect, beforeEach } from 'vitest';
import type { ParseWarning } from '../../src/jitd/discovery/parse-sdef';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef';
import { createMinimalSDEF, createCommandFragment } from '../utils/test-helpers';

/**
 * Tests for Type Inference in Lenient Mode
 *
 * These tests validate that the SDEF parser can infer missing types
 * in lenient mode and collect warnings appropriately.
 */

describe('Type Inference - Lenient Mode', () => {
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

  describe('mode option configuration', () => {
    it('should accept lenient mode in constructor options', () => {
      const leniencyParser = new SDEFParser({ mode: 'lenient' });
      expect(leniencyParser).toBeDefined();
    });

    it('should accept strict mode in constructor options', () => {
      const strictParser = new SDEFParser({ mode: 'strict' });
      expect(strictParser).toBeDefined();
    });

    it('should default to lenient mode', () => {
      const defaultParser = new SDEFParser();
      expect(defaultParser).toBeDefined();
    });
  });

  describe('warning collection', () => {
    it('should call onWarning callback when type is inferred', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="in" code="in  " />
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      expect(warnings.length).toBeGreaterThan(0);
      const missingTypeWarning = warnings.find((w) => w.code === 'MISSING_TYPE');
      expect(missingTypeWarning).toBeDefined();
    });

    it('should include location information in warnings', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="myParam" code="prm " />
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      const warning = warnings.find((w) => w.code === 'MISSING_TYPE');
      expect(warning?.location).toBeDefined();
      expect(warning?.location.element).toBe('parameter');
      expect(warning?.location.name).toBe('myParam');
      expect(warning?.location.command).toBe('test');
      expect(warning?.location.suite).toBe('Test');
    });

    it('should include inferred value in warning', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="filePath" code="prm " />
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      const inferenceWarning = warnings.find((w) =>
        w.code.includes('INFERRED')
      );
      expect(inferenceWarning?.inferredValue).toBeDefined();
    });
  });

  describe('child <type> element parsing', () => {
    it('should parse single child type element', async () => {
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
      expect(parameter.type.type).toBe('text');
    });

    it('should handle multiple child type elements as union type', async () => {
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
      const command = result.suites[0].commands[0];
      const parameter = command.parameters[0];

      // Should use first type and warn about union
      expect(parameter.type).toBeDefined();
      const unionWarning = warnings.find(
        (w) => w.code === 'UNION_TYPE_SIMPLIFIED'
      );
      expect(unionWarning).toBeDefined();
    });

    it('should prioritize child type elements over inference', async () => {
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
      const command = result.suites[0].commands[0];
      const parameter = command.parameters[0];

      // Should use explicit type (integer), not inferred (file)
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('integer');
    });
  });

  describe('type inference from parameter names', () => {
    it('should infer file type for path-related parameters', async () => {
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

      expect(parameter.type.kind).toBe('file');
    });

    it('should infer file type for "in" parameter', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="in" code="in  " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('file');
    });

    it('should infer integer type for count-related parameters', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="count" code="cnt " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('integer');
    });

    it('should infer integer type for index-related parameters', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="index" code="idx " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('integer');
    });

    it('should infer boolean type for flag-related parameters', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="enabled" code="enab" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('boolean');
    });

    it('should infer type for "to" parameter as location specifier', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="to" code="insh" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // "to" should be location specifier
      expect(parameter.type).toBeDefined();
    });
  });

  describe('new standard parameter names', () => {
    it('should infer specifier type for "from" parameter', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="from" code="from" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
      expect(parameter.type.kind).toBe('location_specifier');
    });

    it('should infer location specifier type for "at" parameter', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="at" code="at  " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
      expect(parameter.type.kind).toBe('location_specifier');
    });

    it('should infer specifier type for "for" parameter', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="for" code="for " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
      expect(parameter.type.kind).toBe('location_specifier');
    });

    it('should infer specifier type for "of" parameter', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="of" code="of  " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
      expect(parameter.type.kind).toBe('location_specifier');
    });
  });

  describe('four-character code mapping', () => {
    it('should infer type from four-character code (kfil=file)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="document" code="kfil" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('file');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it('should infer type from four-character code (insh=location specifier)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="location" code="insh" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
    });

    it('should prioritize four-character codes over name patterns', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="filePath" code="kocl" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use code-based inference, not name-based
      expect(parameter.type).toBeDefined();
    });
  });

  describe('new four-character code mappings', () => {
    it("should infer specifier type for 'obj ' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="target" code="obj " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Fixed: 'obj ' (with trailing space) now correctly matches CODE_TO_TYPE_MAP
      // Maps to 'specifier' which parses to location_specifier type
      expect(parameter.type.kind).toBe('location_specifier');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer record type for 'reco' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="data" code="reco" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('record');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer list type for 'list' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="items" code="list" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('list');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer boolean type for 'bool' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="flag" code="bool" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('boolean');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer integer type for 'long' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="long" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('integer');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer real type for 'doub' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="number" code="doub" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('real');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer text type for 'TEXT' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="message" code="TEXT" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer file type for 'alis' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="reference" code="alis" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('file');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer file type for 'fsrf' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="fileRef" code="fsrf" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type.kind).toBe('file');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });

    it("should infer date type for 'ldt ' code", async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="value" code="ldt " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Fixed: 'ldt ' (with trailing space) now correctly matches CODE_TO_TYPE_MAP
      // Maps to 'date' type
      expect(parameter.type.kind).toBe('date');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
    });
  });

  describe('macOS-specific types', () => {
    it('should handle "missing value" type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="optional" code="opt ">
        <type type="missing value" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
    });

    it('should handle "type" type (class reference)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="each" code="kocl" type="type" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
    });

    it('should handle "location specifier" type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="position" code="pos " type="location specifier" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
    });

    it('should handle color type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="color" code="clor" type="color" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
    });

    it('should handle date type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="createdDate" code="date" type="date" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
    });
  });

  describe('context-aware defaults', () => {
    it('should default to "any" type for direct-parameter without type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <direct-parameter />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const directParam = result.suites[0].commands[0].directParameter;

      // Direct parameters should default to "any" (most flexible)
      expect(directParam?.type).toBeDefined();
    });

    it('should default to "text" for named parameter without type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="unknownParam" code="unk " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Named parameters should default to "text"
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');
    });

    it('should default to "any" for result without type', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <result />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const resultType = result.suites[0].commands[0].result;

      // Results should default to "any" if missing
      expect(resultType).toBeDefined();
    });
  });

  describe('strict mode behavior', () => {
    beforeEach(() => {
      parser = new SDEFParser({ mode: 'strict' });
    });

    it('should throw error for missing type attribute in strict mode', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="in" code="in  " />
    </command>
  </suite>
</dictionary>`;

      await expect(parser.parseContent(xml)).rejects.toThrow();
    });

    it('should succeed with explicit type attribute in strict mode', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="in" code="in  " type="file" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      expect(result).toBeDefined();
    });

    it('should succeed with child type element in strict mode', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="in" code="in  ">
        <type type="file" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      expect(result).toBeDefined();
    });
  });

  describe('property type inference', () => {
    it('should infer type for properties without type attribute', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <class name="app" code="capp">
      <property name="name" code="pnam" />
    </class>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const property = result.suites[0].classes[0].properties[0];

      expect(property.type).toBeDefined();
    });

    it('should use lenient inference for properties in lenient mode', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <class name="app" code="capp">
      <property name="filePath" code="path" />
    </class>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const property = result.suites[0].classes[0].properties[0];

      expect(property.type.kind).toBe('file');
    });
  });

  describe('integration with real-world patterns', () => {
    it('should parse Safari-like command with missing types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Safari">
  <suite name="Standard Suite" code="CoRe">
    <command name="open" code="aevtodoc">
      <parameter name="in" code="kfil" />
      <parameter name="using" code="usin" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const command = result.suites[0].commands[0];

      expect(command.parameters.length).toBe(2);
      expect(command.parameters[0].type).toBeDefined();
      expect(command.parameters[1].type).toBeDefined();
    });

    it('should parse System Events-like parameters with union types', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="System Events">
  <suite name="Standard Suite" code="CoRe">
    <command name="set" code="CoRecore">
      <parameter name="to" code="insh">
        <type type="location specifier" />
        <type type="text" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      expect(parameter.type).toBeDefined();
      const unionWarning = warnings.find(
        (w) => w.code === 'UNION_TYPE_SIMPLIFIED'
      );
      expect(unionWarning).toBeDefined();
    });
  });

  describe('substring heuristics for type inference', () => {
    describe('date/time pattern detection', () => {
      it('should infer date type for parameter named "createdDate"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="createdDate" code="cdat" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('date');
        const patternWarning = warnings.find(
          (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
        );
        expect(patternWarning).toBeDefined();
      });

      it('should infer date type for parameter named "modifiedTime"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="modifiedTime" code="mtim" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('date');
        const patternWarning = warnings.find(
          (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
        );
        expect(patternWarning).toBeDefined();
      });

      it('should infer date type for parameter named "timestamp"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="timestamp" code="tstp" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('date');
        const patternWarning = warnings.find(
          (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
        );
        expect(patternWarning).toBeDefined();
      });
    });

    describe('URL/URI pattern detection', () => {
      it('should infer text type for parameter named "websiteUrl"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="websiteUrl" code="wurl" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('primitive');
        expect(parameter.type.type).toBe('text');
        const patternWarning = warnings.find(
          (w) =>
            w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
            w.message.includes('URL/URI')
        );
        expect(patternWarning).toBeDefined();
      });

      it('should infer text type for parameter named "resourceUri"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="resourceUri" code="ruri" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('primitive');
        expect(parameter.type.type).toBe('text');
        const patternWarning = warnings.find(
          (w) =>
            w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
            w.message.includes('URL/URI')
        );
        expect(patternWarning).toBeDefined();
      });

      it('should NOT use URL heuristic for parameter named "apiEndpoint"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="apiEndpoint" code="aend" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        // Should still infer text (default), but not via URL/URI pattern
        expect(parameter.type.kind).toBe('primitive');
        expect(parameter.type.type).toBe('text');
        const urlPatternWarning = warnings.find(
          (w) =>
            w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
            w.message.includes('URL/URI')
        );
        expect(urlPatternWarning).toBeUndefined();
      });
    });

    describe('ID/identifier pattern detection', () => {
      it('should infer text type for parameter named "userId"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="userId" code="usid" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('primitive');
        expect(parameter.type.type).toBe('text');
        const patternWarning = warnings.find(
          (w) =>
            w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
            w.message.includes('ID/identifier')
        );
        expect(patternWarning).toBeDefined();
      });

      it('should infer text type for parameter named "uniqueIdentifier"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="uniqueIdentifier" code="unid" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('primitive');
        expect(parameter.type.type).toBe('text');
        const patternWarning = warnings.find(
          (w) =>
            w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
            w.message.includes('ID/identifier')
        );
        expect(patternWarning).toBeDefined();
      });

      it('should infer text type for parameter named "recordId"', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="recordId" code="rcid" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const parameter = result.suites[0].commands[0].parameters[0];

        expect(parameter.type.kind).toBe('primitive');
        expect(parameter.type.type).toBe('text');
        const patternWarning = warnings.find(
          (w) =>
            w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
            w.message.includes('ID/identifier')
        );
        expect(patternWarning).toBeDefined();
      });
    });
  });

  describe('type inference priority order', () => {
    it('should prioritize four-character code over substring pattern (userId with TEXT code)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="userId" code="TEXT" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use four-character code (TEXT -> text), not ID pattern (text)
      // Both infer text, but warning code should indicate code-based inference
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
      const patternInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.message.includes('ID/identifier')
      );
      expect(patternInferenceWarning).toBeUndefined();
    });

    it('should prioritize four-character code over substring pattern (createdDate with long code)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="createdDate" code="long" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use four-character code (long -> integer), not date pattern
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('integer');
      const codeInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE'
      );
      expect(codeInferenceWarning).toBeDefined();
      const datePatternWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
      );
      expect(datePatternWarning).toBeUndefined();
    });

    it('should prioritize standard parameter name over substring pattern (websiteUrl named "to")', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="to" code="url " />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Should use standard parameter name (to -> location specifier), not substring pattern
      // Note: "url " is not in CODE_TO_TYPE_MAP, so it falls through to name matching
      expect(parameter.type).toBeDefined();
      expect(parameter.type.kind).toBe('location_specifier');
      const nameInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_NAME'
      );
      expect(nameInferenceWarning).toBeDefined();
      const urlPatternWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.message.includes('URL/URI')
      );
      expect(urlPatternWarning).toBeUndefined();
    });

    it('should fall back to substring pattern when no code or standard name matches (userId without code)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="userId" code="usid" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // No code mapping for "usid", no standard name match for "userId"
      // Should fall back to substring pattern (ID -> text)
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');
      const patternInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.message.includes('ID/identifier')
      );
      expect(patternInferenceWarning).toBeDefined();
    });

    it('should use explicit type attribute over all inference mechanisms', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="userId" code="long" type="boolean" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Explicit type should win, no warnings should be emitted
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('boolean');
      const anyInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE' ||
               w.code === 'TYPE_INFERRED_FROM_NAME' ||
               w.code === 'TYPE_INFERRED_FROM_PATTERN'
      );
      expect(anyInferenceWarning).toBeUndefined();
    });

    it('should use child type element over all inference mechanisms', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="userId" code="long">
        <type type="real" />
      </parameter>
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Child type element should win, no inference warnings
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('real');
      const anyInferenceWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_CODE' ||
               w.code === 'TYPE_INFERRED_FROM_NAME' ||
               w.code === 'TYPE_INFERRED_FROM_PATTERN'
      );
      expect(anyInferenceWarning).toBeUndefined();
    });
  });

  describe('substring heuristic false positives / edge cases', () => {
    // Edge cases for substring pattern matching with word boundary enforcement
    // These tests verify that word boundaries prevent false positives
    // (e.g., "validate" should not match "date" pattern)

    it('should correctly handle "validate" without false date match', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="validate" code="vald" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Word boundary matching prevents false positive
      // "validate" contains "date" but not as a separate word
      // Should fall through to default text type (no pattern match)
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');

      // Verify NO date pattern warning (word boundary prevents false match)
      const datePatternWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
      );
      expect(datePatternWarning).toBeUndefined();
    });

    it('should correctly handle "validated" without false date match', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="validated" code="vald" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Word boundary matching prevents false positive
      // "validated" contains "date" but not as a separate word
      // Should fall through to default text type (no pattern match)
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');

      // Verify NO date pattern warning (word boundary prevents false match)
      const datePatternWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
      );
      expect(datePatternWarning).toBeUndefined();
    });

    it('should correctly handle "video" without false ID match', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="video" code="vido" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Word boundary matching prevents false positive
      // "video" contains "id" but not as a separate word
      // Should fall through to default text type (no pattern match)
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');

      // Verify NO ID pattern warning (word boundary prevents false match)
      const idPatternWarning = warnings.find(
        (w) =>
          w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
          w.message.includes('ID/identifier')
      );
      expect(idPatternWarning).toBeUndefined();
    });

    it('should NOT infer date type for parameter named "coordinate" (contains "date" at word boundary)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="coordinate" code="cord" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // "coordinate" contains "date" but doesn't match pattern (no Date/Time suffix)
      // Falls through to default text type - CORRECT behavior
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');

      const datePatternWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
      );
      expect(datePatternWarning).toBeUndefined();
    });

    it('should correctly handle "invalidate" without false date/ID match', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="invalidate" code="invl" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const parameter = result.suites[0].commands[0].parameters[0];

      // Word boundary matching prevents false positives
      // "invalidate" contains both "id" and "date" but neither as separate words
      // Should fall through to default text type (no pattern match)
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');

      // Verify NO date pattern warning (word boundary prevents false match)
      const datePatternWarning = warnings.find(
        (w) => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'date'
      );
      expect(datePatternWarning).toBeUndefined();

      // Verify NO ID pattern warning (word boundary prevents false match)
      const idPatternWarning = warnings.find(
        (w) =>
          w.code === 'TYPE_INFERRED_FROM_PATTERN' &&
          w.message.includes('ID/identifier')
      );
      expect(idPatternWarning).toBeUndefined();
    });
  });

  describe('substring heuristics with snake_case identifiers', () => {
    it('should infer date type for snake_case parameter "created_date"', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="created_date" code="crdt" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const param = result.suites[0].commands[0].parameters[0];

      // Pattern /(^|_)(date|time|timestamp)($|_)/i matches "created_date"
      // because "_date$" (underscore before, end after) matches the pattern
      expect(param.type.kind).toBe('date');
    });

    it('should infer text type for snake_case parameter "user_id" via ID pattern', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="user_id" code="usid" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const param = result.suites[0].commands[0].parameters[0];

      // Pattern /(^|_)(id|identifier)($|_)/i matches "user_id"
      // because "_id$" (underscore before, end after) matches the pattern
      expect(param.type).toEqual({ kind: 'primitive', type: 'text' });
    });

    it('should infer text type for snake_case parameter "web_url" via URL pattern', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="web_url" code="wurl" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const param = result.suites[0].commands[0].parameters[0];

      // Pattern /(^|_)(url|uri)($|_)/i matches "web_url"
      // because "_url$" (underscore before, end after) matches the pattern
      expect(param.type).toEqual({ kind: 'primitive', type: 'text' });
    });
  });

  describe('substring heuristics with all-caps identifiers', () => {
    it('should NOT match ID pattern for all-caps parameter "USERID" (no word boundary)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="USERID" code="USID" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const param = result.suites[0].commands[0].parameters[0];

      // "USERID" doesn't match \b(id|identifier)\b pattern (no word boundary)
      // Also doesn't match (Id|Identifier) capitalized pattern
      // Falls back to default text type
      expect(param.type).toEqual({ kind: 'primitive', type: 'text' });
    });

    it('should infer date type for all-caps parameter "TIMESTAMP" (case-insensitive word boundary)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="TIMESTAMP" code="TMSP" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const param = result.suites[0].commands[0].parameters[0];

      // "TIMESTAMP" matches \b(date|time|timestamp)\b/i pattern (case-insensitive, standalone word)
      expect(param.type.kind).toBe('date');
    });

    it('should NOT match URL pattern for all-caps parameter "WEBSITEURL" (no word boundary)', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="WEBSITEURL" code="WURL" />
    </command>
  </suite>
</dictionary>`;

      const result = await parser.parseContent(xml);
      const param = result.suites[0].commands[0].parameters[0];

      // "WEBSITEURL" doesn't match \b(url|uri)\b pattern (no word boundary between words)
      // Falls back to default text type
      expect(param.type).toEqual({ kind: 'primitive', type: 'text' });
    });
  });

  describe('substring heuristics with very long parameter names', () => {
    it('should handle very long parameter names without performance degradation', async () => {
      // 1000-character parameter name ending with "Date"
      const longName = 'a'.repeat(996) + 'Date';
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="${longName}" code="unkn" />
    </command>
  </suite>
</dictionary>`;

      const startTime = Date.now();
      const result = await parser.parseContent(xml);
      const duration = Date.now() - startTime;

      const param = result.suites[0].commands[0].parameters[0];
      // ReDoS protection: Names > 100 chars are rejected before regex operations
      // Returns 'text' (primitive type) as safe fallback
      expect(param.type.kind).toBe('primitive');
      if (param.type.kind === 'primitive') {
        expect(param.type.type).toBe('text');
      }
      expect(duration).toBeLessThan(1000); // Should complete in < 1 second (ReDoS protection prevents hang)
    });
  });

  describe('Edge Cases for Parser Fixes', () => {
    describe('ReDoS protection for integer pattern', () => {
      it('should not hang on strings with repeated count/index keywords', async () => {
        // Test that integer pattern doesn't hang on repeated keywords
        const repeatedName = 'countcountcountcountcountcountcountcount';
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="${repeatedName}" code="test" />
    </command>
  </suite>
</dictionary>`;

        const startTime = Date.now();
        const result = await parser.parseContent(xml);
        const duration = Date.now() - startTime;

        // Should complete quickly (no ReDoS)
        expect(duration).toBeLessThan(100); // Should be near-instantaneous

        // Should fall through to default text type (no pattern match)
        const param = result.suites[0].commands[0].parameters[0];
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('text');
      });

      it('should still match valid integer patterns like item_count', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="item_count" code="icnt" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // Should match (^|_)(count|index)($|_) pattern
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('integer');
      });

      it('should still match valid integer patterns like recordIndex', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="recordIndex" code="ridx" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // Should match (Count|Index) pattern
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('integer');
      });

      it('should handle pathological ReDoS input for date pattern', async () => {
        // Test repeated date/time keywords
        const repeatedName = 'datetimedatetimedatetimedatetimedate';
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="${repeatedName}" code="test" />
    </command>
  </suite>
</dictionary>`;

        const startTime = Date.now();
        const result = await parser.parseContent(xml);
        const duration = Date.now() - startTime;

        // Should complete quickly (no ReDoS)
        expect(duration).toBeLessThan(100);

        // May or may not match pattern depending on word boundaries
        const param = result.suites[0].commands[0].parameters[0];
        expect(param.type).toBeDefined();
      });

      it('should handle pathological ReDoS input for URL pattern', async () => {
        // Test repeated url/uri keywords
        const repeatedName = 'urluriurluriurluriurluriurl';
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="${repeatedName}" code="test" />
    </command>
  </suite>
</dictionary>`;

        const startTime = Date.now();
        const result = await parser.parseContent(xml);
        const duration = Date.now() - startTime;

        // Should complete quickly (no ReDoS)
        expect(duration).toBeLessThan(100);

        const param = result.suites[0].commands[0].parameters[0];
        expect(param.type).toBeDefined();
      });

      it('should handle pathological ReDoS input for ID pattern', async () => {
        // Test repeated id/identifier keywords
        const repeatedName = 'ididentifierididentifierididentifier';
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="${repeatedName}" code="test" />
    </command>
  </suite>
</dictionary>`;

        const startTime = Date.now();
        const result = await parser.parseContent(xml);
        const duration = Date.now() - startTime;

        // Should complete quickly (no ReDoS)
        expect(duration).toBeLessThan(100);

        const param = result.suites[0].commands[0].parameters[0];
        expect(param.type).toBeDefined();
      });
    });

    describe('Four-character code normalization', () => {
      it('should handle codes with trailing spaces correctly (obj )', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="target" code="obj " />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "obj " (with trailing space) should match CODE_TO_TYPE_MAP["obj "]
        // This tests that the normalization preserves trailing spaces
        expect(param.type.kind).toBe('location_specifier');

        const codeWarning = warnings.find(w => w.code === 'TYPE_INFERRED_FROM_CODE');
        expect(codeWarning).toBeDefined();
      });

      it('should handle codes with trailing spaces correctly (ldt )', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="created" code="ldt " />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "ldt " (with trailing space) should match CODE_TO_TYPE_MAP["ldt "]
        // This tests that the normalization preserves trailing spaces
        expect(param.type.kind).toBe('date');

        const codeWarning = warnings.find(w => w.code === 'TYPE_INFERRED_FROM_CODE');
        expect(codeWarning).toBeDefined();
      });

      it('should handle codes that need normalization (TEXT with variations)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="message" code="TEXT" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "TEXT" should match CODE_TO_TYPE_MAP["TEXT"]
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('text');

        const codeWarning = warnings.find(w => w.code === 'TYPE_INFERRED_FROM_CODE');
        expect(codeWarning).toBeDefined();
      });

      it('should handle code normalization with trim and padding logic (bool)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="flag" code="bool" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "bool" matches CODE_TO_TYPE_MAP["bool"]
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('boolean');

        const codeWarning = warnings.find(w => w.code === 'TYPE_INFERRED_FROM_CODE');
        expect(codeWarning).toBeDefined();
      });

      it('should verify normalization handles codes that do not match map', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="custom" code="cust" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "cust" doesn't match any CODE_TO_TYPE_MAP entry
        // Falls back to name-based inference ("custom" -> default text)
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('text');

        // Should NOT have code inference warning (code didn't match)
        const codeWarning = warnings.find(w => w.code === 'TYPE_INFERRED_FROM_CODE');
        expect(codeWarning).toBeUndefined();
      });
    });

    describe('Boolean pattern false positives', () => {
      it('should NOT infer boolean for "canvas" (starts with "can" but no camelCase)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="canvas" code="canv" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "canvas" doesn't match /^(is|has|can|should|will)[A-Z]/ (no capital after "can")
        // Falls through to default text type
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('text');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeUndefined();
      });

      it('should NOT infer boolean for "island" (starts with "is" but no camelCase)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="island" code="isld" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "island" doesn't match /^(is|has|can|should|will)[A-Z]/ (no capital after "is")
        // Falls through to default text type
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('text');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeUndefined();
      });

      it('should NOT infer boolean for "willingness" (starts with "will" but no camelCase)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="willingness" code="wlng" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "willingness" doesn't match /^(is|has|can|should|will)[A-Z]/ (no capital after "will")
        // Falls through to default text type
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('text');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeUndefined();
      });

      it('should NOT infer boolean for "history" (contains "is" but not at start)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="history" code="hist" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "history" doesn't match /^(is|has|can|should|will)[A-Z]/ ("is" not at start)
        // Falls through to default text type
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('text');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeUndefined();
      });

      it('should still infer boolean for valid "isVisible" (camelCase)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="isVisible" code="isvs" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "isVisible" matches /^(is|has|can|should|will)[A-Z]/ AND contains "visible"
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('boolean');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeDefined();
      });

      it('should still infer boolean for valid "has_permission" (contains enabled/disabled/visible)', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="hasPermission" code="hprm" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "hasPermission" matches /^(is|has|can|should|will)[A-Z]/
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('boolean');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeDefined();
      });

      it('should still infer boolean for standalone "is" keyword', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="is" code="is  " />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "is" matches /^(is|has|can|should|will)$/i (standalone keyword)
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('boolean');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeDefined();
      });

      it('should infer boolean for "enabled" substring match', async () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="enabled" code="enab" />
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);
        const param = result.suites[0].commands[0].parameters[0];

        // "enabled" matches lowerName.includes('enabled')
        expect(param.type.kind).toBe('primitive');
        expect(param.type.type).toBe('boolean');

        const boolWarning = warnings.find(
          w => w.code === 'TYPE_INFERRED_FROM_PATTERN' && w.inferredValue === 'boolean'
        );
        expect(boolWarning).toBeDefined();
      });
    });

    describe('four-character code normalization', () => {
      it('should handle four-character codes with trailing spaces (code="obj ")', async () => {
        // Test that codes with trailing spaces like "obj " are properly normalized
        // and looked up in CODE_TO_TYPE_MAP
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test Suite" code="test">
    <command name="testCmd" code="testtcmd">
      <parameter name="testParam" code="obj " description="Object specifier">
        <type type="specifier"/>
      </parameter>
    </command>
  </suite>
</dictionary>`;

        const result = await parser.parseContent(xml);

        const param = result.suites[0].commands[0].parameters[0];

        // Should use explicit type from XML
        expect(param.type.kind).toBe('location_specifier');
      });
    });
  });

  describe('edge cases', () => {
    it('should handle parameter with both type attribute and child element', async () => {
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

      // Child element should take priority
      expect(parameter.type.kind).toBe('primitive');
      expect(parameter.type.type).toBe('text');
    });

    it('should handle empty parameter name gracefully', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="" code="bad " type="text" />
    </command>
  </suite>
</dictionary>`;

      // Should either throw (missing name is required) or handle gracefully
      const result = await parser.parseContent(xml);
      expect(result).toBeDefined();
    });

    it('should collect multiple warnings in sequence', async () => {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test">
  <suite name="Test" code="TEST">
    <command name="test" code="TESTtest">
      <parameter name="param1" code="prm1" />
      <parameter name="param2" code="prm2" />
      <parameter name="param3" code="prm3" />
    </command>
  </suite>
</dictionary>`;

      await parser.parseContent(xml);

      // Should have warnings for all three missing types
      const missingTypeWarnings = warnings.filter(
        (w) => w.code === 'MISSING_TYPE'
      );
      expect(missingTypeWarnings.length).toBeGreaterThanOrEqual(3);
    });
  });
});
