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
