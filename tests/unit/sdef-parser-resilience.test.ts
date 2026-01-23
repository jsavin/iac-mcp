/**
 * Tests for Resilient SDEF Parsing
 *
 * Tests the lenient mode parsing behavior that gracefully handles malformed SDEF files.
 * These tests are written BEFORE implementation (TDD approach) and will initially fail.
 *
 * Resilience features tested:
 * 1. Lenient mode: Skip commands/enumerations with invalid codes, collect warnings
 * 2. Strict mode: Maintain backward compatibility (throw on invalid codes)
 * 3. Warning collection: Track skipped elements with context
 * 4. Mixed validity: Parse valid elements while skipping malformed ones
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SDEFParser, ParseWarning } from '../../src/jitd/discovery/parse-sdef.js';

describe('SDEF Parser Resilience', () => {
  describe('Lenient Mode - Invalid Code Handling', () => {
    it('should skip commands with invalid codes in lenient mode', async () => {
      // BBEdit-style error: non-printable character in code
      const sdefWithInvalidCommand = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="valid_command" code="validcmd">
      <direct-parameter type="text" description="Valid command"/>
    </command>
    <command name="invalid_command" code="inv\x00lid">
      <direct-parameter type="text" description="Command with null byte in code"/>
    </command>
    <command name="another_valid" code="validtwo">
      <direct-parameter type="text" description="Another valid command"/>
    </command>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithInvalidCommand);

      // Should parse successfully despite invalid command
      expect(result).toBeDefined();
      expect(result.title).toBe('Test App');
      expect(result.suites).toHaveLength(1);

      const suite = result.suites[0];
      // Should have 2 valid commands (skipped the invalid one)
      expect(suite.commands).toHaveLength(2);
      expect(suite.commands[0].name).toBe('valid_command');
      expect(suite.commands[1].name).toBe('another_valid');

      // Should collect warning for skipped command
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);

      const commandWarning = invalidCodeWarnings.find(w =>
        w.location.element === 'command' && w.location.name === 'invalid_command'
      );
      expect(commandWarning).toBeDefined();
      expect(commandWarning?.message).toContain('non-printable');
    });

    it('should skip enumerations with invalid codes in lenient mode', async () => {
      // Microsoft Office-style error: code too long (0x0092fffe = 10 chars instead of 4)
      const sdefWithInvalidEnum = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <enumeration name="valid_enum" code="vald">
      <enumerator name="value1" code="val1"/>
    </enumeration>
    <enumeration name="invalid_enum" code="0x0092fffe">
      <enumerator name="value2" code="val2"/>
    </enumeration>
    <enumeration name="another_valid_enum" code="vld2">
      <enumerator name="value3" code="val3"/>
    </enumeration>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithInvalidEnum);

      // Should parse successfully despite invalid enumeration
      expect(result).toBeDefined();
      expect(result.suites).toHaveLength(1);

      const suite = result.suites[0];
      // Should have 2 valid enumerations (skipped the invalid one)
      expect(suite.enumerations).toHaveLength(2);
      expect(suite.enumerations[0].name).toBe('valid_enum');
      expect(suite.enumerations[1].name).toBe('another_valid_enum');

      // Should collect warning for skipped enumeration
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);

      const enumWarning = invalidCodeWarnings.find(w =>
        w.location.element === 'enumeration' && w.location.name === 'invalid_enum'
      );
      expect(enumWarning).toBeDefined();
      expect(enumWarning?.message).toContain('invalid length');
    });

    it('should skip enumerators with invalid codes in lenient mode', async () => {
      // Enumerator with non-printable character in code
      const sdefWithInvalidEnumerator = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <enumeration name="test_enum" code="tenu">
      <enumerator name="valid_value" code="val1"/>
      <enumerator name="invalid_value" code="va\x00l"/>
      <enumerator name="another_valid" code="val2"/>
    </enumeration>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithInvalidEnumerator);

      // Should parse successfully
      expect(result).toBeDefined();
      expect(result.suites).toHaveLength(1);

      const enumeration = result.suites[0].enumerations[0];
      // Should have 2 valid enumerators (skipped the invalid one)
      expect(enumeration.enumerators).toHaveLength(2);
      expect(enumeration.enumerators[0].name).toBe('valid_value');
      expect(enumeration.enumerators[1].name).toBe('another_valid');

      // Should collect warning for skipped enumerator
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);

      const enumeratorWarning = invalidCodeWarnings.find(w =>
        w.location.element === 'enumerator' && w.location.name === 'invalid_value'
      );
      expect(enumeratorWarning).toBeDefined();
    });

    it('should skip parameters with invalid codes in lenient mode', async () => {
      // Parameter with invalid code
      const sdefWithInvalidParam = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="test_command" code="testcmnd">
      <parameter name="valid_param" code="vald" type="text"/>
      <parameter name="invalid_param" code="inv\x00" type="text"/>
      <parameter name="another_valid" code="vld2" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithInvalidParam);

      // Should parse successfully
      expect(result).toBeDefined();
      const command = result.suites[0].commands[0];

      // Should have 2 valid parameters (skipped the invalid one)
      expect(command.parameters).toHaveLength(2);
      expect(command.parameters[0].name).toBe('valid_param');
      expect(command.parameters[1].name).toBe('another_valid');

      // Should collect warning for skipped parameter
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);
    });

    it('should skip classes with invalid codes in lenient mode', async () => {
      // Class with invalid code
      const sdefWithInvalidClass = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <class name="valid_class" code="vcls">
      <property name="name" code="pnam" type="text" access="r"/>
    </class>
    <class name="invalid_class" code="toolong">
      <property name="value" code="valu" type="integer" access="r"/>
    </class>
    <class name="another_valid" code="vld2">
      <property name="id" code="ID  " type="text" access="r"/>
    </class>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithInvalidClass);

      // Should parse successfully
      expect(result).toBeDefined();
      const suite = result.suites[0];

      // Should have 2 valid classes (skipped the invalid one)
      expect(suite.classes).toHaveLength(2);
      expect(suite.classes[0].name).toBe('valid_class');
      expect(suite.classes[1].name).toBe('another_valid');

      // Should collect warning for skipped class
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);
    });

    it('should skip properties with invalid codes in lenient mode', async () => {
      // Property with invalid code
      const sdefWithInvalidProperty = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <class name="test_class" code="tcls">
      <property name="valid_property" code="vald" type="text" access="r"/>
      <property name="invalid_property" code="way2long" type="text" access="r"/>
      <property name="another_valid" code="vld2" type="text" access="r"/>
    </class>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithInvalidProperty);

      // Should parse successfully
      expect(result).toBeDefined();
      const classObj = result.suites[0].classes[0];

      // Should have 2 valid properties (skipped the invalid one)
      expect(classObj.properties).toHaveLength(2);
      expect(classObj.properties[0].name).toBe('valid_property');
      expect(classObj.properties[1].name).toBe('another_valid');

      // Should collect warning for skipped property
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);
    });

    it('should collect warnings for each skipped element', async () => {
      // Mix of invalid elements
      const sdefWithMultipleInvalid = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="invalid_cmd" code="inv\x00lid">
      <direct-parameter type="text"/>
    </command>
    <enumeration name="invalid_enum" code="toolong">
      <enumerator name="val" code="valu"/>
    </enumeration>
    <class name="invalid_class" code="verylongcode">
      <property name="prop" code="prop" type="text" access="r"/>
    </class>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithMultipleInvalid);

      // Should parse successfully but skip all invalid elements
      expect(result).toBeDefined();
      const suite = result.suites[0];
      expect(suite.commands).toHaveLength(0);
      expect(suite.enumerations).toHaveLength(0);
      expect(suite.classes).toHaveLength(0);

      // Should have collected warnings for all skipped elements
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings).toHaveLength(3);

      // Verify warning structure
      invalidCodeWarnings.forEach(warning => {
        expect(warning.code).toBe('INVALID_CODE_SKIPPED');
        expect(warning.message).toBeTruthy();
        expect(warning.location.element).toBeTruthy();
        expect(warning.location.name).toBeTruthy();
        expect(warning.location.suite).toBe('Test Suite');
      });
    });

    it('should parse valid elements while skipping malformed ones', async () => {
      // Mix of valid and invalid commands in same suite
      const sdefWithMixed = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="open" code="aevtodoc">
      <parameter name="file" code="kfil" type="file"/>
    </command>
    <command name="broken_cmd" code="inv\x00lid">
      <parameter name="param" code="para" type="text"/>
    </command>
    <command name="close" code="coreclos">
      <direct-parameter type="specifier"/>
    </command>
    <enumeration name="broken_enum" code="wayToolong">
      <enumerator name="val" code="valu"/>
    </enumeration>
    <enumeration name="save_options" code="savo">
      <enumerator name="yes" code="yes "/>
      <enumerator name="no" code="no  "/>
    </enumeration>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parseContent(sdefWithMixed);

      // Should parse successfully
      expect(result).toBeDefined();
      expect(result.title).toBe('Test App');

      const suite = result.suites[0];
      // Should have 2 valid commands (skipped 1 invalid)
      expect(suite.commands).toHaveLength(2);
      expect(suite.commands[0].name).toBe('open');
      expect(suite.commands[0].parameters).toHaveLength(1);
      expect(suite.commands[1].name).toBe('close');

      // Should have 1 valid enumeration (skipped 1 invalid)
      expect(suite.enumerations).toHaveLength(1);
      expect(suite.enumerations[0].name).toBe('save_options');
      expect(suite.enumerations[0].enumerators).toHaveLength(2);

      // Should have warnings for skipped elements
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings).toHaveLength(2); // 1 command + 1 enumeration
    });
  });

  describe('Strict Mode - Backward Compatibility', () => {
    it('should throw errors for invalid codes in strict mode', async () => {
      // Ensure existing behavior unchanged
      const sdefWithInvalidCommand = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="invalid_command" code="inv\x00lid">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({
        mode: 'strict',
      });

      // Should throw error in strict mode
      await expect(parser.parseContent(sdefWithInvalidCommand))
        .rejects
        .toThrow(/non-printable/);
    });

    it('should throw errors for code length violations in strict mode', async () => {
      const sdefWithLongCode = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <enumeration name="test_enum" code="toolongcode">
      <enumerator name="val" code="valu"/>
    </enumeration>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({
        mode: 'strict',
      });

      // Should throw error in strict mode
      await expect(parser.parseContent(sdefWithLongCode))
        .rejects
        .toThrow(/must be exactly 4 characters/);
    });

    it('should default to lenient mode when no mode specified', async () => {
      // Default behavior should be lenient
      const sdefWithInvalidCommand = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="valid" code="validcmd">
      <direct-parameter type="text"/>
    </command>
    <command name="invalid" code="inv\x00lid">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser(); // No mode specified

      // Should not throw (default to lenient)
      const result = await parser.parseContent(sdefWithInvalidCommand);
      expect(result).toBeDefined();
      expect(result.suites[0].commands).toHaveLength(1); // Only valid command
    });
  });

  describe('Warning Collection Infrastructure', () => {
    it('should provide detailed location context in warnings', async () => {
      const sdefWithInvalid = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="My Suite" code="mysu">
    <command name="my_command" code="mycmdcod">
      <parameter name="bad_param" code="inv\x00" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      await parser.parseContent(sdefWithInvalid);

      const invalidCodeWarning = warnings.find(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarning).toBeDefined();

      // Verify complete location context
      expect(invalidCodeWarning?.location.suite).toBe('My Suite');
      expect(invalidCodeWarning?.location.command).toBe('my_command');
      expect(invalidCodeWarning?.location.element).toBe('parameter');
      expect(invalidCodeWarning?.location.name).toBe('bad_param');
    });

    it('should allow parsing without warning callback', async () => {
      const sdefWithInvalid = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Test Suite" code="test">
    <command name="invalid" code="inv\x00lid">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      // No onWarning callback provided
      const parser = new SDEFParser({
        mode: 'lenient',
      });

      // Should not throw even without warning callback
      const result = await parser.parseContent(sdefWithInvalid);
      expect(result).toBeDefined();
    });
  });
});
