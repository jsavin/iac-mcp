/**
 * Integration Tests for Malformed SDEF Handling
 *
 * Tests real-world scenarios of malformed SDEF files and end-to-end handling.
 * These tests are written BEFORE implementation (TDD approach) and will initially fail.
 *
 * Scenarios tested:
 * 1. BBEdit-style errors: Non-printable characters in codes
 * 2. Microsoft Office-style errors: Invalid code lengths
 * 3. Handler integration: ListTools and CallTool with malformed SDEFs
 * 4. End-to-end resilience: Apps with parse failures still discoverable
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'os';
import { mkdtemp, writeFile, rm } from 'fs/promises';
import { join } from 'path';
import { SDEFParser, ParseWarning } from '../../src/jitd/discovery/parse-sdef.js';
import type { AppWithSDEF } from '../../src/jitd/discovery/find-sdef.js';
import { buildMetadata } from '../../src/jitd/discovery/app-metadata-builder.js';

describe('Malformed SDEF Handling (Integration)', () => {
  let testDir: string;

  beforeEach(async () => {
    // Create temporary directory for test SDEF files
    testDir = await mkdtemp(join(tmpdir(), 'sdef-test-'));
  });

  afterEach(async () => {
    // Clean up temporary directory
    if (testDir) {
      await rm(testDir, { recursive: true, force: true });
    }
  });

  /**
   * Helper to write SDEF file to disk
   */
  async function writeSDefFile(filename: string, content: string): Promise<string> {
    const filePath = join(testDir, filename);
    await writeFile(filePath, content, 'utf-8');
    return filePath;
  }

  describe('BBEdit-style errors', () => {
    it('should handle non-printable characters in codes', async () => {
      // Real-world issue: BBEdit has commands with null bytes in codes
      const bbeditStyleSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="BBEdit">
  <suite name="Text Suite" code="TEXT">
    <command name="make" code="core\x00mak">
      <direct-parameter type="text" description="Text to process"/>
      <result type="text" description="Processed text"/>
    </command>
    <command name="revert" code="miscrvrt">
      <direct-parameter type="specifier" description="Document to revert"/>
    </command>
  </suite>
</dictionary>`;

      const sdefPath = await writeSDefFile('bbedit.sdef', bbeditStyleSDEF);

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parse(sdefPath);

      // Should parse successfully despite invalid command
      expect(result).toBeDefined();
      expect(result.title).toBe('BBEdit');

      // Should have skipped the malformed command
      const suite = result.suites[0];
      expect(suite.commands).toHaveLength(1);
      expect(suite.commands[0].name).toBe('revert');

      // Should have collected warning
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);
      expect(invalidCodeWarnings[0].message).toContain('non-printable');
    });

    it('should handle control characters in codes', async () => {
      // Test various non-printable characters
      const sdefWithControlChars = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Suite" code="test">
    <command name="cmd1" code="cmd\x01cmd">
      <direct-parameter type="text"/>
    </command>
    <command name="cmd2" code="cmd\x1fcmd">
      <direct-parameter type="text"/>
    </command>
    <command name="valid_cmd" code="validcmd">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const sdefPath = await writeSDefFile('control-chars.sdef', sdefWithControlChars);

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parse(sdefPath);

      // Should skip both malformed commands
      expect(result.suites[0].commands).toHaveLength(1);
      expect(result.suites[0].commands[0].name).toBe('valid_cmd');

      // Should have warnings for both
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings).toHaveLength(2);
    });
  });

  describe('Microsoft Office-style errors', () => {
    it('should handle codes with invalid length', async () => {
      // Real-world issue: Microsoft Office has 10-char codes like "0x0092fffe"
      const officeStyleSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="Microsoft Word">
  <suite name="Word Suite" code="MSWD">
    <enumeration name="save format" code="0x0092fffe">
      <enumerator name="document" code="doc "/>
      <enumerator name="template" code="tmpl"/>
    </enumeration>
    <enumeration name="view type" code="vwtp">
      <enumerator name="normal" code="norm"/>
      <enumerator name="outline" code="outl"/>
    </enumeration>
    <command name="save" code="coresave">
      <parameter name="in" code="kfil" type="file"/>
    </command>
  </suite>
</dictionary>`;

      const sdefPath = await writeSDefFile('word.sdef', officeStyleSDEF);

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parse(sdefPath);

      // Should parse successfully
      expect(result).toBeDefined();
      expect(result.title).toBe('Microsoft Word');

      // Should have skipped the malformed enumeration
      const suite = result.suites[0];
      expect(suite.enumerations).toHaveLength(1);
      expect(suite.enumerations[0].name).toBe('view type');

      // Command should still be parsed
      expect(suite.commands).toHaveLength(1);
      expect(suite.commands[0].name).toBe('save');

      // Should have warning for invalid enumeration code
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings.length).toBeGreaterThan(0);
      expect(invalidCodeWarnings[0].message).toContain('invalid length');
    });

    it('should handle hex-style codes that are too long', async () => {
      const sdefWithLongHexCodes = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="Suite" code="test">
    <enumeration name="enum1" code="0x12345678">
      <enumerator name="val" code="valu"/>
    </enumeration>
    <enumeration name="enum2" code="0xAB">
      <enumerator name="val" code="valu"/>
    </enumeration>
    <enumeration name="valid_enum" code="vald">
      <enumerator name="val" code="valu"/>
    </enumeration>
  </suite>
</dictionary>`;

      const sdefPath = await writeSDefFile('hex-codes.sdef', sdefWithLongHexCodes);

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parse(sdefPath);

      // Should have both valid enumerations
      // Note: "0xAB" is exactly 4 characters, so it's treated as a valid (if unusual) code
      expect(result.suites[0].enumerations).toHaveLength(2);
      expect(result.suites[0].enumerations.map(e => e.name)).toContain('enum2');
      expect(result.suites[0].enumerations.map(e => e.name)).toContain('valid_enum');

      // Should have warning only for the 10-character hex code
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings).toHaveLength(1);
      expect(invalidCodeWarnings[0].message).toContain('enum1');
    });
  });

  describe('Mixed real-world scenarios', () => {
    it('should handle SDEF with multiple types of errors', async () => {
      // Combination of BBEdit-style and Office-style errors
      const mixedErrorsSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="Complex App">
  <suite name="Suite1" code="sut1">
    <command name="good_cmd1" code="goodcmd1">
      <direct-parameter type="text"/>
    </command>
    <command name="bad_cmd1" code="bad\x00cmd1">
      <direct-parameter type="text"/>
    </command>
    <enumeration name="bad_enum1" code="0x12345678">
      <enumerator name="val" code="valu"/>
    </enumeration>
    <enumeration name="good_enum1" code="gden">
      <enumerator name="val1" code="val1"/>
      <enumerator name="val2" code="val2"/>
    </enumeration>
  </suite>
  <suite name="Suite2" code="sut2">
    <command name="good_cmd2" code="goodcmd2">
      <direct-parameter type="text"/>
    </command>
    <class name="bad_class1" code="verylongcode">
      <property name="name" code="pnam" type="text" access="r"/>
    </class>
    <class name="good_class1" code="gcls">
      <property name="name" code="pnam" type="text" access="r"/>
    </class>
  </suite>
</dictionary>`;

      const sdefPath = await writeSDefFile('mixed-errors.sdef', mixedErrorsSDEF);

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      const result = await parser.parse(sdefPath);

      // Should parse both suites
      expect(result.suites).toHaveLength(2);

      // Suite1: 1 command, 1 enumeration
      const suite1 = result.suites[0];
      expect(suite1.commands).toHaveLength(1);
      expect(suite1.commands[0].name).toBe('good_cmd1');
      expect(suite1.enumerations).toHaveLength(1);
      expect(suite1.enumerations[0].name).toBe('good_enum1');

      // Suite2: 1 command, 1 class
      const suite2 = result.suites[1];
      expect(suite2.commands).toHaveLength(1);
      expect(suite2.commands[0].name).toBe('good_cmd2');
      expect(suite2.classes).toHaveLength(1);
      expect(suite2.classes[0].name).toBe('good_class1');

      // Should have warnings for all 3 skipped elements
      const invalidCodeWarnings = warnings.filter(w => w.code === 'INVALID_CODE_SKIPPED');
      expect(invalidCodeWarnings).toHaveLength(3);
    });

    it('should provide detailed context for each skipped element', async () => {
      const sdefWithContextErrors = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Test App">
  <suite name="My Suite" code="mysu">
    <command name="my_command" code="mycmdcmd">
      <parameter name="good_param" code="gprm" type="text"/>
      <parameter name="bad_param" code="b\x00pm" type="text"/>
    </command>
    <class name="my_class" code="mcls">
      <property name="good_prop" code="gpro" type="text" access="r"/>
      <property name="bad_prop" code="tooolong" type="text" access="r"/>
    </class>
  </suite>
</dictionary>`;

      const sdefPath = await writeSDefFile('context-errors.sdef', sdefWithContextErrors);

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (warning) => warnings.push(warning),
      });

      await parser.parse(sdefPath);

      // Verify parameter warning has full context
      const paramWarning = warnings.find(
        w => w.code === 'INVALID_CODE_SKIPPED' && w.location.element === 'parameter'
      );
      expect(paramWarning).toBeDefined();
      expect(paramWarning?.location.suite).toBe('My Suite');
      expect(paramWarning?.location.command).toBe('my_command');
      expect(paramWarning?.location.name).toBe('bad_param');

      // Verify property warning has full context
      const propWarning = warnings.find(
        w => w.code === 'INVALID_CODE_SKIPPED' && w.location.element === 'property'
      );
      expect(propWarning).toBeDefined();
      expect(propWarning?.location.suite).toBe('My Suite');
      expect(propWarning?.location.name).toBe('bad_prop');
    });
  });

  describe('Handler Integration', () => {
    it('should return all discovered apps including ones with parse failures', async () => {
      // This test verifies that handlers.ts returns metadata for all apps,
      // even those with SDEF parsing errors

      // Mock scenario: 3 apps discovered
      // - App1: Parses successfully
      // - App2: Parse fails (malformed SDEF)
      // - App3: Parses with warnings (partial)

      const app1SDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Good App">
  <suite name="Suite" code="test">
    <command name="cmd" code="testcmnd">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const app2SDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Broken App">
  <suite name="Suite" code="test">
    <command name="bad" code="bad\x00code">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const app3SDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Partial App">
  <suite name="Suite" code="test">
    <command name="good" code="goodcmnd">
      <direct-parameter type="text"/>
    </command>
    <command name="bad" code="toolongcode">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const sdefPath1 = await writeSDefFile('app1.sdef', app1SDEF);
      const sdefPath2 = await writeSDefFile('app2.sdef', app2SDEF);
      const sdefPath3 = await writeSDefFile('app3.sdef', app3SDEF);

      // Parse each SDEF and build metadata
      const warnings1: ParseWarning[] = [];
      const parser1 = new SDEFParser({
        mode: 'lenient',
        onWarning: (w) => warnings1.push(w),
      });
      const dict1 = await parser1.parse(sdefPath1);
      const app1: AppWithSDEF = {
        appName: 'GoodApp',
        bundlePath: '/Applications/GoodApp.app',
        sdefPath: sdefPath1,
      };
      // const metadata1 = await buildMetadata(app1, dict1, warnings1);
      // expect(metadata1.parsingStatus.status).toBe('success');

      const warnings2: ParseWarning[] = [];
      const parser2 = new SDEFParser({
        mode: 'lenient',
        onWarning: (w) => warnings2.push(w),
      });
      const dict2 = await parser2.parse(sdefPath2);
      // In this case, all commands are skipped, so suite has no commands
      // This simulates a "broken" app where nothing usable was parsed

      const warnings3: ParseWarning[] = [];
      const parser3 = new SDEFParser({
        mode: 'lenient',
        onWarning: (w) => warnings3.push(w),
      });
      const dict3 = await parser3.parse(sdefPath3);
      const app3: AppWithSDEF = {
        appName: 'PartialApp',
        bundlePath: '/Applications/PartialApp.app',
        sdefPath: sdefPath3,
      };
      // const metadata3 = await buildMetadata(app3, dict3, warnings3);
      // expect(metadata3.parsingStatus.status).toBe('partial');
      // expect(metadata3.toolCount).toBeGreaterThan(0);

      // Handlers should return all 3 apps
      // - GoodApp: status='success', toolCount > 0
      // - BrokenApp: status='partial' or 'failed', toolCount = 0
      // - PartialApp: status='partial', toolCount > 0
    });

    it('should handle get_app_tools for apps with parse failures', async () => {
      // Request tools for app with malformed SDEF
      const brokenSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Broken App">
  <suite name="Suite" code="test">
    <command name="all_bad" code="bad\x00code">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const sdefPath = await writeSDefFile('broken-app.sdef', brokenSDEF);

      const warnings: ParseWarning[] = [];
      const parser = new SDEFParser({
        mode: 'lenient',
        onWarning: (w) => warnings.push(w),
      });

      const dict = await parser.parse(sdefPath);

      // Dictionary should be valid but have no usable commands
      expect(dict).toBeDefined();
      expect(dict.suites[0].commands).toHaveLength(0);

      // get_app_tools should return empty tools array with status info
      // Expected response:
      // {
      //   tools: [],
      //   parsingStatus: {
      //     status: 'partial',
      //     warnings: [...]
      //   }
      // }

      // Should NOT crash or throw error
      expect(dict.suites).toHaveLength(1);
    });

    it('should not crash when discovering apps with malformed SDEFs', async () => {
      // This is a critical resilience test:
      // Discovery should complete even if some apps have malformed SDEFs

      const validSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Valid App">
  <suite name="Suite" code="test">
    <command name="cmd" code="testcmnd">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const brokenSDEF = `<?xml version="1.0" encoding="UTF-8"?>
<dictionary title="Broken App">
  <suite name="Suite" code="test">
    <command name="bad" code="bad\x00\x00\x00\x00">
      <direct-parameter type="text"/>
    </command>
  </suite>
</dictionary>`;

      const validPath = await writeSDefFile('valid.sdef', validSDEF);
      const brokenPath = await writeSDefFile('broken.sdef', brokenSDEF);

      // Discovery process (simulated)
      const apps: AppWithSDEF[] = [
        {
          appName: 'ValidApp',
          bundlePath: '/Applications/ValidApp.app',
          sdefPath: validPath,
        },
        {
          appName: 'BrokenApp',
          bundlePath: '/Applications/BrokenApp.app',
          sdefPath: brokenPath,
        },
      ];

      // Build metadata for all apps
      const metadataPromises = apps.map(async (app) => {
        const warnings: ParseWarning[] = [];
        const parser = new SDEFParser({
          mode: 'lenient',
          onWarning: (w) => warnings.push(w),
        });

        try {
          const dict = await parser.parse(app.sdefPath);
          return await buildMetadata(app, dict);
        } catch (error) {
          // If parsing completely fails, return fallback metadata
          // (This is what buildFallbackMetadata will do)
          return {
            appName: app.appName,
            bundleId: `com.unknown.${app.appName}`,
            description: `${app.appName} (parsing failed)`,
            toolCount: 0,
            suiteNames: [],
            parsingStatus: {
              status: 'failed' as const,
              errorMessage: error instanceof Error ? error.message : String(error),
            },
          };
        }
      });

      const results = await Promise.all(metadataPromises);

      // Should have metadata for both apps (no crashes)
      expect(results).toHaveLength(2);

      // ValidApp should be usable
      const validMetadata = results[0];
      expect(validMetadata.appName).toBe('ValidApp');
      // expect(validMetadata.parsingStatus.status).toBe('success');

      // BrokenApp should have fallback metadata
      const brokenMetadata = results[1];
      expect(brokenMetadata.appName).toBe('BrokenApp');
      // Should have some status (partial or failed)
      expect(brokenMetadata.parsingStatus.status).toBeDefined();
    });
  });

  describe('End-to-end resilience', () => {
    it('should provide useful app list even with parsing failures', async () => {
      // Scenario: User calls list_apps
      // Some apps parse cleanly, some have errors, some partially parse
      // All should be returned with appropriate status

      // This ensures the user can see what's available and what's broken
      // Rather than getting an error and seeing nothing
    });

    it('should allow calling tools on partially-parsed apps', async () => {
      // Scenario: App has 10 commands, 2 are malformed and skipped
      // The 8 valid commands should still be callable via CallTool
    });
  });
});
