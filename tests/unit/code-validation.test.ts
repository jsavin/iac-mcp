/**
 * Four-Character Code Validation Security Tests
 *
 * Tests hardened validation to prevent shell injection and other attacks
 */

import { describe, it, expect } from 'vitest';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef.js';

describe('Four-Character Code Validation Security', () => {
  describe('Shell Metacharacter Rejection', () => {
    it('should reject codes containing dollar sign ($)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod$exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing pipe (|)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="co|eexec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing semicolon (;)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="c;deexec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing ampersand (&)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="co&dexec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing backtick (`)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod\`exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing greater than (>)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod>exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing less than (<)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod<exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing parentheses ()', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod(exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing square brackets []', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod[exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing curly braces {}', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod{exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing backslash (\\)', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod\\exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should reject codes containing quote marks ("\')', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code='cod"exec'>
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });
  });

  describe('Valid Code Acceptance', () => {
    it('should accept codes with uppercase letters', async () => {
      const validSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="TEST">
    <command name="cmd" code="ABCDTEST">
      <parameter name="arg" code="ARG1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      const result = await parser.parseContent(validSDEF);

      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].code).toBe('TEST');
      expect(result.suites[0].commands[0].code).toBe('ABCDTEST');
    });

    it('should accept codes with lowercase letters', async () => {
      const validSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="cmd" code="abcdtest">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      const result = await parser.parseContent(validSDEF);

      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].code).toBe('test');
      expect(result.suites[0].commands[0].code).toBe('abcdtest');
    });

    it('should accept codes with numbers', async () => {
      const validSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="te12">
    <command name="cmd" code="ab12cd34">
      <parameter name="arg" code="ar01" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      const result = await parser.parseContent(validSDEF);

      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].code).toBe('te12');
      expect(result.suites[0].commands[0].code).toBe('ab12cd34');
    });

    it('should accept codes with underscores', async () => {
      const validSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="te_t">
    <command name="cmd" code="ab_dte_t">
      <parameter name="arg" code="ar_1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      const result = await parser.parseContent(validSDEF);

      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].code).toBe('te_t');
      expect(result.suites[0].commands[0].code).toBe('ab_dte_t');
    });

    it('should accept codes with spaces', async () => {
      const validSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="te t">
    <command name="cmd" code="ab dte t">
      <parameter name="arg" code="ar 1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      const result = await parser.parseContent(validSDEF);

      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].code).toBe('te t');
      expect(result.suites[0].commands[0].code).toBe('ab dte t');
    });

    it('should accept codes with mixed alphanumeric, underscore, and space', async () => {
      const validSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="T_3t">
    <command name="cmd" code="A1_bC2_d">
      <parameter name="arg" code="x_9 " type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      const result = await parser.parseContent(validSDEF);

      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].code).toBe('T_3t');
      expect(result.suites[0].commands[0].code).toBe('A1_bC2_d');
    });

    it('should accept 8-character command codes with safe special chars', async () => {
      const validSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="valid" code="test?+#x">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      const result = await parser.parseContent(validSDEF);

      expect(result.suites[0].commands[0].name).toBe('valid');
      expect(result.suites[0].commands[0].code).toBe('test?+#x');
    });
  });

  describe('Null Byte Protection (Existing)', () => {
    it('should still reject codes containing null bytes', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="malicious" code="cod\x00exec">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/non-printable character/i);
    });
  });

  describe('Code Validation in Different Elements', () => {
    it('should validate suite codes', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="te$t">
    <command name="cmd" code="testtest">
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should validate parameter codes', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <command name="cmd" code="testtest">
      <parameter name="arg" code="ar|1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should validate class codes', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <class name="window" code="cw;n">
      <property name="name" code="pnam" type="text"/>
    </class>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should validate property codes', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <class name="window" code="cwin">
      <property name="name" code="pn&m" type="text"/>
    </class>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should validate enumeration codes', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <enumeration name="save options" code="sav$">
      <enumerator name="yes" code="yes "/>
      <enumerator name="no" code="no  "/>
    </enumeration>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });

    it('should validate enumerator codes', async () => {
      const maliciousSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="TestSuite" code="test">
    <enumeration name="save options" code="savo">
      <enumerator name="yes" code="ye$s"/>
      <enumerator name="no" code="no  "/>
    </enumeration>
  </suite>
</dictionary>`;

      const parser = new SDEFParser({ mode: 'strict' });
      await expect(parser.parseContent(maliciousSDEF)).rejects.toThrow(/disallowed characters/i);
    });
  });
});
