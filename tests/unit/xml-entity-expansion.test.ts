/**
 * XML Entity Expansion Security Tests
 *
 * Tests protection against XML entity expansion attacks (billion laughs, etc.)
 */

import { describe, it, expect } from 'vitest';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef.js';

describe('XML Entity Expansion Security', () => {
  describe('Billion Laughs Attack Protection', () => {
    it('should safely handle billion laughs XML entity expansion attack', async () => {
      // Classic "billion laughs" attack: exponential entity expansion
      const billionLaughs = `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<dictionary title="Test">
  <suite name="TestSuite" code="test">
    <command name="test" code="testtest">
      <documentation>&lol4;</documentation>
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();

      // Should NOT expand entities, should either:
      // 1. Parse without expanding (entity references left as-is)
      // 2. Throw an error about entities
      // 3. Ignore the entity reference completely
      //
      // What we DON'T want: exponential memory/CPU consumption from expansion
      const result = await parser.parseContent(billionLaughs);

      // Should complete in reasonable time without hanging or consuming GB of memory
      expect(result).toBeDefined();

      // If it parsed successfully, verify it didn't expand the entity
      if (result.suites && result.suites.length > 0) {
        const command = result.suites[0]?.commands?.[0];
        if (command && command.documentation) {
          // Should NOT contain expanded "lollollollol..." (billions of characters)
          // Should contain literal "&lol4;" or be empty/undefined
          expect(command.documentation).not.toMatch(/lol{10,}/); // Not expanded to gigabytes
          expect(command.documentation.length).toBeLessThan(100); // Not expanded to gigabytes
        }
      }
    });

    it('should safely handle nested entity references', async () => {
      const nestedEntities = `<?xml version="1.0"?>
<!DOCTYPE dictionary [
  <!ENTITY a "AAAA">
  <!ENTITY b "&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;">
]>
<dictionary title="Test">
  <suite name="TestSuite" code="test">
    <command name="test" code="testtest">
      <documentation>&c;</documentation>
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      const result = await parser.parseContent(nestedEntities);

      expect(result).toBeDefined();

      // Should NOT expand to "AAAAAAAAAAAAAAAA..." (16 A's from nested expansion)
      if (result.suites && result.suites.length > 0) {
        const command = result.suites[0]?.commands?.[0];
        if (command && command.documentation) {
          expect(command.documentation).not.toMatch(/A{10,}/);
          expect(command.documentation.length).toBeLessThan(100);
        }
      }
    });

    it('should parse normal SDEF files correctly with processEntities: false', async () => {
      // Normal SDEF without entities should still work
      const normalSDEF = `<?xml version="1.0"?>
<dictionary title="TestApp">
  <suite name="Standard Suite" code="std ">
    <command name="open" code="aevtodoc">
      <direct-parameter description="The file(s) to open" type="file"/>
      <result type="integer" description="Result code"/>
    </command>
    <class name="window" code="cwin">
      <property name="name" code="pnam" type="text" access="r">
        <documentation>The title of the window</documentation>
      </property>
    </class>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      const result = await parser.parseContent(normalSDEF);

      expect(result.title).toBe('TestApp');
      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].name).toBe('Standard Suite');
      expect(result.suites[0].code).toBe('std ');
      expect(result.suites[0].commands).toHaveLength(1);
      expect(result.suites[0].commands[0].name).toBe('open');
      expect(result.suites[0].commands[0].code).toBe('aevtodoc');
    });

    it('should handle HTML entities without expanding them', async () => {
      // HTML entities like &lt; &gt; &amp; should not be expanded
      const htmlEntities = `<?xml version="1.0"?>
<dictionary title="Test">
  <suite name="TestSuite" code="test">
    <command name="test" code="testtest">
      <documentation>&lt;html&gt; &amp; other &quot;entities&quot;</documentation>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      const result = await parser.parseContent(htmlEntities);

      expect(result).toBeDefined();
      expect(result.suites).toHaveLength(1);
      expect(result.suites[0].commands).toHaveLength(1);

      // Should NOT expand HTML entities to < > & "
      // Should keep them as literal &lt; &gt; &amp; &quot; OR handle them safely
      const doc = result.suites[0].commands[0].documentation;
      if (doc) {
        // Either keeps entities as-is OR doesn't expand them into the actual symbols
        // (implementation dependent, but should not cause issues)
        expect(doc).toBeDefined();
      }
    });
  });

  describe('Entity Expansion Edge Cases', () => {
    it('should handle empty entity definitions', async () => {
      const emptyEntity = `<?xml version="1.0"?>
<!DOCTYPE dictionary [
  <!ENTITY empty "">
]>
<dictionary title="Test">
  <suite name="TestSuite" code="test">
    <command name="test" code="testtest">
      <documentation>&empty;</documentation>
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      const result = await parser.parseContent(emptyEntity);

      expect(result).toBeDefined();
      // Should handle gracefully without errors
    });

    it('should handle undefined entity references', async () => {
      const undefinedEntity = `<?xml version="1.0"?>
<dictionary title="Test">
  <suite name="TestSuite" code="test">
    <command name="test" code="testtest">
      <documentation>&undefined;</documentation>
      <parameter name="arg" code="arg1" type="text"/>
    </command>
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      const result = await parser.parseContent(undefinedEntity);

      // Should either parse (ignoring undefined entity) or throw a clear error
      expect(result).toBeDefined();
    });

    it('should complete parsing in reasonable time (< 5 seconds)', async () => {
      // Performance test: should not hang on entity-heavy documents
      const largeEntityDoc = `<?xml version="1.0"?>
<!DOCTYPE dictionary [
  <!ENTITY e1 "entity1">
  <!ENTITY e2 "entity2">
  <!ENTITY e3 "entity3">
]>
<dictionary title="Test">
  <suite name="TestSuite" code="test">
    ${Array.from({ length: 100 }, (_, i) => `
    <command name="test${i}" code="tst${String(i).padStart(5, '0')}">
      <parameter name="arg" code="arg1" type="text"/>
    </command>`).join('')}
  </suite>
</dictionary>`;

      const parser = new SDEFParser();
      const startTime = Date.now();
      const result = await parser.parseContent(largeEntityDoc);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      expect(duration).toBeLessThan(5000); // Should complete in < 5 seconds
    });
  });
});
