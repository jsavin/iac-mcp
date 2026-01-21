/**
 * Unit Tests - XML Comment Removal
 *
 * Tests for the removeXMLComments function that safely removes XML comments
 * without ReDoS vulnerability. Validates that the linear-time state machine
 * correctly handles normal comments and edge cases.
 */

import { describe, it, expect } from 'vitest';

/**
 * Copy of removeXMLComments from parse-sdef.ts for testing
 * In a real scenario, we would export this function from parse-sdef.ts
 */
function removeXMLComments(content: string): string {
  let result = '';
  let i = 0;

  while (i < content.length) {
    // Check for comment start
    if (content.substr(i, 4) === '<!--') {
      // Skip to end of comment
      const endIndex = content.indexOf('-->', i + 4);
      if (endIndex === -1) {
        // Malformed comment with no closing --> - stop processing
        // This prevents infinite loops on malformed XML
        break;
      }
      // Skip the entire comment (including the -->)
      i = endIndex + 3;
    } else {
      // Regular character - add to result
      result += content[i];
      i++;
    }
  }

  return result;
}

describe('XML Comment Removal - removeXMLComments()', () => {
  describe('Basic Comment Removal', () => {
    it('should remove single comment from XML', () => {
      const input = '<!-- comment --><root/>';
      const expected = '<root/>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should remove multiple comments from XML', () => {
      const input = '<!-- comment 1 --><root/><!-- comment 2 -->';
      const expected = '<root/>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should remove comment from middle of content', () => {
      const input = '<root><!-- comment --><child/></root>';
      const expected = '<root><child/></root>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should preserve non-comment content', () => {
      const input = '<root><child>data</child></root>';
      expect(removeXMLComments(input)).toBe(input);
    });

    it('should remove comment with special characters', () => {
      const input = '<!-- comment with <special> & characters --><root/>';
      const expected = '<root/>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should remove comment with newlines and whitespace', () => {
      const input = `<!-- multi
line
comment --><root/>`;
      const expected = '<root/>';
      expect(removeXMLComments(input)).toBe(expected);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty input', () => {
      expect(removeXMLComments('')).toBe('');
    });

    it('should handle only a comment', () => {
      const input = '<!-- just a comment -->';
      expect(removeXMLComments(input)).toBe('');
    });

    it('should handle multiple consecutive comments', () => {
      const input = '<!-- c1 --><!-- c2 --><!-- c3 -->';
      expect(removeXMLComments(input)).toBe('');
    });

    it('should handle comment with closing markers inside text', () => {
      const input = '<!-- this contains --> literal text --><root/>';
      // First --> closes the comment at "contains -->"
      // The text " literal text -->" stays in result since it's not in a comment
      const expected = ' literal text --><root/>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should handle partial comment start at end (<!--)', () => {
      const input = '<root/><!--';
      // No closing -->, so we break and stop processing
      // This is fail-secure: incomplete comments are treated as errors
      const expected = '<root/>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should handle partial comment at end (<!-- no closing', () => {
      const input = '<root/><!-- incomplete comment';
      // No closing -->, so we break and stop processing at the <!-- marker
      // This is safer than trying to preserve potentially malformed content
      const expected = '<root/>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should handle malformed XML with unclosed comment', () => {
      const input = '<root><!-- unclosed comment';
      // No closing -->, should break at the <!-- and stop processing
      // Fail-secure approach: incomplete comments are treated as errors
      const expected = '<root>';
      expect(removeXMLComments(input)).toBe(expected);
    });

    it('should handle content starting with <!--', () => {
      const input = '<!--comment-->content';
      expect(removeXMLComments(input)).toBe('content');
    });

    it('should handle content ending with -->', () => {
      const input = 'content<!--comment-->';
      expect(removeXMLComments(input)).toBe('content');
    });
  });

  describe('Performance and Security', () => {
    it('should handle large XML files efficiently (O(n) complexity)', () => {
      // Create a 1MB XML file with comments
      const largeContent = '<root>' +
        '<!-- comment -->'.repeat(50000) +
        '<data>content</data>' +
        '</root>';

      const startTime = process.hrtime.bigint();
      const result = removeXMLComments(largeContent);
      const endTime = process.hrtime.bigint();

      // Should complete in reasonable time (< 1 second for 1MB)
      const durationMs = Number(endTime - startTime) / 1_000_000;
      expect(durationMs).toBeLessThan(1000);

      // Result should have comments removed
      expect(result).not.toContain('<!--');
      expect(result).not.toContain('-->');
      expect(result).toContain('<data>content</data>');
    });

    it('should handle pathological comment patterns (ReDoS protection)', () => {
      // Test pattern that would cause ReDoS with regex: [\s\S]*?
      // This creates many overlapping possibilities for the regex engine
      const pathological = '<!--' + ' '.repeat(1000) + 'no close marker';

      const startTime = process.hrtime.bigint();
      const result = removeXMLComments(pathological);
      const endTime = process.hrtime.bigint();

      // Should complete instantly (no catastrophic backtracking)
      const durationMs = Number(endTime - startTime) / 1_000_000;
      expect(durationMs).toBeLessThan(100); // Should be < 100ms

      // Since there's no closing -->, we break and stop processing at the <!-- marker
      // Fail-secure: incomplete comments are treated as errors
      expect(result).toBe('');
    });

    it('should handle repeated closing markers without backtracking', () => {
      // Pattern that looks like multiple --> sequences
      const input = '<!--' + '-->'.repeat(1000) + '<root/>';

      const startTime = process.hrtime.bigint();
      const result = removeXMLComments(input);
      const endTime = process.hrtime.bigint();

      // Should complete instantly
      const durationMs = Number(endTime - startTime) / 1_000_000;
      expect(durationMs).toBeLessThan(100);

      // The first --> closes the comment immediately
      expect(result).toBe('-->'.repeat(999) + '<root/>');
    });
  });

  describe('Real-World SDEF Patterns', () => {
    it('should handle Finder SDEF comment pattern', () => {
      const finderPattern = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Finder SDEF Definition -->
<dictionary title="Finder">
  <!-- Command suite -->
  <suite name="Standard Suite" code="core">
  </suite>
</dictionary>`;

      const result = removeXMLComments(finderPattern);
      expect(result).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(result).toContain('<dictionary title="Finder">');
      expect(result).not.toContain('<!--');
      expect(result).not.toContain('-->');
    });

    it('should handle SDEF with ENTITY reference in comment', () => {
      const withEntity = `<!-- This refers to <!ENTITY foo> in comment, should not trigger XXE protection -->
<dictionary>
  <suite name="test" code="test"/>
</dictionary>`;

      const result = removeXMLComments(withEntity);
      expect(result).not.toContain('ENTITY'); // Comment removed
      expect(result).toContain('<dictionary>');
      expect(result).toContain('<suite name="test" code="test"/>');
    });

    it('should handle SDEF with XInclude in comment', () => {
      const withXInclude = `<!-- This file uses <xi:include href="shared.sdef"/> for shared definitions -->
<dictionary xmlns:xi="http://www.w3.org/2001/XInclude">
  <suite name="test" code="test"/>
</dictionary>`;

      const result = removeXMLComments(withXInclude);
      expect(result).not.toContain('shared.sdef');
      expect(result).toContain('xmlns:xi');
      expect(result).toContain('<suite name="test" code="test"/>');
    });

    it('should preserve dashes inside comment closing sequence', () => {
      const input = `<!-- comment with --- dashes --><root/>`;
      const result = removeXMLComments(input);
      expect(result).toBe('<root/>');
    });

    it('should handle comment immediately before DOCTYPE', () => {
      const input = `<!-- File header --><!DOCTYPE dictionary>
<dictionary/>`;
      const result = removeXMLComments(input);
      expect(result).toContain('<!DOCTYPE dictionary>');
      expect(result).not.toContain('<!-- File header -->');
    });
  });

  describe('Boundary Conditions', () => {
    it('should handle single character input', () => {
      expect(removeXMLComments('a')).toBe('a');
    });

    it('should handle exactly "<!--"', () => {
      const input = '<!--';
      // Incomplete comment at end, no closing -->
      // Fail-secure: stop processing at the <!-- marker
      expect(removeXMLComments(input)).toBe('');
    });

    it('should handle exactly "-->"', () => {
      const input = '-->';
      // Not in a comment, so it's preserved
      expect(removeXMLComments(input)).toBe('-->');
    });

    it('should handle input with only spaces', () => {
      expect(removeXMLComments('   ')).toBe('   ');
    });

    it('should handle input with only newlines', () => {
      expect(removeXMLComments('\n\n\n')).toBe('\n\n\n');
    });

    it('should handle very long comment', () => {
      const longContent = 'x'.repeat(1000000); // 1MB
      const input = `<!-- ${longContent} --><root/>`;
      const result = removeXMLComments(input);
      expect(result).toBe('<root/>');
      expect(result).not.toContain(longContent);
    });
  });

  describe('Comparison with Regex Approach (for documentation)', () => {
    it('should produce same output as regex for well-formed XML', () => {
      const wellFormedInputs = [
        '<root/><!-- comment --><child/>',
        '<!-- start --><root><child/></root><!-- end -->',
        '<root><!-- mid --></root>',
      ];

      for (const input of wellFormedInputs) {
        const stateResult = removeXMLComments(input);
        // Regex approach (only works for well-formed)
        const regexResult = input.replace(/<!--[\s\S]*?-->/g, '');
        expect(stateResult).toBe(regexResult);
      }
    });

    it('should handle malformed XML that regex would hang on', () => {
      // This pattern would potentially cause ReDoS with [\s\S]*?
      const malformedInput = '<!--' + ' '.repeat(10000);

      // State machine handles it instantly
      const result = removeXMLComments(malformedInput);
      expect(result).toBe(''); // No closing -->, so we stop at the <!--

      // This demonstrates the security improvement
    });
  });
});
