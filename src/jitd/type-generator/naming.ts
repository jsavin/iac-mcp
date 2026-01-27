/**
 * Naming Convention Utilities
 *
 * Converts SDEF names to TypeScript naming conventions:
 * - camelCase for properties
 * - PascalCase for types (classes, interfaces, enums)
 */

/**
 * Convert a string to camelCase
 *
 * @param name - Input string (e.g., "start date", "item-id", "window's-group")
 * @returns camelCase string (e.g., "startDate", "itemId", "windowSGroup")
 *
 * @example
 * toCamelCase('start date') // 'startDate'
 * toCamelCase('item-id') // 'itemId'
 * toCamelCase("window's-group") // 'windowSGroup'
 */
export function toCamelCase(name: string): string {
  // Replace non-alphanumeric characters with spaces for consistent word splitting
  const normalized = name.replace(/[^a-zA-Z0-9]+/g, ' ');

  // Split into words and convert to camelCase
  const words = normalized.trim().split(/\s+/);

  if (words.length === 0) {
    return '';
  }

  // First word is lowercase, rest are capitalized
  return words
    .map((word, index) => {
      if (index === 0) {
        return word.toLowerCase();
      }
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    })
    .join('');
}

/**
 * Convert a string to PascalCase
 *
 * @param name - Input string (e.g., "save options", "read only", "imap account")
 * @returns PascalCase string (e.g., "SaveOptions", "ReadOnly", "ImapAccount")
 *
 * @example
 * toPascalCase('save options') // 'SaveOptions'
 * toPascalCase('read only') // 'ReadOnly'
 * toPascalCase('imap account') // 'ImapAccount'
 */
export function toPascalCase(name: string): string {
  // Replace non-alphanumeric characters with spaces for consistent word splitting
  const normalized = name.replace(/[^a-zA-Z0-9]+/g, ' ');

  // Split into words and convert to PascalCase
  const words = normalized.trim().split(/\s+/);

  if (words.length === 0) {
    return '';
  }

  // Capitalize first letter of each word
  return words
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join('');
}
