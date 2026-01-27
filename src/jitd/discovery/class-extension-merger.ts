/**
 * Class Extension Merger
 *
 * Merges class extensions into base classes, combining properties
 * and elements from multiple extensions.
 */

import type { ParsedClass, ClassExtension } from './types.js';

/**
 * Merge class extensions into a base class
 *
 * Creates a new class with all properties and elements from the base
 * class plus all matching extensions.
 *
 * @param baseClass - The base class to extend
 * @param extensions - Array of extensions (only matching ones will be applied)
 * @returns New class with merged properties and elements
 */
export function mergeClassExtensions(
  baseClass: ParsedClass,
  extensions: ClassExtension[]
): ParsedClass {
  // Filter extensions that apply to this class
  const applicableExtensions = extensions.filter(
    (ext) => ext.extends === baseClass.name
  );

  // If no extensions apply, return a copy of the base class
  if (applicableExtensions.length === 0) {
    return {
      ...baseClass,
      properties: [...baseClass.properties],
      elements: [...baseClass.elements],
    };
  }

  // Merge all extensions
  const mergedProperties = [...baseClass.properties];
  const mergedElements = [...baseClass.elements];

  for (const ext of applicableExtensions) {
    // Add properties from extension
    for (const prop of ext.properties) {
      // Check if property already exists (by code)
      const exists = mergedProperties.some((p) => p.code === prop.code);
      if (!exists) {
        mergedProperties.push(prop);
      }
    }

    // Add elements from extension
    for (const elem of ext.elements) {
      // Check if element already exists (by type)
      const exists = mergedElements.some((e) => e.type === elem.type);
      if (!exists) {
        mergedElements.push(elem);
      }
    }
  }

  return {
    ...baseClass,
    properties: mergedProperties,
    elements: mergedElements,
  };
}
