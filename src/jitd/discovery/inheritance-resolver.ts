/**
 * Inheritance Chain Resolver
 *
 * Resolves inheritance chains for SDEF classes, handling
 * multi-level inheritance (e.g., item → container → disk → startup disk)
 */

import type { ParsedClass } from './types.js';

/**
 * Resolve the full inheritance chain for a class
 *
 * Returns classes from base to derived, e.g.:
 * resolveInheritanceChain('startup disk') → [item, container, disk, startup disk]
 *
 * @param className - Name of the class to resolve
 * @param allClasses - All available classes
 * @returns Array of classes from base to derived (empty if class not found)
 */
export function resolveInheritanceChain(
  className: string,
  allClasses: ParsedClass[]
): ParsedClass[] {
  // Find the target class
  const targetClass = allClasses.find((c) => c.name === className);
  if (!targetClass) {
    return [];
  }

  const visited = new Set<string>(); // Track visited classes to detect cycles
  let currentClass: ParsedClass | undefined = targetClass;

  // Build chain from derived to base
  const reverseChain: ParsedClass[] = [];
  while (currentClass) {
    // Check for circular inheritance
    if (visited.has(currentClass.name)) {
      console.warn(
        `Circular inheritance detected in class hierarchy involving "${currentClass.name}"`
      );
      break;
    }

    visited.add(currentClass.name);
    reverseChain.push(currentClass);

    // Move to parent class
    if (currentClass.inherits) {
      currentClass = allClasses.find((c) => c.name === currentClass!.inherits);
      if (!currentClass) {
        // Parent class not found, stop here
        break;
      }
    } else {
      // No more parents
      break;
    }

    // Safety check: prevent infinite loops
    if (reverseChain.length > 50) {
      console.warn(
        `Inheritance chain too deep (>50 levels) for class "${className}", stopping`
      );
      break;
    }
  }

  // Reverse to get base-to-derived order
  return reverseChain.reverse();
}
