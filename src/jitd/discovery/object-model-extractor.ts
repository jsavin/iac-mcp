/**
 * Object Model Extractor
 *
 * Extracts classes and enumerations from SDEF dictionaries in LLM-friendly format.
 * This object model is included in get_app_tools responses to help the LLM understand
 * the app's object structure and valid enumeration values.
 *
 * Phase 2 of lazy loading implementation.
 */

import type { SDEFDictionary } from '../../types/sdef.js';
import type {
  AppObjectModel,
  ClassInfo,
  PropertyInfo,
  ElementInfo,
  EnumerationInfo,
  EnumeratorInfo,
} from '../../types/app-metadata.js';

/**
 * Converts SDEF type to string representation
 *
 * Handles complex types like lists, records, and unions.
 *
 * @param type - SDEF type definition
 * @returns String representation of the type
 */
function sdefTypeToString(type: any): string {
  if (!type) {
    return 'any';
  }

  if (typeof type === 'string') {
    return type;
  }

  if (typeof type === 'object' && type.kind) {
    switch (type.kind) {
      case 'primitive':
        return type.type;
      case 'file':
        return 'file';
      case 'list':
        return `list of ${sdefTypeToString(type.itemType)}`;
      case 'record':
        return 'record';
      case 'class':
        return type.className;
      case 'enumeration':
        return type.enumerationName;
      case 'any':
        return 'any';
      case 'missing_value':
        return 'missing value';
      case 'type_class':
        return 'type';
      case 'location_specifier':
        return 'location specifier';
      case 'color':
        return 'color';
      case 'date':
        return 'date';
      case 'property':
        return 'property';
      case 'save_options':
        return 'save options';
      default:
        return 'any';
    }
  }

  // Handle union types (e.g., "text or file")
  if (typeof type === 'string' && type.includes(' or ')) {
    return type;
  }

  return 'any';
}

/**
 * Extracts object model (classes and enumerations) from SDEF dictionary
 *
 * Iterates through all suites and extracts:
 * - Classes with properties, elements, and inheritance
 * - Enumerations with their valid values
 *
 * Note: This function is synchronous but returns a Promise for API compatibility.
 * Use extractObjectModelSync() for performance-critical synchronous paths.
 *
 * @param dictionary - Parsed SDEF dictionary
 * @returns AppObjectModel containing classes and enumerations
 */
export async function extractObjectModel(dictionary: SDEFDictionary): Promise<AppObjectModel> {
  return extractObjectModelSync(dictionary);
}

/**
 * Synchronous version of extractObjectModel for performance-critical paths
 *
 * @param dictionary - Parsed SDEF dictionary
 * @returns AppObjectModel containing classes and enumerations
 */
export function extractObjectModelSync(dictionary: SDEFDictionary): AppObjectModel {
  const allClasses: ClassInfo[] = [];
  const allEnumerations: EnumerationInfo[] = [];

  // Extract classes and enumerations from all suites
  for (const suite of dictionary.suites) {
    // Extract classes
    for (const sdefClass of suite.classes) {
      const classInfo: ClassInfo = {
        name: sdefClass.name,
        code: sdefClass.code,
        description: sdefClass.description || '',
        properties: sdefClass.properties.map((prop): PropertyInfo => ({
          name: prop.name,
          code: prop.code,
          type: sdefTypeToString(prop.type),
          description: prop.description || '',
          optional: false,
        })),
        elements: sdefClass.elements.map((elem): ElementInfo => ({
          name: elem.type,
          type: elem.type,
          description: '',
        })),
      };

      // Add inheritance if present
      if (sdefClass.inherits) {
        classInfo.inherits = sdefClass.inherits;
      }

      allClasses.push(classInfo);
    }

    // Extract enumerations
    for (const sdefEnum of suite.enumerations) {
      const enumInfo: EnumerationInfo = {
        name: sdefEnum.name,
        code: sdefEnum.code,
        description: sdefEnum.description || '',
        values: sdefEnum.enumerators.map((enumerator): EnumeratorInfo => ({
          name: enumerator.name,
          code: enumerator.code,
          description: enumerator.description || '',
        })),
      };

      allEnumerations.push(enumInfo);
    }
  }

  return {
    classes: allClasses,
    enumerations: allEnumerations,
  };
}
