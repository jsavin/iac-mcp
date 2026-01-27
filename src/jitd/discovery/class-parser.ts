/**
 * SDEF Class Parser
 *
 * Parses SDEF XML files to extract class definitions, properties,
 * elements, and enumerations. This is critical for Phase 1 of
 * object model exposure.
 */

import { XMLParser, XMLValidator } from 'fast-xml-parser';
import type {
  ParsedClass,
  ParsedProperty,
  ParsedElement,
  ParsedEnumeration,
  ClassExtension,
} from './types.js';
import type {
  SDEFXMLRoot,
  SDEFClass,
  SDEFEnumeration,
  SDEFClassExtension,
  SDEFTypeElement,
} from './xml-types.js';

/**
 * Parse SDEF XML and extract all classes, enumerations, and class extensions
 *
 * @param sdefXML - The SDEF XML content as a string
 * @returns Parsed classes, enumerations, and class extensions
 * @throws Error if XML is malformed or invalid
 */
export function parseSDEFClasses(sdefXML: string): {
  classes: ParsedClass[];
  enumerations: ParsedEnumeration[];
  classExtensions: ClassExtension[];
} {
  // First validate the XML structure
  const validationResult = XMLValidator.validate(sdefXML, {
    allowBooleanAttributes: true,
  });

  if (validationResult !== true) {
    throw new Error(
      `Invalid SDEF XML: ${validationResult.err.msg} at line ${validationResult.err.line}`
    );
  }

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    allowBooleanAttributes: true,
    parseAttributeValue: false, // Keep as strings
    trimValues: false, // Preserve whitespace in attribute values (important for four-char codes)
    stopNodes: [], // Parse all nodes
  });

  let parsed: SDEFXMLRoot;
  try {
    parsed = parser.parse(sdefXML) as SDEFXMLRoot;
  } catch (error) {
    throw new Error(
      `Failed to parse SDEF XML: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const dictionary = parsed.dictionary;
  if (!dictionary) {
    throw new Error('Invalid SDEF: missing <dictionary> element');
  }

  const classes: ParsedClass[] = [];
  const enumerations: ParsedEnumeration[] = [];
  const classExtensions: ClassExtension[] = [];

  // Normalize suites to always be an array
  const suites = Array.isArray(dictionary.suite)
    ? dictionary.suite
    : dictionary.suite
    ? [dictionary.suite]
    : [];

  for (const suite of suites) {
    // Parse classes
    const suiteClasses = Array.isArray(suite.class)
      ? suite.class
      : suite.class
      ? [suite.class]
      : [];

    for (const classData of suiteClasses) {
      // Skip hidden classes
      if (classData['@_hidden'] === 'yes') {
        continue;
      }

      // Skip classes missing required attributes
      if (!classData['@_name'] || !classData['@_code']) {
        continue;
      }

      const parsedClass: ParsedClass = {
        name: classData['@_name'],
        code: classData['@_code'],
        inherits: classData['@_inherits'],
        description: classData['@_description'],
        properties: parseProperties(classData),
        elements: parseElements(classData),
      };

      classes.push(parsedClass);
    }

    // Parse enumerations
    const suiteEnums = Array.isArray(suite.enumeration)
      ? suite.enumeration
      : suite.enumeration
      ? [suite.enumeration]
      : [];

    for (const enumData of suiteEnums) {
      const parsedEnum = parseEnumeration(enumData);
      if (parsedEnum) {
        enumerations.push(parsedEnum);
      }
    }

    // Parse class extensions
    const suiteExtensions = Array.isArray(suite['class-extension'])
      ? suite['class-extension']
      : suite['class-extension']
      ? [suite['class-extension']]
      : [];

    for (const extData of suiteExtensions) {
      const extension = parseClassExtension(extData);
      if (extension) {
        classExtensions.push(extension);
      }
    }
  }

  return { classes, enumerations, classExtensions };
}

/**
 * Parse properties from a class definition
 */
function parseProperties(classData: SDEFClass | SDEFClassExtension): ParsedProperty[] {
  const properties: ParsedProperty[] = [];

  const propsData = Array.isArray(classData.property)
    ? classData.property
    : classData.property
    ? [classData.property]
    : [];

  for (const prop of propsData) {
    // Skip hidden properties
    if (prop['@_hidden'] === 'yes') {
      continue;
    }

    // Skip properties missing required attributes
    if (!prop['@_name'] || !prop['@_code']) {
      continue;
    }

    // Parse type - can be inline attribute or child elements
    let type: string | string[];
    let list = false;

    if (prop['@_type']) {
      // Inline type attribute
      type = prop['@_type'];
      // Check if it's a list type
      if (type === 'list') {
        list = true;
      }
    } else if (prop.type) {
      // Child type element(s)
      const typeElements: SDEFTypeElement[] = Array.isArray(prop.type) ? prop.type : [prop.type];

      if (typeElements.length === 1 && typeElements[0]) {
        // Single type
        const typeEl = typeElements[0];
        type = typeEl['@_type'] || 'any';
        // Check if list attribute is set
        if (typeEl['@_list'] === 'yes') {
          list = true;
        }
      } else if (typeElements.length > 1) {
        // Union type (multiple type elements)
        type = typeElements.map((t) => t['@_type'] || 'any');
        // For union types, check if any has list="yes"
        if (typeElements.some((t) => t['@_list'] === 'yes')) {
          list = true;
        }
      } else {
        // Empty type array, default to 'any'
        type = 'any';
      }
    } else {
      // No type specified, default to 'any'
      type = 'any';
    }

    const parsedProp: ParsedProperty = {
      name: prop['@_name'],
      code: prop['@_code'],
      type,
      access: prop['@_access'] as 'r' | 'w' | 'rw' | undefined,
      description: prop['@_description'],
    };

    if (list) {
      parsedProp.list = true;
    }

    properties.push(parsedProp);
  }

  return properties;
}

/**
 * Parse elements from a class definition
 */
function parseElements(classData: SDEFClass | SDEFClassExtension): ParsedElement[] {
  const elements: ParsedElement[] = [];

  const elemsData = Array.isArray(classData.element)
    ? classData.element
    : classData.element
    ? [classData.element]
    : [];

  for (const elem of elemsData) {
    if (!elem['@_type']) {
      continue;
    }

    const parsedElem: ParsedElement = {
      type: elem['@_type'],
    };

    if (elem['@_cocoaKey']) {
      parsedElem.cocoaKey = elem['@_cocoaKey'];
    }

    elements.push(parsedElem);
  }

  return elements;
}

/**
 * Parse an enumeration definition
 */
function parseEnumeration(enumData: SDEFEnumeration): ParsedEnumeration | null {
  if (!enumData['@_name'] || !enumData['@_code']) {
    return null;
  }

  const enumerators: ParsedEnumeration['enumerators'] = [];

  const enumsData = Array.isArray(enumData.enumerator)
    ? enumData.enumerator
    : enumData.enumerator
    ? [enumData.enumerator]
    : [];

  for (const enumerator of enumsData) {
    if (!enumerator['@_name'] || !enumerator['@_code']) {
      continue;
    }

    enumerators.push({
      name: enumerator['@_name'],
      code: enumerator['@_code'],
      description: enumerator['@_description'],
    });
  }

  return {
    name: enumData['@_name'],
    code: enumData['@_code'],
    enumerators,
  };
}

/**
 * Parse a class extension definition
 */
function parseClassExtension(extData: SDEFClassExtension): ClassExtension | null {
  if (!extData['@_extends']) {
    return null;
  }

  return {
    extends: extData['@_extends'],
    properties: parseProperties(extData),
    elements: parseElements(extData),
  };
}

// Re-export types for convenience
export type {
  ParsedClass,
  ParsedProperty,
  ParsedElement,
  ParsedEnumeration,
  ClassExtension,
};

// Re-export related functions
export { resolveInheritanceChain } from './inheritance-resolver.js';
export { mergeClassExtensions } from './class-extension-merger.js';
