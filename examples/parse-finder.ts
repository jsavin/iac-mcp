/**
 * Example: Parse Finder.sdef and display structured information
 *
 * This example demonstrates how to use the SDEF parser to extract
 * commands, classes, and enumerations from macOS Finder.
 */

import { sdefParser } from '../src/jitd/discovery/parse-sdef.js';

async function main() {
  const finderSDEFPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';

  console.log('Parsing Finder.sdef...\n');
  const startTime = Date.now();

  try {
    const result = await sdefParser.parse(finderSDEFPath);

    const elapsed = Date.now() - startTime;
    console.log(`✓ Parsed in ${elapsed}ms\n`);

    // Display summary
    console.log('=== Summary ===');
    console.log(`Title: ${result.title}`);
    console.log(`Suites: ${result.suites.length}`);
    console.log(
      `Total Commands: ${result.suites.reduce((sum, s) => sum + s.commands.length, 0)}`
    );
    console.log(`Total Classes: ${result.suites.reduce((sum, s) => sum + s.classes.length, 0)}`);
    console.log(
      `Total Enumerations: ${result.suites.reduce((sum, s) => sum + s.enumerations.length, 0)}\n`
    );

    // Display suites
    console.log('=== Suites ===');
    for (const suite of result.suites) {
      console.log(`\n${suite.name} (${suite.code})`);
      if (suite.description) {
        console.log(`  ${suite.description}`);
      }
      console.log(`  Commands: ${suite.commands.length}`);
      console.log(`  Classes: ${suite.classes.length}`);
      console.log(`  Enumerations: ${suite.enumerations.length}`);
    }

    // Display sample commands from Standard Suite
    console.log('\n=== Sample Commands: Standard Suite ===');
    const standardSuite = result.suites.find((s) => s.name === 'Standard Suite');
    if (standardSuite) {
      for (const command of standardSuite.commands.slice(0, 5)) {
        console.log(`\n${command.name} (${command.code})`);
        if (command.description) {
          console.log(`  ${command.description}`);
        }

        if (command.directParameter) {
          console.log(`  Direct parameter: ${formatType(command.directParameter.type)}`);
          if (command.directParameter.description) {
            console.log(`    ${command.directParameter.description}`);
          }
        }

        if (command.parameters.length > 0) {
          console.log('  Parameters:');
          for (const param of command.parameters) {
            const optional = param.optional ? ' (optional)' : '';
            console.log(`    - ${param.name}: ${formatType(param.type)}${optional}`);
            if (param.description) {
              console.log(`      ${param.description}`);
            }
          }
        }

        if (command.result) {
          console.log(`  Returns: ${formatType(command.result)}`);
        }
      }
    }

    // Display sample classes
    console.log('\n=== Sample Classes: Finder items ===');
    const finderItemsSuite = result.suites.find((s) => s.name === 'Finder items');
    if (finderItemsSuite) {
      for (const cls of finderItemsSuite.classes.slice(0, 2)) {
        console.log(`\n${cls.name} (${cls.code})`);
        if (cls.description) {
          console.log(`  ${cls.description}`);
        }

        if (cls.properties.length > 0) {
          console.log('  Properties:');
          for (const prop of cls.properties.slice(0, 5)) {
            console.log(`    - ${prop.name} (${prop.access}): ${formatType(prop.type)}`);
            if (prop.description) {
              console.log(`      ${prop.description}`);
            }
          }
          if (cls.properties.length > 5) {
            console.log(`    ... and ${cls.properties.length - 5} more`);
          }
        }

        if (cls.elements.length > 0) {
          console.log('  Elements:');
          for (const elem of cls.elements) {
            console.log(`    - ${elem.type} (${elem.access})`);
          }
        }
      }
    }

    // Display sample enumerations
    console.log('\n=== Sample Enumerations ===');
    const typeDefsSuite = result.suites.find((s) => s.name === 'Type Definitions');
    if (typeDefsSuite) {
      for (const enumeration of typeDefsSuite.enumerations.slice(0, 2)) {
        console.log(`\n${enumeration.name} (${enumeration.code})`);
        console.log('  Values:');
        for (const enumerator of enumeration.enumerators) {
          console.log(`    - ${enumerator.name} (${enumerator.code})`);
          if (enumerator.description) {
            console.log(`      ${enumerator.description}`);
          }
        }
      }
    }
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

/**
 * Format SDEFType for display
 */
function formatType(type: any): string {
  switch (type.kind) {
    case 'primitive':
      return type.type;
    case 'file':
      return 'file';
    case 'list':
      return `list of ${formatType(type.itemType)}`;
    case 'record':
      return 'record';
    case 'class':
      return `class ${type.className}`;
    case 'enumeration':
      return `enum ${type.enumerationName}`;
    default:
      return 'unknown';
  }
}

main();
