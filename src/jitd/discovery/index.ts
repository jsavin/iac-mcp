/**
 * SDEF Discovery Module
 *
 * Exports all discovery-related functionality for finding SDEF files
 * in macOS application bundles.
 */

export {
  findSDEFFile,
  findAllScriptableApps,
  getSDEFPath,
  invalidateCache,
  isValidSDEFFile,
  getKnownScriptableApps,
  type AppWithSDEF,
} from './find-sdef.js';

export { SDEFParser, sdefParser } from './parse-sdef.js';
