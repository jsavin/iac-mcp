/**
 * Tool Generator Configuration Types
 *
 * Defines configuration options and interfaces for the tool generator module.
 */

/**
 * Application Information
 *
 * Metadata about the application being processed.
 * Used to generate tool names and populate tool metadata.
 */
export interface AppInfo {
  /**
   * Application display name (e.g., "Finder")
   */
  appName: string;

  /**
   * macOS bundle identifier (e.g., "com.apple.finder")
   */
  bundleId: string;

  /**
   * Absolute path to .app bundle
   */
  bundlePath: string;

  /**
   * Absolute path to SDEF file
   */
  sdefPath: string;
}

/**
 * Tool naming strategy
 *
 * Determines how tool names are generated from commands.
 */
export type NamingStrategy = 'app_prefix' | 'suite_prefix' | 'fully_qualified';

/**
 * Tool Generator Options
 *
 * Configuration options for customizing tool generation behavior.
 */
export interface ToolGeneratorOptions {
  /**
   * Strategy for generating tool names
   *
   * - 'app_prefix': {app}_{command} (default) - e.g., "finder_open"
   * - 'suite_prefix': {app}_{suite}_{command} - e.g., "finder_standard_open"
   * - 'fully_qualified': {bundle}.{suite}.{command} - e.g., "com.apple.finder.standard.open"
   *
   * @default 'app_prefix'
   */
  namingStrategy?: NamingStrategy;

  /**
   * Include commands marked as hidden in SDEF
   *
   * @default false
   */
  includeHiddenCommands?: boolean;

  /**
   * Maximum length for tool descriptions (truncate if longer)
   *
   * @default 500
   */
  maxDescriptionLength?: number;

  /**
   * Enable strict validation (throw on unknown types, invalid schemas, etc.)
   *
   * @default false
   */
  strictValidation?: boolean;
}

/**
 * Naming Utility Options
 *
 * Options specific to the naming utility.
 */
export interface NamingOptions {
  /**
   * Naming strategy to use
   */
  strategy?: NamingStrategy;

  /**
   * Maximum tool name length
   *
   * @default 64
   */
  maxLength?: number;

  /**
   * Whether to append hash for truncated names
   *
   * @default true
   */
  useHashForTruncation?: boolean;
}

/**
 * Type Mapper Options
 *
 * Options specific to the type mapper.
 */
export interface TypeMapperOptions {
  /**
   * Throw error on unknown SDEF types
   *
   * @default false (defaults to string type)
   */
  strictTypeChecking?: boolean;

  /**
   * Maximum nesting depth for complex types
   *
   * @default 3
   */
  maxNestingDepth?: number;
}

/**
 * Schema Builder Options
 *
 * Options specific to the schema builder.
 */
export interface SchemaBuilderOptions {
  /**
   * Maximum description length
   *
   * @default 500
   */
  maxDescriptionLength?: number;

  /**
   * Generate descriptions for parameters missing them
   *
   * @default true
   */
  generateMissingDescriptions?: boolean;

  /**
   * Name to use for direct parameters
   *
   * @default 'target'
   */
  directParameterName?: string;
}
