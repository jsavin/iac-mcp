/**
 * Tool Generator Constants
 *
 * Centralized constants for the tool generator module to avoid magic numbers
 * and make configuration values explicit and maintainable.
 */

/**
 * Maximum nesting depth for complex SDEF types
 *
 * Prevents infinite recursion when mapping deeply nested or circular types.
 * After this depth, complex types are simplified to generic strings or objects.
 */
export const DEFAULT_MAX_NESTING_DEPTH = 3;

/**
 * Maximum length for tool descriptions
 *
 * Descriptions longer than this will be truncated with "..." suffix.
 * Based on MCP best practices for LLM consumption.
 */
export const DEFAULT_MAX_DESCRIPTION_LENGTH = 500;

/**
 * Maximum length for tool names
 *
 * MCP protocol requirement: tool names must be 64 characters or less.
 * Names longer than this will be truncated with a hash suffix for uniqueness.
 */
export const DEFAULT_MAX_TOOL_NAME_LENGTH = 64;

/**
 * Maximum attempts to resolve name collisions
 *
 * When generating unique tool names, this limits the number of numeric
 * suffixes (_1, _2, etc.) before giving up and throwing an error.
 * Prevents infinite loops in pathological collision scenarios.
 */
export const MAX_COLLISION_RESOLUTION_ATTEMPTS = 100;

/**
 * Default LRU cache size for generated tools
 *
 * Number of tool dictionaries to cache by bundle ID.
 * Helps avoid redundant generation when processing the same app multiple times.
 */
export const DEFAULT_CACHE_SIZE = 1000;

/**
 * Length of hash suffix for truncated names
 *
 * When truncating tool names to meet the 64-character limit,
 * this many characters of the hash are appended to ensure uniqueness.
 */
export const HASH_SUFFIX_LENGTH = 8;
