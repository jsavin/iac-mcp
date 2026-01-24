/**
 * Error Message Sanitization Utilities
 *
 * Sanitizes error messages to prevent information disclosure while preserving
 * useful debugging information.
 *
 * Strategy:
 * - PRESERVE: System paths (/Applications, /System, /Library)
 * - SANITIZE: User home directory paths (/Users/username, /home/username, $HOME)
 *
 * This allows users to share error messages for debugging without exposing
 * their username or personal directory structure.
 */

/**
 * Sanitizes error messages by removing user-specific path information
 * while preserving system paths
 *
 * @param message - Error message that may contain file paths
 * @returns Sanitized message with user paths replaced
 *
 * @example
 * sanitizeErrorMessage('/Users/jake/Documents/file.txt')
 * // Returns: '/Users/[user]/Documents/file.txt'
 *
 * @example
 * sanitizeErrorMessage('/Applications/Safari.app/Contents/Resources/Safari.sdef')
 * // Returns: '/Applications/Safari.app/Contents/Resources/Safari.sdef' (unchanged)
 */
export function sanitizeErrorMessage(message: string): string {
  if (!message) {
    return message;
  }

  let sanitized = message;

  // Step 1: Sanitize /Users/username paths (macOS)
  // Match /Users/[username] where username is any non-slash characters
  // Replace with /Users/[user] to hide username
  sanitized = sanitized.replace(/\/Users\/[^\/\s]+/g, '/Users/[user]');

  // Step 2: Sanitize /home/username paths (Linux)
  // Match /home/[username] where username is any non-slash characters
  // Replace with /home/[user] to hide username
  sanitized = sanitized.replace(/\/home\/[^\/\s]+/g, '/home/[user]');

  // Step 3: Sanitize $HOME environment variable paths
  // If $HOME is set, replace all occurrences with [HOME]
  const home = process.env.HOME;
  if (home && home.length > 0) {
    // Escape special regex characters in the home path
    const escapedHome = home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const homeRegex = new RegExp(escapedHome, 'g');
    sanitized = sanitized.replace(homeRegex, '[HOME]');
  }

  // Note: We do NOT sanitize /Applications, /System, or /Library paths
  // These are system paths and safe to expose in error messages
  // They provide useful debugging context (e.g., which app failed to parse)

  return sanitized;
}

/**
 * Sanitizes an Error object's message property
 *
 * @param error - Error object to sanitize
 * @returns New Error object with sanitized message
 *
 * @example
 * const error = new Error('Failed to read /Users/jake/file.txt');
 * const sanitized = sanitizeError(error);
 * console.log(sanitized.message); // 'Failed to read /Users/[user]/file.txt'
 */
export function sanitizeError(error: Error): Error {
  const sanitized = new Error(sanitizeErrorMessage(error.message));
  sanitized.name = error.name;
  sanitized.stack = error.stack; // Preserve stack trace (may contain paths, but useful for debugging)
  return sanitized;
}

/**
 * Sanitizes an error's message in-place (mutating)
 *
 * @param error - Error object to sanitize
 * @returns The same error object with mutated message
 *
 * @example
 * const error = new Error('Failed to read /Users/jake/file.txt');
 * sanitizeErrorInPlace(error);
 * console.log(error.message); // 'Failed to read /Users/[user]/file.txt'
 */
export function sanitizeErrorInPlace(error: Error): Error {
  error.message = sanitizeErrorMessage(error.message);
  return error;
}
