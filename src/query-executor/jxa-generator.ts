/**
 * JXA script generation for Calendar.app queries
 */

import { QueryParams } from './types.js';

/**
 * Maximum allowed length for calendar names
 */
const MAX_CALENDAR_NAME_LENGTH = 100;

/**
 * Sanitize calendar name to prevent JXA injection attacks
 * Only allows alphanumeric characters, spaces, hyphens, apostrophes, and underscores
 * 
 * @param calendarName - The calendar name to sanitize
 * @returns Sanitized calendar name
 * @throws Error if calendar name contains invalid characters or exceeds length limit
 */
export function sanitizeCalendarName(calendarName: string): string {
  // Check length limit
  if (calendarName.length > MAX_CALENDAR_NAME_LENGTH) {
    throw new Error(
      `Calendar name too long (max ${MAX_CALENDAR_NAME_LENGTH} characters, got ${calendarName.length})`
    );
  }

  // Character whitelist: alphanumeric, space, hyphen, apostrophe, underscore
  // This prevents injection via quotes, semicolons, backslashes, control characters
  const validPattern = /^[a-zA-Z0-9 \-'_]+$/;
  
  if (!validPattern.test(calendarName)) {
    throw new Error(
      `Invalid characters in calendar name. Only alphanumeric characters, spaces, hyphens, apostrophes, and underscores are allowed. Got: "${calendarName}"`
    );
  }

  return calendarName;
}

/**
 * Generate JXA script for querying Calendar.app
 */
export function generateJXAScript(params: QueryParams): string {
  const now = new Date();
  const filterDate = getFilterDate(params.timeRange, now);

  // Sanitize calendar name if provided to prevent injection
  const sanitizedCalendarName = params.calendarName
    ? sanitizeCalendarName(params.calendarName)
    : undefined;

  // Access all calendars or specific calendar
  const calendarAccess = sanitizedCalendarName
    ? `app.calendars.byName("${sanitizedCalendarName}")`
    : 'app.calendars';

  return `
    const app = Application("Calendar");
    const calendars = ${calendarAccess};
    const allEvents = [];

    // Get events from calendar(s)
    ${sanitizedCalendarName ? `
      const events = calendars.events();
      allEvents.push(...events);
    ` : `
      for (let i = 0; i < calendars.length; i++) {
        const cal = calendars[i];
        const events = cal.events();
        allEvents.push(...events);
      }
    `}

    // Filter by date
    const filterDate = new Date("${filterDate.toISOString()}");
    const filtered = allEvents.filter(e => {
      const startDate = e.startDate();
      return startDate >= filterDate;
    });

    // Format results
    JSON.stringify(filtered.map(e => ({
      summary: e.summary(),
      startDate: e.startDate().toISOString(),
      endDate: e.endDate().toISOString(),
      location: e.location ? e.location() : undefined
    })));
  `.trim();
}

/**
 * Get filter date based on time range
 */
export function getFilterDate(timeRange: string, now: Date): Date {
  const date = new Date(now);
  date.setHours(0, 0, 0, 0); // Start of day

  switch (timeRange) {
    case 'today':
      return date;

    case 'this_week': {
      // Get start of week (Sunday)
      const dayOfWeek = date.getDay();
      date.setDate(date.getDate() - dayOfWeek);
      return date;
    }

    case 'this_month':
      // Start of month
      date.setDate(1);
      return date;

    case 'all':
      // Far past date (show all events)
      return new Date(1900, 0, 1);

    default:
      throw new Error(`Invalid time range: ${timeRange}`);
  }
}
