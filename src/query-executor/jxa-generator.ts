/**
 * JXA script generation for Calendar.app queries
 */

import { QueryParams } from './types.js';

/**
 * Generate JXA script for querying Calendar.app
 */
export function generateJXAScript(params: QueryParams): string {
  const now = new Date();
  const filterDate = getFilterDate(params.timeRange, now);

  // Access all calendars or specific calendar
  const calendarAccess = params.calendarName
    ? `app.calendars.byName("${params.calendarName}")`
    : 'app.calendars';

  return `
    const app = Application("Calendar");
    const calendars = ${calendarAccess};
    const allEvents = [];

    // Get events from calendar(s)
    ${params.calendarName ? `
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
