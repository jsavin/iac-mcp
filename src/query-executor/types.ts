/**
 * Type definitions for query executor
 */

/**
 * Query parameters for Calendar.app queries
 */
export interface QueryParams {
  /** Target application (e.g., "Calendar") */
  app: string;
  /** Time range for filtering events */
  timeRange: 'today' | 'this_week' | 'this_month' | 'all';
  /** Optional calendar name to filter by specific calendar */
  calendarName?: string;
}

/**
 * Calendar event structure returned from queries
 */
export interface CalendarEvent {
  /** Event title/summary */
  summary: string;
  /** Event start date in ISO 8601 format */
  startDate: string;
  /** Event end date in ISO 8601 format */
  endDate: string;
  /** Optional event location */
  location?: string;
  /** Optional event notes/description */
  notes?: string;
  /** Optional event URL */
  url?: string;
  /** Whether event is all-day */
  allday?: boolean;
  /** Event status */
  status?: string;
}
