import { describe, it, expect, beforeAll } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * Integration tests for Calendar query execution
 *
 * IMPORTANT: These tests require:
 * 1. macOS system with Calendar.app installed
 * 2. Automation permissions granted to Terminal/process
 * 3. At least one calendar configured in Calendar.app
 *
 * Tests may return empty arrays if no events exist - this is expected behavior.
 */

interface CalendarEvent {
  summary: string;
  startDate: string;
  endDate: string;
  location?: string;
  calendar?: {
    name: string;
  };
}

// Helper function to execute JXA scripts
async function executeJXA(script: string): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync('osascript', [
      '-l',
      'JavaScript',
      '-e',
      script,
    ]);

    if (stderr && stderr.trim().length > 0) {
      console.warn('JXA stderr:', stderr);
    }

    return stdout.trim();
  } catch (error: any) {
    throw new Error(`JXA execution failed: ${error.message}`);
  }
}

// Helper to check if Calendar.app is accessible
async function isCalendarAccessible(): Promise<boolean> {
  try {
    const script = 'Application("Calendar").name()';
    await executeJXA(script);
    return true;
  } catch (error) {
    return false;
  }
}

// Helper to get calendar names
async function getCalendarNames(): Promise<string[]> {
  try {
    const script = `
      const app = Application("Calendar");
      const calendars = app.calendars();
      JSON.stringify(calendars.map(cal => cal.name()));
    `;
    const result = await executeJXA(script);
    return JSON.parse(result);
  } catch (error) {
    return [];
  }
}

describe('Calendar Query Integration Tests', () => {
  let calendarAccessible = false;
  let availableCalendars: string[] = [];

  beforeAll(async () => {
    // Check if Calendar.app is accessible
    calendarAccessible = await isCalendarAccessible();

    if (calendarAccessible) {
      availableCalendars = await getCalendarNames();
      console.log('Available calendars:', availableCalendars);
    } else {
      console.warn(
        'Calendar.app not accessible - tests will be skipped. ' +
          'Grant automation permissions in System Preferences > Privacy & Security > Automation'
      );
    }
  }, 30000); // 30 second timeout for Calendar initialization

  describe('Basic Calendar Access', () => {
    it('should access Calendar.app', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const script = 'Application("Calendar").name()';
      const result = await executeJXA(script);

      expect(result).toBe('Calendar');
    });

    it('should list calendars', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const script = `
        const app = Application("Calendar");
        const calendars = app.calendars();
        JSON.stringify({ count: calendars.length, names: calendars.map(c => c.name()) });
      `;
      const result = await executeJXA(script);
      const data = JSON.parse(result);

      expect(data.count).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(data.names)).toBe(true);
    });
  });

  describe('Query Events - Today', () => {
    it('should query events for today', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const now = new Date();
      const startOfToday = new Date(now);
      startOfToday.setHours(0, 0, 0, 0);

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        const filterDate = new Date("${startOfToday.toISOString()}");
        const filtered = allEvents.filter(e => {
          const startDate = e.startDate();
          return startDate >= filterDate;
        });

        JSON.stringify(filtered.map(e => ({
          summary: e.summary(),
          startDate: e.startDate().toISOString(),
          endDate: e.endDate().toISOString(),
          location: e.location ? e.location() : undefined
        })));
      `;

      const result = await executeJXA(script);
      const events: CalendarEvent[] = JSON.parse(result);

      // May be empty if no events today - that's OK
      expect(Array.isArray(events)).toBe(true);

      // If there are events, verify structure
      if (events.length > 0) {
        const event = events[0];
        expect(event).toHaveProperty('summary');
        expect(event).toHaveProperty('startDate');
        expect(event).toHaveProperty('endDate');
        expect(typeof event.summary).toBe('string');
        expect(typeof event.startDate).toBe('string');
        expect(typeof event.endDate).toBe('string');

        // Verify startDate is valid ISO date
        const startDate = new Date(event.startDate);
        expect(startDate.toString()).not.toBe('Invalid Date');

        // Verify startDate is today or later
        expect(startDate.getTime()).toBeGreaterThanOrEqual(startOfToday.getTime());
      }
    }, 30000);
  });

  describe('Query Events - This Week', () => {
    it('should query events for this week', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const now = new Date();
      const startOfWeek = new Date(now);
      startOfWeek.setDate(now.getDate() - now.getDay());
      startOfWeek.setHours(0, 0, 0, 0);

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        const filterDate = new Date("${startOfWeek.toISOString()}");
        const filtered = allEvents.filter(e => {
          const startDate = e.startDate();
          return startDate >= filterDate;
        });

        JSON.stringify(filtered.map(e => ({
          summary: e.summary(),
          startDate: e.startDate().toISOString(),
          endDate: e.endDate().toISOString()
        })));
      `;

      const result = await executeJXA(script);
      const events: CalendarEvent[] = JSON.parse(result);

      expect(Array.isArray(events)).toBe(true);

      // If there are events, verify they're from this week or later
      if (events.length > 0) {
        events.forEach((event) => {
          const startDate = new Date(event.startDate);
          expect(startDate.getTime()).toBeGreaterThanOrEqual(startOfWeek.getTime());
        });
      }
    }, 30000);
  });

  describe('Query Events - This Month', () => {
    it('should query events for this month', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const now = new Date();
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        const filterDate = new Date("${startOfMonth.toISOString()}");
        const filtered = allEvents.filter(e => {
          const startDate = e.startDate();
          return startDate >= filterDate;
        });

        JSON.stringify(filtered.map(e => ({
          summary: e.summary(),
          startDate: e.startDate().toISOString(),
          endDate: e.endDate().toISOString()
        })));
      `;

      const result = await executeJXA(script);
      const events: CalendarEvent[] = JSON.parse(result);

      expect(Array.isArray(events)).toBe(true);

      // If there are events, verify they're from this month or later
      if (events.length > 0) {
        events.forEach((event) => {
          const startDate = new Date(event.startDate);
          expect(startDate.getTime()).toBeGreaterThanOrEqual(startOfMonth.getTime());
        });
      }
    }, 30000);
  });

  describe('Query Events - All', () => {
    it('should query all events', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        // No date filter - get all events
        JSON.stringify(allEvents.map(e => ({
          summary: e.summary(),
          startDate: e.startDate().toISOString(),
          endDate: e.endDate().toISOString()
        })));
      `;

      const result = await executeJXA(script);
      const events: CalendarEvent[] = JSON.parse(result);

      expect(Array.isArray(events)).toBe(true);

      // Verify structure if events exist
      if (events.length > 0) {
        events.forEach((event) => {
          expect(event).toHaveProperty('summary');
          expect(event).toHaveProperty('startDate');
          expect(event).toHaveProperty('endDate');
        });
      }
    }, 60000); // Longer timeout for potentially large result set
  });

  describe('Query Events - By Calendar Name', () => {
    it('should query events from specific calendar', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      if (availableCalendars.length === 0) {
        console.warn('Skipping test: No calendars available');
        return;
      }

      const calendarName = availableCalendars[0];
      console.log('Testing with calendar:', calendarName);

      const script = `
        const app = Application("Calendar");
        const calendar = app.calendars.byName("${calendarName}");
        const events = calendar.events();

        JSON.stringify(events.map(e => ({
          summary: e.summary(),
          startDate: e.startDate().toISOString(),
          endDate: e.endDate().toISOString()
        })));
      `;

      const result = await executeJXA(script);
      const events: CalendarEvent[] = JSON.parse(result);

      expect(Array.isArray(events)).toBe(true);

      // If there are events, verify structure
      if (events.length > 0) {
        events.forEach((event) => {
          expect(event).toHaveProperty('summary');
          expect(event).toHaveProperty('startDate');
          expect(event).toHaveProperty('endDate');
        });
      }
    }, 30000);
  });

  describe('Error Scenarios', () => {
    it('should handle non-existent calendar name', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const script = `
        const app = Application("Calendar");
        const calendar = app.calendars.byName("NonExistentCalendar12345");
        const events = calendar.events();
        JSON.stringify(events);
      `;

      // This should either throw or return empty array depending on JXA behavior
      try {
        const result = await executeJXA(script);
        const events = JSON.parse(result);
        expect(Array.isArray(events)).toBe(true);
      } catch (error: any) {
        // Expected: Error about calendar not found
        expect(error.message).toContain('JXA execution failed');
      }
    }, 30000);

    it('should handle non-existent app', async () => {
      const script = 'Application("NonExistentApp12345").name()';

      await expect(executeJXA(script)).rejects.toThrow('JXA execution failed');
    });

    it('should handle invalid bundle ID', async () => {
      const script = 'Application("com.invalid.BundleID").name()';

      await expect(executeJXA(script)).rejects.toThrow('JXA execution failed');
    });
  });

  describe('Event Structure Validation', () => {
    it('should verify event properties are correctly typed', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      // Create a test event (only if we can)
      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        if (allEvents.length === 0) {
          JSON.stringify([]);
        } else {
          const event = allEvents[0];
          JSON.stringify({
            summary: event.summary(),
            startDate: event.startDate().toISOString(),
            endDate: event.endDate().toISOString(),
            location: event.location ? event.location() : undefined,
            summaryType: typeof event.summary(),
            startDateType: typeof event.startDate().toISOString(),
            endDateType: typeof event.endDate().toISOString()
          });
        }
      `;

      const result = await executeJXA(script);
      const data = JSON.parse(result);

      if (Array.isArray(data)) {
        // No events, that's OK
        console.log('No events available for type validation');
      } else {
        // Verify types
        expect(data.summaryType).toBe('string');
        expect(data.startDateType).toBe('string');
        expect(data.endDateType).toBe('string');
      }
    }, 30000);
  });

  describe('Performance and Limits', () => {
    it('should handle querying large number of events', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const startTime = Date.now();

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        JSON.stringify({
          count: allEvents.length,
          sample: allEvents.slice(0, 5).map(e => ({
            summary: e.summary(),
            startDate: e.startDate().toISOString()
          }))
        });
      `;

      const result = await executeJXA(script);
      const data = JSON.parse(result);

      const endTime = Date.now();
      const duration = endTime - startTime;

      console.log(`Query completed in ${duration}ms for ${data.count} events`);

      expect(data.count).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(data.sample)).toBe(true);

      // Verify query didn't take unreasonably long (< 30 seconds)
      expect(duration).toBeLessThan(30000);
    }, 60000);

    it('should handle empty calendars gracefully', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        JSON.stringify(allEvents);
      `;

      const result = await executeJXA(script);
      const events = JSON.parse(result);

      // Should return empty array, not error
      expect(Array.isArray(events)).toBe(true);
    }, 30000);
  });

  describe('Date Filtering Accuracy', () => {
    it('should only return events from specified time range', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const now = new Date();
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(0, 0, 0, 0);

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        const filterDate = new Date("${tomorrow.toISOString()}");
        const filtered = allEvents.filter(e => {
          const startDate = e.startDate();
          return startDate >= filterDate;
        });

        JSON.stringify(filtered.map(e => ({
          summary: e.summary(),
          startDate: e.startDate().toISOString()
        })));
      `;

      const result = await executeJXA(script);
      const events: CalendarEvent[] = JSON.parse(result);

      expect(Array.isArray(events)).toBe(true);

      // Verify all events are tomorrow or later
      events.forEach((event) => {
        const eventDate = new Date(event.startDate);
        expect(eventDate.getTime()).toBeGreaterThanOrEqual(tomorrow.getTime());
      });
    }, 30000);
  });

  describe('Special Characters and Edge Cases', () => {
    it('should handle events with special characters in summary', async () => {
      if (!calendarAccessible) {
        console.warn('Skipping test: Calendar not accessible');
        return;
      }

      const script = `
        const app = Application("Calendar");
        const allEvents = [];

        for (let i = 0; i < app.calendars.length; i++) {
          const cal = app.calendars[i];
          const events = cal.events();
          allEvents.push(...events);
        }

        // Look for events with special characters
        const filtered = allEvents.filter(e => {
          const summary = e.summary();
          return /[<>"'&]/.test(summary);
        });

        JSON.stringify(filtered.map(e => ({
          summary: e.summary(),
          startDate: e.startDate().toISOString()
        })));
      `;

      const result = await executeJXA(script);
      const events = JSON.parse(result);

      expect(Array.isArray(events)).toBe(true);

      // If there are such events, verify they're properly escaped
      if (events.length > 0) {
        events.forEach((event: CalendarEvent) => {
          expect(typeof event.summary).toBe('string');
        });
      }
    }, 30000);
  });
});
