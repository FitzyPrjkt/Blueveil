// Shared live-test clock for the PostgreSQL suite.
package postgres

import "time"

var pgClock = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
