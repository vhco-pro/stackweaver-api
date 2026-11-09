// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import "time"

// FormatTime writes t as the API writes every timestamp attribute: the UTC instant in RFC 3339,
// whole seconds, ending in Z ("2026-10-17T18:04:05Z").
//
// It is the only way a handler formats a timestamp (scripts/check-timestamp-formatting.js holds
// that). Go's layout "2006-01-02T15:04:05Z" prints the value's own wall clock followed by a
// literal Z, so in a process outside UTC it names a different instant; and a time.Time attribute
// left to encoding/json carries the loaded offset and sub-second digits. For a UTC value the
// bytes equal the literal-Z layout's, which go-tfe's iso8601 attributes require.
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// FormatTimePtr is FormatTime for an optional timestamp: nil stays nil, so an omitempty or
// nullable attribute keeps its absent or null form.
func FormatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := FormatTime(*t)
	return &s
}
