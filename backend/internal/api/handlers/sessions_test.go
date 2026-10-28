// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
)

func TestSessionAttributes_ExpirationDate(t *testing.T) {
	created := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	expires := created.Add(12 * time.Hour)

	tests := []struct {
		name    string
		expires time.Time
		want    string
	}{
		{name: "a session with a lifetime reports when it expires", expires: expires, want: `"expiration-date":"2026-10-27T21:00:00Z"`},
		{name: "a session without a lifetime has no expiration-date", expires: time.Time{}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SessionWithCurrent{Session: &sessions.Session{ID: "s", CreationDate: created, ExpirationDate: tt.expires}}
			body, err := json.Marshal(sessionAttributes(s))
			if err != nil {
				t.Fatal(err)
			}
			got := string(body)
			if tt.want == "" {
				if strings.Contains(got, "expiration-date") {
					t.Errorf("attributes = %s, want no expiration-date", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("attributes = %s, want %s", got, tt.want)
			}
		})
	}
}
