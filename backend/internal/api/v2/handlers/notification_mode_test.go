// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"strings"
	"testing"
)

// #829 D3: the notification mode fails closed. Unset or empty means email in every mode, and
// return_code is refused in production because it hands auth codes to anonymous callers.
func TestParseNotificationMode(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		release bool
		want    NotificationMode
		wantErr bool
	}{
		{name: "unset in debug means email", raw: "", release: false, want: NotificationModeEmail},
		{name: "unset in release means email", raw: "", release: true, want: NotificationModeEmail},
		{name: "whitespace only means email", raw: "  ", release: true, want: NotificationModeEmail},
		{name: "email in debug", raw: "email", release: false, want: NotificationModeEmail},
		{name: "email in release", raw: "email", release: true, want: NotificationModeEmail},
		{name: "return_code in debug", raw: "return_code", release: false, want: NotificationModeReturnCode},
		{name: "return_code in release is refused", raw: "return_code", release: true, wantErr: true},
		{name: "unknown value in debug is refused", raw: "e-mail", release: false, wantErr: true},
		{name: "unknown value in release is refused", raw: "returncode", release: true, wantErr: true},
		{name: "wrong case is refused", raw: "Email", release: false, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNotificationMode(tt.raw, tt.release)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseNotificationMode(%q, %v) = %q, want an error", tt.raw, tt.release, got)
				}
				if !strings.Contains(err.Error(), "STACKWEAVER_NOTIFICATION_MODE") {
					t.Errorf("error must name the variable: %v", err)
				}
				if !strings.Contains(err.Error(), `"`+tt.raw+`"`) {
					t.Errorf("error must quote the value %q: %v", tt.raw, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNotificationMode(%q, %v) returned error: %v", tt.raw, tt.release, err)
			}
			if got != tt.want {
				t.Errorf("ParseNotificationMode(%q, %v) = %q, want %q", tt.raw, tt.release, got, tt.want)
			}
		})
	}
}
