// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckPostgresVersion(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		err     error
		wantErr string
	}{
		{name: "17.0", raw: "170000"},
		{name: "17.4", raw: "170004"},
		{name: "18.1", raw: "180001"},
		{name: "surrounding whitespace", raw: " 170002\n"},
		{name: "16.6", raw: "160006", wantErr: "requires PostgreSQL 17 or later; the database server is PostgreSQL 16.6"},
		{name: "13.0", raw: "130000", wantErr: "PostgreSQL 13.0"},
		{name: "not a number", raw: "seventeen", wantErr: "unexpected server_version_num"},
		{name: "query fails", err: errors.New("connection refused"), wantErr: "reading the PostgreSQL server version: connection refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPostgresVersion(func() (string, error) { return tc.raw, tc.err })
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkPostgresVersion(%q) = %v, want nil", tc.raw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkPostgresVersion(%q) = %v, want an error containing %q", tc.raw, err, tc.wantErr)
			}
		})
	}
}
