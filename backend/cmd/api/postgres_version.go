// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// minPostgresVersionNum is the oldest PostgreSQL server the API runs against, as PostgreSQL reports it
// in server_version_num: 170000 is PostgreSQL 17.0. Stackweaver relies on PostgreSQL 17 features, and
// the bundled database already runs 17.
const minPostgresVersionNum = 170000

// checkPostgresVersion reads the server's server_version_num through query and returns an error when
// the server is older than PostgreSQL 17 or its version cannot be read, so the API refuses to start
// instead of failing later on a missing feature.
func checkPostgresVersion(query func() (string, error)) error {
	raw, err := query()
	if err != nil {
		return fmt.Errorf("reading the PostgreSQL server version: %w", err)
	}
	num, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("reading the PostgreSQL server version: unexpected server_version_num %q", raw)
	}
	if num < minPostgresVersionNum {
		return fmt.Errorf("stackweaver requires PostgreSQL 17 or later; the database server is PostgreSQL %d.%d (server_version_num %d)",
			num/10000, num%10000, num)
	}
	return nil
}
