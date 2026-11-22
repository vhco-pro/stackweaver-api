// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package main

import (
	"os"
	"testing"

	"github.com/michielvha/stackweaver/core/dbtest"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestCheckPostgresVersionAgainstServer runs the startup check against the real test server, which
// runs PostgreSQL 17 like the bundled database, so the check must accept it. It reads only the server
// version and writes nothing.
func TestCheckPostgresVersionAgainstServer(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("opening the test database: %v", err)
	}
	err = checkPostgresVersion(func() (string, error) {
		var v string
		err := db.Raw("SHOW server_version_num").Scan(&v).Error
		return v, err
	})
	if err != nil {
		t.Fatalf("checkPostgresVersion against the test server: %v", err)
	}
}
