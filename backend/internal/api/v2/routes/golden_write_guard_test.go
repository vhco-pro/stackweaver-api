// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"strings"
	"testing"
)

// TestGoldenWriteSettingsGuard pins the check that stands between the write recorder and the
// main stack (#869, AC14).
//
// The write recorder performs real, successful writes. A router built on the default queue and
// storage settings talks to Redis logical database 0 and the `stackweaver` bucket, which are the
// running dev stack's own: a job enqueued there is picked up and executed by its orchestrator.
// So the recorder builds a router only on a worktree slot's resources, and this is the test that
// the refusal holds for every way the settings can be wrong. It is given settings directly and
// touches no service, so it runs wherever the harness runs.
func TestGoldenWriteSettingsGuard(t *testing.T) {
	ok := writeSettings{RedisDB: "3", Bucket: "sw-wt-3"}
	if err := ok.check(); err != nil {
		t.Fatalf("a slot's own Redis database and bucket must be accepted, got: %v", err)
	}

	refused := []struct {
		name     string
		settings writeSettings
		want     string // a fragment the error must carry, so the message names what is wrong
	}{
		{"the main stack's Redis database", writeSettings{RedisDB: "0", Bucket: "sw-wt-3"}, "logical database 0"},
		{"an empty Redis database, which the queue would read as 0", writeSettings{RedisDB: "", Bucket: "sw-wt-3"}, "not a slot number"},
		{"a Redis database that is not a number", writeSettings{RedisDB: "three", Bucket: "sw-wt-3"}, "not a slot number"},
		{"a negative Redis database", writeSettings{RedisDB: "-1", Bucket: "sw-wt-3"}, "not a slot number"},
		{"a Redis database with a sign or spaces", writeSettings{RedisDB: " 3", Bucket: "sw-wt-3"}, "not a slot number"},
		{"the main stack's bucket", writeSettings{RedisDB: "3", Bucket: "stackweaver"}, "stackweaver"},
		{"an empty bucket, which storage would read as the main stack's", writeSettings{RedisDB: "3", Bucket: ""}, "sw-wt-3"},
		{"another slot's bucket", writeSettings{RedisDB: "3", Bucket: "sw-wt-4"}, "sw-wt-3"},
		{"a bucket that only starts like the slot's", writeSettings{RedisDB: "3", Bucket: "sw-wt-30"}, "sw-wt-3"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.settings.check()
			if err == nil {
				t.Fatalf("settings %+v were accepted; the write recorder would have built a router on them", tc.settings)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
