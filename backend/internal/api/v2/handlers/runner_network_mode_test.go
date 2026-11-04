// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// A runner carries the driver and network mode its launcher reported, read-only (#933, D4, D5,
// AC22): the pool page shows them from this resource.
func TestBuildRunnerResponse_DriverAndNetworkMode(t *testing.T) {
	r := &models.Runner{ID: uuid.New(), Name: "l", Driver: "container", NetworkMode: "egress-only", RegisteredAt: time.Now()}
	attrs := buildRunnerResponse(r).Attributes
	if attrs.Driver != "container" || attrs.NetworkMode != "egress-only" {
		t.Errorf("driver %q network mode %q, want container and egress-only", attrs.Driver, attrs.NetworkMode)
	}
}

// The rest of a launcher's deployment-level settings read back on its runner the same way (#933,
// D0, D15): hosted.strict, the cache verification mode and the node cache.
func TestBuildRunnerResponse_LauncherSettings(t *testing.T) {
	r := &models.Runner{
		ID: uuid.New(), Name: "l", RegisteredAt: time.Now(),
		HostedStrict: true, CacheVerification: "offline", LocalCache: true, LocalCacheSizeLimit: 5 << 30,
	}
	a := buildRunnerResponse(r).Attributes
	if !a.HostedStrict || a.CacheVerification != "offline" || !a.LocalCache || a.LocalCacheSizeLimit != 5<<30 {
		t.Errorf("attributes = %+v", a)
	}
}
