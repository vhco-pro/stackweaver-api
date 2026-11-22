// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
)

const (
	maxPlaybookSnapshotBytes  = 32 << 20
	oversizedPlaybookSnapshot = "The playbook snapshot exceeds 32 MiB. Reduce the repository content captured, refresh the snapshot, and start a new run."
)

// Sealing and opening each archive hold several buffers. Share one slot across
// playbook uploads, downloads and optional artifact hints in this API process.
var playbookSnapshotSlot = make(chan struct{}, 1)

func tryPlaybookSnapshotSlot() bool {
	select {
	case playbookSnapshotSlot <- struct{}{}:
		return true
	default:
		return false
	}
}

func releasePlaybookSnapshotSlot() { <-playbookSnapshotSlot }

func writePlaybookSnapshotBusy(c *gin.Context) {
	c.Header("Retry-After", "1")
	jsonapi.WriteError(c, http.StatusServiceUnavailable, "Service Unavailable", "Another playbook snapshot is being processed. Retry shortly.")
}
