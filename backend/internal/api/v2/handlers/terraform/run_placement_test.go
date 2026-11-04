// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

func TestFormatRunPlacement(t *testing.T) {
	res := formatRunPlacement(&models.Run{ID: "run-abc", Attempt: 2, Placement: models.JobPlacement{Driver: "container", Node: "n1"}})
	if res.Type != "placements" || res.ID != "run-abc" || res.Attributes.Attempt != 2 || res.Attributes.Driver != "container" || res.Attributes.Node != "n1" {
		t.Fatalf("placement resource = %+v", res)
	}
}
