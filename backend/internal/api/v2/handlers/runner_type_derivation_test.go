// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// TestDeriveRunnerType pins the capability → type mapping used by both the create and the
// re-register paths. Re-registration previously skipped this entirely, so a row kept whatever
// type it was first created with: a runner whose capabilities changed (or one created under an
// older enum value) reported Online and heartbeated while FindAvailableRunner never matched it,
// leaving every job pending with no error anywhere.
func TestDeriveRunnerType(t *testing.T) {
	cases := []struct {
		name          string
		tofu, ansible string
		want          models.RunnerType
	}{
		{"tofu only", "1.12.5", "", models.RunnerTypeTofu},
		{"ansible only", "", "2.16.0", models.RunnerTypeAnsible},
		{"both", "1.12.5", "2.16.0", models.RunnerTypeCombined},
		{"neither", "", "", models.RunnerTypeCombined},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deriveRunnerType(c.tofu, c.ansible); got != c.want {
				t.Errorf("deriveRunnerType(%q, %q) = %q, want %q", c.tofu, c.ansible, got, c.want)
			}
		})
	}
}

// TestRunnerTypeRoutability guards the pairing between the derived type and the dispatch
// predicates - the two must agree or runners silently never receive work.
func TestRunnerTypeRoutability(t *testing.T) {
	tofuRunner := &models.Runner{RunnerType: deriveRunnerType("1.12.5", "")}
	if !tofuRunner.CanExecuteTerraform() {
		t.Error("a tofu-only runner must be routable for OpenTofu jobs")
	}
	combined := &models.Runner{RunnerType: deriveRunnerType("1.12.5", "2.16.0")}
	if !combined.CanExecuteTerraform() {
		t.Error("a combined runner must be routable for OpenTofu jobs")
	}
	ansibleOnly := &models.Runner{RunnerType: deriveRunnerType("", "2.16.0")}
	if ansibleOnly.CanExecuteTerraform() {
		t.Error("an ansible-only runner must NOT be routable for OpenTofu jobs")
	}
}
