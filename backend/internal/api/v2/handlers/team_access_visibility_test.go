// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// Pins the read rule Terraform Enterprise documents for both workspace and project
// team access: organization members see access rows for teams they can see, while
// callers who can manage teams see the full set including secret teams.
// Issue #679 - the project List endpoint used to require team-management permission
// outright, while the workspace List endpoint returned every row to any org member.
func TestTeamAccessVisible(t *testing.T) {
	myTeam := uuid.New()
	otherTeam := uuid.New()
	memberOf := map[uuid.UUID]bool{myTeam: true}

	secretMine := models.Team{ID: myTeam, Visibility: "secret"}
	secretTheirs := models.Team{ID: otherTeam, Visibility: "secret"}
	orgVisible := models.Team{ID: otherTeam, Visibility: "organization"}

	tests := []struct {
		name        string
		team        models.Team
		memberOf    map[uuid.UUID]bool
		isTeamAdmin bool
		want        bool
	}{
		{"admin sees a secret team they are not in", secretTheirs, nil, true, true},
		{"admin sees an organization-visible team", orgVisible, nil, true, true},
		{"member sees a secret team they belong to", secretMine, memberOf, false, true},
		{"member does NOT see a secret team they are not in", secretTheirs, memberOf, false, false},
		{"member sees an organization-visible team", orgVisible, memberOf, false, true},
		{"member with no team memberships sees nothing secret", secretTheirs, nil, false, false},

		// Team.Visibility defaults to "secret"; anything unrecognised must fail closed
		// so a legacy or malformed row is never exposed to a non-member.
		{"empty visibility is treated as secret", models.Team{ID: otherTeam}, memberOf, false, false},
		{"unknown visibility is treated as secret", models.Team{ID: otherTeam, Visibility: "public"}, memberOf, false, false},

		// Value handling should not be brittle about case or padding.
		{"visibility matching ignores case and padding", models.Team{ID: otherTeam, Visibility: "  Organization "}, memberOf, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := teamAccessVisible(tt.team, tt.memberOf, tt.isTeamAdmin); got != tt.want {
				t.Errorf("teamAccessVisible(visibility=%q, isTeamAdmin=%v) = %v, want %v",
					tt.team.Visibility, tt.isTeamAdmin, got, tt.want)
			}
		})
	}
}
