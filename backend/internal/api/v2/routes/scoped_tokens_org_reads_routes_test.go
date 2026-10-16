// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The activity, analytics and registry protocol reads, through the router the server mounts, judge a
// team or project token the way every other read does, and hold any organization token to the
// organization it is bound to.

//go:build integration

package routes_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// teamKeyOfAMember mints an ordinary team-scoped key whose owner belongs to a team with write on
// wsInP, so the key acts as that team.
func teamKeyOfAMember(t *testing.T, f *scopedTokensFixture) string {
	t.Helper()
	s := uuid.NewString()[:8]
	member := models.User{ID: uuid.New(), ZitadelSubject: "scoped-m-" + s, Email: "scoped-m-" + s + "@test.local"}
	team := models.Team{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-m-" + s}
	level := "write"
	for _, row := range []any{
		&member, &team,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: f.org.ID, UserID: member.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: member.ID},
		&models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: team.ID, WorkspaceID: f.wsInP.ID, Access: &level},
	} {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	_, token, err := f.keys.CreateAPIKey(member.ID, "scoped-m-"+s, []string{"team:" + team.ID.String() + ":write"}, nil)
	if err != nil {
		t.Fatalf("mint a team-scoped key: %v", err)
	}
	return token
}

// otherOrgToken mints an organization token, owned by the harness user, bound to a second
// organization the harness user also owns.
func otherOrgToken(t *testing.T, f *scopedTokensFixture) string {
	t.Helper()
	s := uuid.NewString()[:8]
	other := models.Organization{ID: uuid.New(), Name: "scoped-other-" + s}
	owners := models.Team{ID: uuid.New(), OrganizationID: other.ID, Name: "owners"}
	for _, row := range []any{&other, &owners, &models.TeamMember{TeamID: owners.ID, UserID: f.owner.ID}} {
		if err := f.h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	_, token, err := f.keys.CreateAPIKey(f.owner.ID, "scoped-other-"+s, []string{"org:" + other.ID.String() + ":admin"}, nil)
	if err != nil {
		t.Fatalf("mint a key bound to %s: %v", other.Name, err)
	}
	return token
}

func TestScopedTokens_ActivityAnalyticsAndRegistry(t *testing.T) {
	f := setupScopedTokens(t)
	module := models.Module{ID: uuid.New(), OrganizationID: f.org.ID, Name: "scoped-mod-" + uuid.NewString()[:8], Provider: "aws"}
	if err := f.h.db.Create(&module).Error; err != nil {
		t.Fatalf("seed module: %v", err)
	}
	if err := f.h.db.Create(&models.ModuleVersion{ModuleID: module.ID, Version: "1.0.0", PublishedAt: time.Now()}).Error; err != nil {
		t.Fatalf("seed module version: %v", err)
	}
	activities := "/api/v2/activities?organization_id=" + f.org.ID.String()
	analytics := "/api/v2/organizations/" + f.org.Name + "/analytics"
	registry := fmt.Sprintf("/v1/modules/%s/%s/%s", f.org.Name, module.Name, module.Provider)

	teamKey := teamKeyOfAMember(t, f)
	t.Run("a team-scoped key of a team member reads the organization's activity", func(t *testing.T) {
		readStatus(t, f, teamKey, activities, http.StatusOK)
	})
	t.Run("a team-scoped key of a team member reads the organization's analytics", func(t *testing.T) {
		readStatus(t, f, teamKey, analytics, http.StatusOK)
	})
	t.Run("a team-scoped key of a team member reads a private module", func(t *testing.T) {
		readStatus(t, f, teamKey, registry, http.StatusOK)
	})

	foreign := otherOrgToken(t, f)
	t.Run("a token bound to another organization cannot read the organization's activity", func(t *testing.T) {
		readStatus(t, f, foreign, activities, http.StatusForbidden)
	})
	t.Run("a token bound to another organization cannot read a private module", func(t *testing.T) {
		readStatus(t, f, foreign, registry, http.StatusForbidden)
	})

	t.Run("the owner's user token reads all three", func(t *testing.T) {
		readStatus(t, f, f.h.token, activities, http.StatusOK)
		readStatus(t, f, f.h.token, analytics, http.StatusOK)
		readStatus(t, f, f.h.token, registry, http.StatusOK)
	})
}
