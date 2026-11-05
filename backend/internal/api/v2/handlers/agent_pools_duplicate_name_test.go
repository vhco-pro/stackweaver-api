// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A pool name taken in the organization answers 409 on create and on rename, through the same
// routes the TFE provider calls, also when the name is the organization's hidden hosted pool's,
// which the name lookup does not see but the unique index does.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAgentPool_DuplicateName

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestAgentPool_DuplicateNameAnswers409(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	hosted := models.NewHostedPool(f.orgA.ID)
	other := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "taken-" + f.sfx, OrganizationScoped: true}
	mine := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "mine-" + f.sfx, OrganizationScoped: true}
	for _, p := range []*models.AgentPool{hosted, other, mine} {
		if err := f.db.Create(p).Error; err != nil {
			t.Fatal(err)
		}
		id := p.ID
		t.Cleanup(func() { f.db.Where("id = ?", id).Delete(&models.AgentPool{}) })
	}
	t.Cleanup(func() {
		f.db.Where("organization_id = ? AND kind <> ?", f.orgA.ID, models.AgentPoolKindHosted).Delete(&models.AgentPool{})
	})
	poolRepo := repository.NewAgentPoolRepository(f.db)
	h := NewAgentPoolHandlerV2(poolRepo, repository.NewRunnerRepository(f.db), repository.NewOrganizationRepository(f.db), f.authSvc,
		rbac.NewServiceWithTeams(repository.NewOrganizationRepository(f.db), repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.POST("/api/v2/organizations/:name/agent-pools", h.Create)
	r.PATCH("/api/v2/agent-pools/:id", h.Update)

	body := func(name string) string {
		return `{"data":{"type":"agent-pools","attributes":{"name":"` + name + `"}}}`
	}
	for _, name := range []string{hosted.Name, other.Name} {
		rec := platformAdminCall(t, r, http.MethodPost, "/api/v2/organizations/"+f.orgA.Name+"/agent-pools", browserAs(f.owner), body(name))
		if rec.Code != http.StatusConflict {
			t.Errorf("create a pool named %q = %d, want 409 (%s)", name, rec.Code, rec.Body.String())
		}
		rec = platformAdminCall(t, r, http.MethodPatch, "/api/v2/agent-pools/"+mine.ID.String(), browserAs(f.owner), body(name))
		if rec.Code != http.StatusConflict {
			t.Errorf("rename a pool to %q = %d, want 409 (%s)", name, rec.Code, rec.Body.String())
		}
	}
	var kept models.AgentPool
	if err := f.db.First(&kept, "id = ?", mine.ID).Error; err != nil || kept.Name != mine.Name {
		t.Errorf("the refused rename changed the pool: %+v, %v", kept, err)
	}
}
