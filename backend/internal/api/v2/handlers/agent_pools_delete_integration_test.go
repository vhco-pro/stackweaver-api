// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for an agent pool delete that loses a race with another delete of the same
// pool (#856). It uses deleteWhileRowLocked from runners_delete_integration_test.go.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAgentPoolDelete_

//go:build integration

package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// AgentPoolRepository.Delete reports a delete that removed no row as gorm.ErrRecordNotFound, like
// the launcher delete. The losing request answers 404, as the lookup before it would have.
func TestAgentPoolDelete_LosingConcurrentDeleteIsNotFound(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "pdel-" + f.sfx, OrganizationScoped: true}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{}) })

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewAgentPoolHandlerV2(repository.NewAgentPoolRepository(f.db), repository.NewRunnerRepository(f.db), orgs, f.authSvc,
		rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.DELETE("/api/v2/agent-pools/:id", h.Delete)

	rec := deleteWhileRowLocked(t, f.db, r, "/api/v2/agent-pools/"+pool.ID.String(), browserAs(f.owner),
		func(tx *gorm.DB) error { return tx.Delete(&models.AgentPool{}, "id = ?", pool.ID).Error })
	if rec.Code != http.StatusNotFound {
		t.Fatalf("losing delete = %d %s, want 404", rec.Code, rec.Body.String())
	}
}

func TestAgentPoolDelete_LegacyRunnerPreservesRefusal(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "legacy-pdel-" + f.sfx}
	if err := f.db.Create(pool).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", pool.ID).Delete(&models.AgentPool{}) })
	runner := &models.Runner{
		ID: uuid.New(), OrganizationID: &f.orgA.ID, AgentPoolID: &pool.ID,
		Name: "legacy-pdel-" + f.sfx, Status: models.RunnerStatusOffline,
	}
	if err := f.db.Create(runner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", runner.ID).Delete(&models.Runner{}) })

	orgs := repository.NewOrganizationRepository(f.db)
	h := NewAgentPoolHandlerV2(repository.NewAgentPoolRepository(f.db), repository.NewRunnerRepository(f.db), orgs, f.authSvc,
		rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	router := platformAdminRouter()
	router.DELETE("/api/v2/agent-pools/:id", h.Delete)

	path := "/api/v2/agent-pools/" + pool.ID.String()
	recorder := platformAdminCall(t, router, http.MethodDelete, path, browserAs(f.owner), "")
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "Failed to delete agent pool") {
		t.Fatalf("delete pool with legacy runner = %d %s, want existing refusal", recorder.Code, recorder.Body.String())
	}
	if err := f.db.Where("id = ?", runner.ID).Delete(&models.Runner{}).Error; err != nil {
		t.Fatal(err)
	}
	recorder = platformAdminCall(t, router, http.MethodDelete, path, browserAs(f.owner), "")
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("delete empty pool = %d %s, want 204", recorder.Code, recorder.Body.String())
	}
	recorder = platformAdminCall(t, router, http.MethodDelete, path, browserAs(f.owner), "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("delete removed pool = %d %s, want 404", recorder.Code, recorder.Body.String())
	}
}
