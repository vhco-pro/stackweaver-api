// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The hosted binding on an organization and a project, and on a run's token (#1113, D3; AC-06,
// AC-09): both levels may select it while it is configured, and a run of a hosted workspace that
// resolves it carries it on its job token. The workspace, job template, inventory source and
// inventory cases live beside their handlers, in the terraform and ansible packages.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestHostedBindingSelection

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/michielvha/stackweaver/backend/internal/api/v2/levelrefs"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestHostedBindingSelection_OrganizationProjectAndRunToken(t *testing.T) {
	f := setupOrgVersionFixture(t)
	repository.SetHostedBinding(&repository.HostedBindingConfig{
		Name: "hosted-workload-identity", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity",
		Annotations: map[string]string{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
	})
	t.Cleanup(func() { repository.SetHostedBinding(nil) })
	hosted := models.HostedIdentityBindingID("hosted-workload-identity")
	org := f.createOrg(t, "hbsel-"+f.sfx)

	if code, body := storedAsSentCall(t, f.router, http.MethodPatch, "/api/v2/organizations/"+org.Name, f.creator.ID,
		storedAsSentDocument(t, "organizations", map[string]any{"identity-binding-id": hosted.String()})); code != http.StatusOK {
		t.Fatalf("an organization selecting the hosted binding = %d, want 200 (%s)", code, body)
	}

	var project models.Project
	if err := f.db.Where("organization_id = ?", org.ID).Order("created_at").First(&project).Error; err != nil {
		t.Fatal(err)
	}
	orgRepo, teamRepo, projectRepo := repository.NewOrganizationRepository(f.db), repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)
	projects := NewProjectHandlerV2(projectRepo, orgRepo, teamRepo, repository.NewAgentPoolRepository(f.db), repository.NewTagBindingRepository(f.db),
		auth.NewService(repository.NewUserRepository(f.db)), nil, rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo))
	projects.SetLevelRefs(levelrefs.New(f.db))
	router := storedAsSentRouter()
	router.PATCH("/api/v2/projects/:id", projects.UpdateByID)
	if code, body := storedAsSentCall(t, router, http.MethodPatch, "/api/v2/projects/"+project.ID.String(), f.creator.ID,
		storedAsSentDocument(t, "projects", map[string]any{"identity-binding-id": hosted.String()})); code != http.StatusOK {
		t.Fatalf("a project selecting the hosted binding = %d, want 200 (%s)", code, body)
	}
	for table, id := range map[string]any{"organizations": org.ID, "projects": project.ID} {
		var got *string
		if err := f.db.Table(table).Select("identity_binding_id::text").Where("id = ?", id).Scan(&got).Error; err != nil {
			t.Fatal(err)
		}
		if got == nil || *got != hosted.String() {
			t.Errorf("%s stored %v, want the hosted binding", table, got)
		}
	}

	// A run of a hosted workspace in the project resolves the project's hosted binding, and its
	// job token carries it.
	ws := f.workspaceIn(t, org, "hbsel-ws", "")
	run := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", run.ID).Delete(&models.Run{}) })
	hostedPool, _, err := repository.HostedPoolOf(f.db, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{db: f.db}
	id, err := h.jobIdentity(models.JobTypeTofuRun, run.ID, &hostedPool)
	if err != nil || id == nil || id.BindingID != hosted.String() || id.ServiceAccount != "stackweaver-hosted-identity" || id.Mechanism != models.IdentityMechanismAzureWorkloadIdentity {
		t.Errorf("the hosted run's token identity = %+v, %v; want the hosted binding", id, err)
	}
}
