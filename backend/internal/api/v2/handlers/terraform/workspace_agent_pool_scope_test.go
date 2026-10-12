// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a workspace may name as its agent pool (#916): a pool of its own organization. A pool of
// another organization is answered exactly like an identifier that names nothing.
//
// The defect these tests were written against: the pool was looked up by identifier and held to
// its own scoping rules only, and those compare no organization. An organization-scoped pool
// allows every workspace that is not excluded, so a workspace of one organization could be
// pointed at a pool of another. A runner of that pool is refused such a run where it accepts it
// (RunnerAgentHandler.authorizeRunnerForRun compares the run's organization with the runner's),
// so the run did not execute there, but the workspace kept naming a pool that is not its
// organization's.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run 'TestWorkspaceAgentPool'

//go:build integration

package terraform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// workspacePoolFixture is workspaceBooleansFixture with agent pools, organization-scoped as a
// pool is by default: two in the fixture's organization and one in a second organization the
// caller has no part in. Its router mounts a handler that has the pool repository the shared
// fixture leaves out.
type workspacePoolFixture struct {
	*workspaceBooleansFixture
	router            *gin.Engine
	own, own2, other  *models.AgentPool
	workspacesAtStart int64
}

func setupWorkspacePools(t *testing.T) *workspacePoolFixture {
	t.Helper()
	base := setupWorkspaceBooleans(t)
	db := base.db
	if err := db.AutoMigrate(&models.AgentPool{}); err != nil {
		t.Fatalf("migrating agent pools: %v", err)
	}
	sfx := uuid.NewString()[:8]
	var project models.Project
	if err := db.First(&project, "id = ?", base.projectID).Error; err != nil {
		t.Fatalf("reading the fixture's project: %v", err)
	}
	var owner models.OrganizationMember
	if err := db.First(&owner, "organization_id = ?", project.OrganizationID).Error; err != nil {
		t.Fatalf("reading the fixture's owner: %v", err)
	}
	otherOrg := &models.Organization{ID: uuid.New(), Name: "wspool-b-" + sfx}
	pool := func(organizationID uuid.UUID, name string) *models.AgentPool {
		return &models.AgentPool{ID: uuid.New(), OrganizationID: organizationID, Name: name + sfx, OrganizationScoped: true}
	}
	f := &workspacePoolFixture{
		workspaceBooleansFixture: base,
		own:                      pool(project.OrganizationID, "wspool-a-"),
		own2:                     pool(project.OrganizationID, "wspool-a2-"),
		other:                    pool(otherOrg.ID, "wspool-b-"),
	}
	for _, row := range []any{otherOrg, f.own, f.own2, f.other} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	poolIDs := []uuid.UUID{f.own.ID, f.own2.ID, f.other.ID}
	// Registered after the shared fixture's cleanup, so it runs before it: the fixture project's
	// workspaces that name a pool go first, then the pools and the second organization.
	t.Cleanup(func() {
		db.Where("project_id = ? AND agent_pool_id IN ?", base.projectID, poolIDs).Delete(&models.Workspace{})
		db.Where("id IN ?", poolIDs).Delete(&models.AgentPool{})
		db.Where("id = ?", otherOrg.ID).Delete(&models.Organization{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	h := NewWorkspaceHandlerV2(
		repository.NewWorkspaceRepository(db), projectRepo, orgRepo, repository.NewVCSConnectionRepository(db), teamRepo,
		repository.NewAgentPoolRepository(db), nil, auth.NewService(repository.NewUserRepository(db)), nil,
		rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo), nil, db,
	)
	f.router = gin.New()
	f.router.Use(func(c *gin.Context) { c.Set("user_id", owner.UserID); c.Next() })
	f.router.POST("/api/v2/organizations/:name/workspaces", h.Create)
	f.router.PATCH("/api/v2/organizations/:name/workspaces/:workspace_name", h.Update)
	f.router.PATCH("/api/v2/workspaces/:id", h.UpdateByID)
	f.workspacesAtStart = f.workspaces(t)
	return f
}

func (f *workspacePoolFixture) send(t *testing.T, method, path string, attrs map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "workspaces", "attributes": attrs}})
	if err != nil {
		t.Fatalf("marshalling the request document: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f *workspacePoolFixture) workspaces(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := f.db.Model(&models.Workspace{}).Where("project_id = ?", f.projectID).Count(&n).Error; err != nil {
		t.Fatalf("counting the workspaces: %v", err)
	}
	return n
}

// poolOf reads the pool a workspace names, empty when it names none.
func (f *workspacePoolFixture) poolOf(t *testing.T, workspaceID string) string {
	t.Helper()
	var workspace models.Workspace
	if err := f.db.Select("agent_pool_id").First(&workspace, "id = ?", workspaceID).Error; err != nil {
		t.Fatalf("reading workspace %s: %v", workspaceID, err)
	}
	if workspace.AgentPoolID == nil {
		return ""
	}
	return workspace.AgentPoolID.String()
}

func agentPoolAttrs(pool string) map[string]any {
	return map[string]any{"execution-mode": "agent", "agent-pool-id": pool}
}

func TestWorkspaceAgentPool_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupWorkspacePools(t)
	writes := map[string]func(t *testing.T, pool string) *httptest.ResponseRecorder{
		"a create": func(t *testing.T, pool string) *httptest.ResponseRecorder {
			attrs := agentPoolAttrs(pool)
			attrs["name"], attrs["project-id"] = "wspool-"+uuid.NewString()[:8], f.projectID.String()
			return f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/workspaces", attrs)
		},
		"an update by name": func(t *testing.T, pool string) *httptest.ResponseRecorder {
			_, name, _ := f.create(t, nil)
			return f.send(t, http.MethodPatch, "/api/v2/organizations/"+f.orgName+"/workspaces/"+name, agentPoolAttrs(pool))
		},
		"an update by id": func(t *testing.T, pool string) *httptest.ResponseRecorder {
			id, _, _ := f.create(t, nil)
			return f.send(t, http.MethodPatch, "/api/v2/workspaces/"+id, agentPoolAttrs(pool))
		},
	}
	for name, send := range writes {
		t.Run(name, func(t *testing.T) {
			foreign, missing := send(t, f.other.ID.String()), send(t, uuid.NewString())
			if foreign.Code != http.StatusUnprocessableEntity || !strings.Contains(foreign.Body.String(), "Agent pool not found") {
				t.Errorf("another organization's pool: %d %s, want 422 Agent pool not found", foreign.Code, foreign.Body.String())
			}
			if foreign.Code != missing.Code || !bytes.Equal(foreign.Body.Bytes(), missing.Body.Bytes()) {
				t.Errorf("another organization's pool and one that does not exist are answered differently:\n  other organization: %d %s\n  does not exist:     %d %s",
					foreign.Code, foreign.Body.String(), missing.Code, missing.Body.String())
			}
		})
	}
	var naming int64
	if err := f.db.Model(&models.Workspace{}).Where("agent_pool_id = ?", f.other.ID).Count(&naming).Error; err != nil {
		t.Fatalf("counting the workspaces: %v", err)
	}
	if naming != 0 {
		t.Errorf("%d workspace(s) name the other organization's pool", naming)
	}
	// The two updates each created the workspace they then failed to update; the creates left
	// nothing behind.
	if got := f.workspaces(t) - f.workspacesAtStart; got != 4 {
		t.Errorf("%d workspace(s) exist beyond the start, want the 4 the update cases created", got)
	}
}

func TestWorkspaceAgentPool_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupWorkspacePools(t)
	attrs := agentPoolAttrs(f.own.ID.String())
	attrs["name"], attrs["project-id"] = "wspool-"+uuid.NewString()[:8], f.projectID.String()
	rec := f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/workspaces", attrs)
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating a workspace with its organization's pool: %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || doc.Data.ID == "" {
		t.Fatalf("decoding the workspace: %v (%s)", err, rec.Body.String())
	}
	if got := f.poolOf(t, doc.Data.ID); got != f.own.ID.String() {
		t.Errorf("the workspace names pool %q, want %q", got, f.own.ID)
	}

	id, _, _ := f.create(t, nil)
	if rec := f.send(t, http.MethodPatch, "/api/v2/workspaces/"+id, agentPoolAttrs(f.own2.ID.String())); rec.Code != http.StatusOK {
		t.Fatalf("pointing a workspace at a pool of its organization: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.poolOf(t, id); got != f.own2.ID.String() {
		t.Errorf("after the update the workspace names pool %q, want %q", got, f.own2.ID)
	}
}
