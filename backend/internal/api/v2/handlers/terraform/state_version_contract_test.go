// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The state-version contract under the TFE rules (#858, D7, AC5). Creating a state version takes
// the document go-tfe's StateVersions.Create sends (StateVersionCreateOptions: type
// state-versions, md5 and serial required, state base64, a run relationship) and answers the same
// projection Get answers. It succeeds only while the workspace is locked by the caller, or its
// state is locked by the run the document names, which is why the Terraform CLI's remote backend
// locks before it pushes. go-tfe is not a dependency of this module, so the document is a literal
// in the shape its jsonapi encoder produces; the provider fork's data_source_outputs_test.go is
// the round trip through real go-tfe.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestStateVersionContract

//go:build integration

package terraform

import (
	"crypto/md5" //nolint:gosec // TFE's integrity check of the state is an MD5 of it, not a security boundary
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
	"gorm.io/gorm"
)

type stateVersionFixture struct {
	db        *gorm.DB
	router    *gin.Engine
	owner     *models.User
	other     *models.User
	workspace *models.Workspace
	runID     string
}

func setupStateVersionContract(t *testing.T) *stateVersionFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	// The md5, size, status and resources-processed columns are new; the API migrates them on
	// startup, and the test migrates them itself so it does not depend on that having run.
	if err := db.AutoMigrate(&models.StateVersion{}); err != nil {
		t.Fatalf("migrate state versions: %v", err)
	}
	sfx := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "svc-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "svc-own-" + sfx, Email: "svc-own-" + sfx + "@test.local"}
	other := &models.User{ID: uuid.New(), ZitadelSubject: "svc-oth-" + sfx, Email: "svc-oth-" + sfx + "@test.local"}
	owners := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-sv" + sfx + "00000", ProjectID: project.ID, Name: "ws-" + sfx}
	run := &models.Run{ID: "run-sv" + sfx + "00000", WorkspaceID: workspace.ID, Status: models.RunStatusApplying, Operation: models.RunOperationPlanAndApply}
	for _, row := range []any{
		org, owner, other, owners, project, workspace, run,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: other.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: owners.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: owners.ID, UserID: other.ID},
	} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		db.Exec("DELETE FROM state_version_outputs WHERE state_version_id IN (SELECT id FROM state_versions WHERE workspace_id = ?)", workspace.ID)
		db.Exec("DELETE FROM state_version_resources WHERE state_version_id IN (SELECT id FROM state_versions WHERE workspace_id = ?)", workspace.ID)
		db.Where("workspace_id = ?", workspace.ID).Delete(&models.StateVersion{})
		db.Where("workspace_id = ?", workspace.ID).Delete(&models.StateLock{})
		db.Where("id = ?", run.ID).Delete(&models.Run{})
		db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("team_id = ?", owners.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", owners.ID).Delete(&models.Team{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, other.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	workspaceRepo := repository.NewWorkspaceRepository(db)
	versionRepo := repository.NewStateVersionRepository(db)
	store := storagetest.NewMemory()
	stateService := state.NewService(versionRepo, repository.NewStateLockRepository(db), workspaceRepo, store, nil, nil)
	h := NewStateVersionHandlerV2(versionRepo, workspaceRepo, projectRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo),
		stateService, store, repository.NewStateVersionOutputRepository(db), repository.NewStateVersionResourceRepository(db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	r.GET("/workspaces/:id/state-versions", h.ListByWorkspace)
	r.POST("/workspaces/:id/state-versions", h.Create)
	r.POST("/workspaces/:id/state-versions/remove-resource", h.RemoveResource)
	return &stateVersionFixture{db: db, router: r, owner: owner, other: other, workspace: workspace, runID: run.ID}
}

func (f *stateVersionFixture) call(t *testing.T, as uuid.UUID, method, path, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("X-Test-User", as.String())
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// lockBy sets the workspace's lock as the workspace lock action does, or clears it with nil.
func (f *stateVersionFixture) lockBy(t *testing.T, user *uuid.UUID) {
	t.Helper()
	now := time.Now()
	update := map[string]any{"locked": user != nil, "locked_by": user, "locked_at": &now}
	if user == nil {
		update["locked_at"] = nil
	}
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", f.workspace.ID).Updates(update).Error; err != nil {
		t.Fatalf("set the workspace lock: %v", err)
	}
}

// stateDocument is the document go-tfe's jsonapi encoder produces for StateVersionCreateOptions
// with State set, a serial and, when runID is not empty, the run relationship.
func stateDocument(t *testing.T, serial int, md5Override, runID string) string {
	t.Helper()
	raw := `{"version":4,"terraform_version":"1.9.0","serial":` + strconv.Itoa(serial) +
		`,"lineage":"contract-lineage","outputs":{"region":{"value":"eu-west-1","type":"string"}},"resources":[` +
		`{"mode":"managed","type":"null_resource","name":"a","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"attributes":{"id":"1"}}]},` +
		`{"mode":"managed","type":"null_resource","name":"b","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"attributes":{"id":"2"}}]}]}`
	sum := md5.Sum([]byte(raw)) //nolint:gosec // see the import
	digest := hex.EncodeToString(sum[:])
	if md5Override != "" {
		digest = md5Override
	}
	doc := map[string]any{"data": map[string]any{
		"type": "state-versions",
		"attributes": map[string]any{
			"lineage": "contract-lineage", "md5": digest, "serial": serial,
			"state": base64.StdEncoding.EncodeToString([]byte(raw)),
		},
	}}
	if runID != "" {
		doc["data"].(map[string]any)["relationships"] = map[string]any{"run": map[string]any{"data": map[string]any{"type": "runs", "id": runID}}}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type stateVersionResource struct {
	Type          string                     `json:"type"`
	ID            string                     `json:"id"`
	Attributes    map[string]any             `json:"attributes"`
	Relationships map[string]json.RawMessage `json:"relationships"`
}

func decodeStateVersion(t *testing.T, raw []byte) stateVersionResource {
	t.Helper()
	var doc struct {
		Data stateVersionResource `json:"data"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Data.Type != "state-versions" || doc.Data.ID == "" {
		t.Fatalf("not a state-versions resource: %s", raw)
	}
	return doc.Data
}

func TestStateVersionContract(t *testing.T) {
	f := setupStateVersionContract(t)
	path := "/workspaces/" + f.workspace.ID + "/state-versions"

	conflict := func(t *testing.T, as uuid.UUID, body string) {
		t.Helper()
		if code, raw := f.call(t, as, http.MethodPost, path, body); code != http.StatusConflict {
			t.Errorf("got %d %s, want 409", code, raw)
		}
	}

	t.Run("an unlocked workspace refuses the push", func(t *testing.T) {
		f.lockBy(t, nil)
		conflict(t, f.owner.ID, stateDocument(t, 1, "", ""))
	})

	t.Run("a workspace locked by another identity refuses the push", func(t *testing.T) {
		f.lockBy(t, &f.other.ID)
		conflict(t, f.owner.ID, stateDocument(t, 1, "", ""))
	})

	t.Run("a flat state_data body is not the document", func(t *testing.T) {
		f.lockBy(t, &f.owner.ID)
		code, raw := f.call(t, f.owner.ID, http.MethodPost, path, `{"state_data":{"version":4,"serial":1}}`)
		if code != http.StatusBadRequest || !strings.Contains(string(raw), `request body must be a JSON:API document: {\"data\": {\"type\": \"state-versions\"`) {
			t.Errorf("got %d %s, want the document sentence", code, raw)
		}
	})

	t.Run("an md5 that does not match the state is refused", func(t *testing.T) {
		f.lockBy(t, &f.owner.ID)
		if code, raw := f.call(t, f.owner.ID, http.MethodPost, path, stateDocument(t, 1, "00000000000000000000000000000000", "")); code != http.StatusBadRequest || !strings.Contains(string(raw), "md5") {
			t.Errorf("got %d %s, want a 400 naming the md5", code, raw)
		}
	})

	var created stateVersionResource
	t.Run("a workspace locked by the caller takes the push and answers the projection", func(t *testing.T) {
		f.lockBy(t, &f.owner.ID)
		code, raw := f.call(t, f.owner.ID, http.MethodPost, path, stateDocument(t, 1, "", ""))
		if code != http.StatusCreated {
			t.Fatalf("got %d %s, want 201", code, raw)
		}
		created = decodeStateVersion(t, raw)
		a := created.Attributes
		if !strings.HasSuffix(a["hosted-state-download-url"].(string), "/api/v2/state-versions/"+created.ID+"/download") ||
			a["serial"] != float64(1) || a["status"] != "finalized" || a["lineage"] != "contract-lineage" {
			t.Errorf("attributes: %v", a)
		}
		for _, name := range []string{"created-at", "size", "resources-processed", "state-version", "vcs-commit-sha"} {
			if _, ok := a[name]; !ok {
				t.Errorf("attributes lack %s: %v", name, a)
			}
		}
		for _, name := range []string{"workspace", "outputs"} {
			if _, ok := created.Relationships[name]; !ok {
				t.Errorf("relationships lack %s: %v", name, created.Relationships)
			}
		}
		if _, leaked := a["workspace_id"]; leaked {
			t.Errorf("the attributes are still the database row: %v", a)
		}
	})

	t.Run("a state lock held by the named run takes the push", func(t *testing.T) {
		f.lockBy(t, nil)
		lock := &models.StateLock{WorkspaceID: f.workspace.ID, LockID: "lock-" + uuid.NewString()[:8], Operation: "apply", LockedBy: &f.runID, ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.db.Create(lock).Error; err != nil {
			t.Fatalf("seed the run's state lock: %v", err)
		}
		t.Cleanup(func() { f.db.Where("id = ?", lock.ID).Delete(&models.StateLock{}) })
		code, raw := f.call(t, f.owner.ID, http.MethodPost, path, stateDocument(t, 2, "", f.runID))
		if code != http.StatusCreated {
			t.Fatalf("got %d %s, want 201", code, raw)
		}
		var rel struct {
			Data struct{ Type, ID string } `json:"data"`
		}
		if err := json.Unmarshal(decodeStateVersion(t, raw).Relationships["run"], &rel); err != nil || rel.Data.ID != f.runID {
			t.Errorf("the run relationship does not name the run: %s", raw)
		}
		// Without naming the run, the run's lock is another identity's.
		conflict(t, f.owner.ID, stateDocument(t, 3, "", ""))
		f.db.Where("id = ?", lock.ID).Delete(&models.StateLock{})
	})

	t.Run("the list answers the same projection with the standard block", func(t *testing.T) {
		code, raw := f.call(t, f.owner.ID, http.MethodGet, path, "")
		if code != http.StatusOK {
			t.Fatalf("got %d %s", code, raw)
		}
		var doc struct {
			Data []stateVersionResource `json:"data"`
			Meta struct {
				Pagination map[string]any `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Data) != 2 {
			t.Fatalf("list: %s", raw)
		}
		for _, v := range doc.Data {
			if v.Type != "state-versions" || v.Attributes["status"] != "finalized" || v.Attributes["hosted-state-download-url"] == nil {
				t.Errorf("a listed version is not the projection: %+v", v)
			}
		}
		if doc.Meta.Pagination["total-count"] != float64(2) {
			t.Errorf("pagination: %v", doc.Meta.Pagination)
		}
	})

	t.Run("remove-resource takes a state-versions document and answers the version it wrote", func(t *testing.T) {
		f.lockBy(t, nil)
		code, raw := f.call(t, f.owner.ID, http.MethodPost, path+"/remove-resource", `{"address":"null_resource.a"}`)
		if code != http.StatusBadRequest || !strings.Contains(string(raw), `\"type\": \"state-versions\"`) {
			t.Errorf("a flat address: got %d %s, want the document sentence", code, raw)
		}
		code, raw = f.call(t, f.owner.ID, http.MethodPost, path+"/remove-resource", `{"data":{"type":"state-versions","attributes":{"address":"null_resource.a"}}}`)
		if code != http.StatusCreated {
			t.Fatalf("got %d %s, want 201", code, raw)
		}
		v := decodeStateVersion(t, raw)
		// The third version of the workspace. Its serial column stays empty: SaveState, the core
		// path the removal writes through, does not record one.
		if v.ID == created.ID || v.Attributes["state-version"] != float64(3) {
			t.Errorf("remove-resource answered %+v, want the new, third version", v)
		}
	})
}
