// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// #815: VariableHandlerV2.Update used the empty string as its "field not supplied" sentinel, so a
// PATCH carrying `"description": ""` or `"value": ""` returned 200 and changed nothing. The
// request attributes are now pointers - nil leaves a field alone, "" clears it - mirroring
// UpdateVariableSetVariable. These tests drive the real handler against real Postgres and cover
// both directions, plus the guards that key off the same branch: the HCL-empty refusal (#674), the
// sensitivity reconciliation (AUD-044) and the masked-value round trip (AUD-105).
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestWorkspaceVariableUpdate

//go:build integration

package terraform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	varsvc "github.com/michielvha/stackweaver/core/services/variable"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestWorkspaceVariableUpdate(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.TeamWorkspaceAccess{}, &models.Project{}, &models.Workspace{}, &models.Variable{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "varupd-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "varupd-own-" + sfx, Email: "varupd-own-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-vu" + sfx + "00000", ProjectID: project.ID, Name: "ws-" + sfx}
	admin := "admin"

	seed := []any{
		org, owner, ownersTeam, project, workspace,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
		&models.TeamWorkspaceAccess{ID: uuid.New(), TeamID: ownersTeam.ID, WorkspaceID: workspace.ID, Access: &admin},
	}
	t.Cleanup(func() {
		db.Where("workspace_id = ?", workspace.ID).Delete(&models.Variable{})
		db.Where("workspace_id = ?", workspace.ID).Delete(&models.TeamWorkspaceAccess{})
		db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(db)
	varRepo := repository.NewVariableRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	varSvc := varsvc.NewService(varRepo, []byte("0123456789abcdef0123456789abcdef"))
	h := NewVariableHandlerV2(varRepo, repository.NewWorkspaceRepository(db), authService, rbacService, varSvc)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if v := c.GetHeader("X-Test-User"); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				c.Set("user_id", id)
			}
		}
		c.Next()
	})
	router.POST("/workspaces/:id/vars", h.Create)
	router.PATCH("/workspaces/:id/vars/:variable_id", h.Update)

	base := "/workspaces/" + workspace.ID + "/vars"
	do := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/vnd.api+json")
		req.Header.Set("X-Test-User", owner.ID.String())
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	// create goes through the handler so sensitive values are encrypted exactly as in production.
	create := func(attrs string) string {
		t.Helper()
		code, resp := do(http.MethodPost, base, `{"data":{"type":"vars","attributes":`+attrs+`}}`)
		if code != http.StatusCreated {
			t.Fatalf("create variable %s: status %d body %v", attrs, code, resp)
		}
		data, _ := resp["data"].(map[string]any)
		id, _ := data["id"].(string)
		if id == "" {
			t.Fatalf("create variable %s: no id in %v", attrs, resp)
		}
		return id
	}
	patch := func(id, attrs string) (int, map[string]any) {
		t.Helper()
		return do(http.MethodPatch, base+"/"+id, `{"data":{"id":"`+id+`","type":"vars","attributes":`+attrs+`}}`)
	}
	load := func(id string) models.Variable {
		t.Helper()
		var v models.Variable
		if err := db.Where("id = ?", id).First(&v).Error; err != nil {
			t.Fatalf("load variable %s: %v", id, err)
		}
		return v
	}
	plaintext := func(v models.Variable) string {
		t.Helper()
		if !v.Encrypted {
			return v.Value
		}
		p, err := varSvc.Decrypt(v.Value)
		if err != nil {
			t.Fatalf("decrypt variable %s: %v", v.ID, err)
		}
		return p
	}

	t.Run("explicit empty description clears it", func(t *testing.T) {
		id := create(`{"key":"DESC_CLEAR_` + sfx + `","value":"v","description":"old"}`)
		if code, resp := patch(id, `{"description":""}`); code != http.StatusOK {
			t.Fatalf("status %d body %v", code, resp)
		}
		if got := load(id).Description; got != "" {
			t.Errorf("description = %q, want cleared", got)
		}
	})

	t.Run("omitted fields are left alone", func(t *testing.T) {
		id := create(`{"key":"OMIT_` + sfx + `","value":"keep-value","description":"keep-desc","category":"env"}`)
		if code, resp := patch(id, `{"hcl":false}`); code != http.StatusOK {
			t.Fatalf("status %d body %v", code, resp)
		}
		v := load(id)
		if v.Value != "keep-value" || v.Description != "keep-desc" || v.Category != "env" || v.Key != "OMIT_"+sfx {
			t.Errorf("omitted fields changed: %+v", v)
		}
	})

	t.Run("explicit empty value clears it", func(t *testing.T) {
		id := create(`{"key":"VAL_CLEAR_` + sfx + `","value":"something"}`)
		code, resp := patch(id, `{"value":""}`)
		if code != http.StatusOK {
			t.Fatalf("status %d body %v", code, resp)
		}
		if got := load(id).Value; got != "" {
			t.Errorf("value = %q, want cleared", got)
		}
		attrs, _ := resp["data"].(map[string]any)["attributes"].(map[string]any)
		if got, _ := attrs["value"].(string); got != "" {
			t.Errorf("response value = %q, want empty", got)
		}
	})

	t.Run("explicit empty sensitive value clears it and stays encrypted", func(t *testing.T) {
		id := create(`{"key":"SECRET_CLEAR_` + sfx + `","value":"s3cret","sensitive":true}`)
		if code, resp := patch(id, `{"value":""}`); code != http.StatusOK {
			t.Fatalf("status %d body %v", code, resp)
		}
		v := load(id)
		if !v.Encrypted {
			t.Error("cleared sensitive value is no longer encrypted at rest")
		}
		if got := plaintext(v); got != "" {
			t.Errorf("sensitive value decrypts to %q, want cleared", got)
		}
	})

	t.Run("clearing an HCL variable's value is refused", func(t *testing.T) {
		id := create(`{"key":"HCL_CLEAR_` + sfx + `","value":"[1, 2, 3]","hcl":true}`)
		if code, resp := patch(id, `{"value":""}`); code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422 (body %v)", code, resp)
		}
		if got := load(id).Value; got != "[1, 2, 3]" {
			t.Errorf("value = %q after a refused clear, want it untouched", got)
		}
		// Clearing and un-flagging in one request is fine: the result is a quoted empty string.
		if code, resp := patch(id, `{"value":"","hcl":false}`); code != http.StatusOK {
			t.Fatalf("clear + unset hcl: status %d body %v", code, resp)
		}
	})

	t.Run("flipping hcl onto an empty variable is refused", func(t *testing.T) {
		id := create(`{"key":"HCL_FLIP_` + sfx + `","value":""}`)
		if code, resp := patch(id, `{"hcl":true}`); code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422 (body %v)", code, resp)
		}
		if load(id).HCL {
			t.Error("variable marked hcl despite the refusal")
		}
	})

	t.Run("explicit empty key is refused", func(t *testing.T) {
		id := create(`{"key":"KEY_EMPTY_` + sfx + `","value":"v"}`)
		if code, resp := patch(id, `{"key":""}`); code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400 (body %v)", code, resp)
		}
		if got := load(id).Key; got != "KEY_EMPTY_"+sfx {
			t.Errorf("key = %q, want untouched", got)
		}
	})

	t.Run("masked value round trip keeps the secret (AUD-105)", func(t *testing.T) {
		id := create(`{"key":"MASK_` + sfx + `","value":"s3cret","sensitive":true}`)
		code, resp := patch(id, `{"key":"MASK_`+sfx+`","value":"`+maskedVariableValue+`","description":"edited","sensitive":true}`)
		if code != http.StatusOK {
			t.Fatalf("status %d body %v", code, resp)
		}
		v := load(id)
		if v.Description != "edited" {
			t.Errorf("description = %q, want the sibling edit applied", v.Description)
		}
		if got := plaintext(v); got != "s3cret" {
			t.Errorf("secret = %q after a masked round trip, want it preserved", got)
		}
	})

	t.Run("sensitivity flip without a value reconciles encryption (AUD-044)", func(t *testing.T) {
		id := create(`{"key":"UNSENS_` + sfx + `","value":"s3cret","sensitive":true}`)
		// The masked value is what a round-tripping client sends; it must count as "no new value".
		if code, resp := patch(id, `{"value":"`+maskedVariableValue+`","sensitive":false}`); code != http.StatusOK {
			t.Fatalf("status %d body %v", code, resp)
		}
		v := load(id)
		if v.Encrypted || v.Sensitive || v.Value != "s3cret" {
			t.Errorf("after sensitive->non-sensitive: encrypted=%v sensitive=%v value=%q, want false/false/s3cret", v.Encrypted, v.Sensitive, v.Value)
		}

		if code, resp := patch(id, `{"sensitive":true}`); code != http.StatusOK {
			t.Fatalf("re-flag sensitive: status %d body %v", code, resp)
		}
		v = load(id)
		if !v.Encrypted || plaintext(v) != "s3cret" {
			t.Errorf("after non-sensitive->sensitive: encrypted=%v plaintext=%q, want true/s3cret", v.Encrypted, plaintext(v))
		}
	})
}
