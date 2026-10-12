// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A run task created with `enabled: false` must be stored disabled, and one created without the
// attribute must be enabled. That is what Terraform Enterprise does and what the tfe provider
// relies on: tfe_organization_run_task sends `enabled` on every create and reads it back, so a
// server that stored true for a sent false fails the apply with an inconsistent result.
//
// The defect this test was written against: RunTask.Enabled carried `gorm:"default:true"`, and
// GORM substitutes a literal default for a zero value in the INSERT (and writes it back into the
// struct), so the 201 body and the stored row both said true. The default lives in
// RunTaskHandlerV2.Create instead.
//
// This drives the real handler, the real rbac.Service and real Postgres. Gated behind
// `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly row-scoped (the
// database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/terraform/ -run TestRunTaskCreate_Enabled

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
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/runtask"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// createEnabledRequest sends one JSON:API request to router and returns the status with the
// response's data.id and data.attributes. An empty attrs sends no body.
func createEnabledRequest(t *testing.T, router http.Handler, method, path, resourceType string, attrs map[string]any) (int, string, map[string]any) {
	t.Helper()
	body := ""
	if attrs != nil {
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": resourceType, "attributes": attrs}})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		body = string(raw)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var doc struct {
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("%s %s: decode response (%d): %v\n%s", method, path, rec.Code, err, rec.Body.String())
	}
	if rec.Code >= 400 {
		t.Logf("%s %s = %d: %s", method, path, rec.Code, rec.Body.String())
	}
	return rec.Code, doc.Data.ID, doc.Data.Attributes
}

func TestRunTaskCreate_EnabledIsStoredAsSent(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	// Registered first, so it runs after the row cleanup below. The suite shares one Postgres with
	// every other session on the host, and a pool left open holds connections until the test
	// binary exits.
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.Project{}, &models.Workspace{}, &models.RunTask{}, &models.WorkspaceTask{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "rtenabled-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "rtenabled-" + sfx, Email: "rtenabled-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	seed := []any{
		org, owner, ownersTeam,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		// Row-scoped only: TEST_DATABASE_URL may point at a live database. The organization is this
		// test's own, so its run tasks are exactly the ones the cases below created.
		db.Where("organization_id = ?", org.ID).Delete(&models.RunTask{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})

	// The create handshakes with the task URL before the INSERT, through an SSRF-guarded client
	// that refuses loopback unless this variable is set when the service is constructed.
	t.Setenv("STACKWEAVER_RUN_TASKS_ALLOW_PRIVATE", "true")
	taskServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(taskServer.Close)

	cryptoService, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("crypto service: %v", err)
	}
	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	h := NewRunTaskHandlerV2(
		repository.NewRunTaskRepository(db),
		repository.NewWorkspaceTaskRepository(db),
		orgRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, teamRepo, repository.NewProjectRepository(db)),
		cryptoService,
		runtask.NewService(cryptoService),
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", owner.ID)
		c.Next()
	})
	router.POST("/api/v2/organizations/:name/tasks", h.Create)
	router.GET("/api/v2/tasks/:id", h.Read)

	sent := func(v bool) *bool { return &v }
	cases := []struct {
		name    string
		enabled *bool // nil leaves the attribute out
		want    bool
	}{
		{"explicit false", sent(false), false},
		{"explicit true", sent(true), true},
		{"absent", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]any{"name": "rtenabled-" + uuid.NewString()[:8], "url": taskServer.URL}
			if tc.enabled != nil {
				attrs["enabled"] = *tc.enabled
			}
			code, id, created := createEnabledRequest(t, router, http.MethodPost,
				"/api/v2/organizations/"+org.Name+"/tasks", "tasks", attrs)
			if code != http.StatusCreated {
				t.Fatalf("create = %d, want 201", code)
			}
			if got, ok := created["enabled"].(bool); !ok || got != tc.want {
				t.Errorf("create response: enabled = %v, want %t", created["enabled"], tc.want)
			}

			code, _, read := createEnabledRequest(t, router, http.MethodGet, "/api/v2/tasks/"+id, "tasks", nil)
			if code != http.StatusOK {
				t.Fatalf("read = %d, want 200", code)
			}
			if got, ok := read["enabled"].(bool); !ok || got != tc.want {
				t.Errorf("read back: enabled = %v, want %t", read["enabled"], tc.want)
			}
		})
	}
}
