// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/launcher"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

func TestRunnerPermissionReadRecovery(t *testing.T) {
	fixture := setupClaimRouteFixture(t)
	key, err := fixture.keys.VerifyAPIKey(fixture.token)
	if err != nil || key == nil || key.UserID == nil || key.AgentPoolID == nil {
		t.Fatal("the fixture needs a marked launcher key with a user")
	}
	if err := fixture.db.Model(&models.APIKey{}).Where("id = ?", key.ID).Update("agent_pool_id", nil).Error; err != nil {
		t.Fatal(err)
	}

	authService := auth.NewService(repository.NewUserRepository(fixture.db))
	authService.SetAPIKeyService(fixture.keys)
	permissions := rbac.NewServiceWithTeams(
		repository.NewOrganizationRepository(fixture.db),
		repository.NewTeamRepository(fixture.db),
		repository.NewProjectRepository(fixture.db),
	)
	router := gin.New()
	registration := uuid.NewString()
	// A launcher already registered before pool marking would hold this identity in memory.
	// Keep that handshake local to the fixture so registration cannot replace it with a new key.
	router.POST("/api/v2/runner/register", func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer "+registration {
			c.Status(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusOK, runnercontract.RegisterResponse{
			RunnerID: fixture.runnerA1.ID.String(), RunnerAPIKey: fixture.token,
		})
	})
	router.Use(middleware.AuthMiddleware(authService))
	trust := &middleware.LauncherTrust{Permissions: permissions}
	runnerRoutes := router.Group("/api/v2/runner",
		middleware.RunnerAuth(repository.NewRunnerRepository(fixture.db), trust),
		middleware.RequireRunnerToken(),
	)
	runnerRoutes.GET("/permission-probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	runnerRoutes.POST("/jobs/:id/start", fixture.handler.JobStart)

	probe := func() *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/runner/permission-probe", nil)
		request.Header.Set("Authorization", "Bearer "+fixture.token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	denied := probe()
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "restart the launcher") {
		t.Fatalf("genuine denial returned HTTP %d without the expected registration advice", denied.Code)
	}

	owners := &models.Team{ID: uuid.New(), OrganizationID: fixture.orgA, Name: "owners"}
	membership := &models.OrganizationMember{ID: uuid.New(), OrganizationID: fixture.orgA, UserID: *key.UserID}
	teamMember := &models.TeamMember{ID: uuid.New(), TeamID: owners.ID, UserID: *key.UserID}
	t.Cleanup(func() {
		for _, row := range []any{teamMember, membership, owners} {
			if err := fixture.db.Delete(row).Error; err != nil {
				t.Error(err)
			}
		}
	})
	for _, row := range []any{owners, membership, teamMember} {
		if err := fixture.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if response := probe(); response.Code != http.StatusNoContent {
		t.Fatalf("permitted unmarked launcher returned HTTP %d", response.Code)
	}

	var fault atomic.Bool
	var faults atomic.Int32
	const callback = "runner_permission_recovery:fail_membership"
	if err := fixture.db.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table == "organization_members" && fault.CompareAndSwap(true, false) {
			faults.Add(1)
			_ = tx.AddError(errors.New("temporary permission read failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.db.Callback().Query().Remove(callback); err != nil {
			t.Error(err)
		}
	})

	fault.Store(true)
	unavailable := probe()
	code, _ := runnercontract.DecodeError(unavailable.Body.Bytes())
	if unavailable.Code != http.StatusInternalServerError || code != "" || strings.Contains(unavailable.Body.String(), "restart the launcher") {
		t.Errorf("permission read failure returned HTTP %d, code %q, restart advice %v",
			unavailable.Code, code, strings.Contains(unavailable.Body.String(), "restart the launcher"))
	}
	if faults.Load() != 1 {
		t.Fatal("the membership read fault did not run")
	}

	offer := startRouteCases[0]
	jobID, _ := fixture.seedStart(t, offer)
	server := httptest.NewServer(router)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	client := launcher.NewClient(server.URL, registration)
	if _, err := client.Register(ctx, runnercontract.RegisterRequest{}); err != nil {
		t.Fatalf("restore the fixture's existing launcher identity: %v", err)
	}
	fault.Store(true)
	request := runnercontract.PendingJob{JobID: jobID, JobType: offer.kind, Attempt: 1}
	if err := client.Start(ctx, request, nil); err != nil {
		t.Errorf("launcher did not recover the original offer after the permission failure: %v", err)
	}
	if faults.Load() != 2 {
		t.Error("the retry scenario did not exercise the membership read fault")
	}
}

func TestRunnerManagementPermissionReadRecovery(t *testing.T) {
	fixture := setupClaimRouteFixture(t)
	orgs := repository.NewOrganizationRepository(fixture.db)
	org, err := orgs.GetByID(fixture.orgA)
	if err != nil {
		t.Fatal(err)
	}
	permissions := rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(fixture.db), repository.NewProjectRepository(fixture.db))
	handler := NewRunnerHandlerV2(repository.NewRunnerRepository(fixture.db), nil, nil, orgs, permissions)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uuid.New())
	})
	router.GET("/organizations/:name/runners", handler.List)

	list := func() int {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/organizations/"+org.Name+"/runners", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response.Code
	}
	if got := list(); got != http.StatusForbidden {
		t.Fatalf("nonmember received HTTP %d, want 403", got)
	}

	callback := fixture.db.Callback().Query()
	const name = "runner_management_permission:fail_membership"
	observed := false
	if err := callback.After("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "organization_members" && strings.Contains(tx.Statement.SQL.String(), "count(") {
			observed = true
			_ = tx.AddError(errors.New("temporary permission read failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := callback.Remove(name); err != nil {
			t.Error(err)
		}
	})

	if got := list(); got != http.StatusInternalServerError {
		t.Errorf("permission read failure received HTTP %d, want 500", got)
	}
	if !observed {
		t.Fatal("the permission lookup was not exercised")
	}
}
