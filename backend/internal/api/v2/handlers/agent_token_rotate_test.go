// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Agent token rotation (#734) against real Postgres: the replacement token authenticates, the old
// token keeps authenticating for the grace window and is rejected after it, rotation never extends
// an expiry, and only a caller who may manage the pool's org can rotate.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAgentTokenRotate

//go:build integration
// +build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type agentRotateFixture struct {
	db       *gorm.DB
	router   *gin.Engine
	keys     *apikey.Service
	owner    *models.User // orgA owners team
	member   *models.User // orgA, no org-level permissions
	outsider *models.User // orgB owner
	pool     *models.AgentPool
}

func setupAgentRotateFixture(t *testing.T) *agentRotateFixture {
	t.Helper()
	db := setupAuthzTestDB(t)
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "rotate-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "rotate-b-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "rotate-owner-" + sfx, Email: "rotate-owner-" + sfx + "@test.local"}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "rotate-member-" + sfx, Email: "rotate-member-" + sfx + "@test.local"}
	outsider := &models.User{ID: uuid.New(), ZitadelSubject: "rotate-out-" + sfx, Email: "rotate-out-" + sfx + "@test.local"}
	ownersA := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	devsA := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "developers"}
	ownersB := &models.Team{ID: uuid.New(), OrganizationID: orgB.ID, Name: "owners"}
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: orgA.ID, Name: "rotate-pool-" + sfx}

	seed := []any{
		orgA, orgB, owner, member, outsider, ownersA, devsA, ownersB, pool,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: owner.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgB.ID, UserID: outsider.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersA.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: devsA.ID, UserID: member.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersB.ID, UserID: outsider.ID},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		teamIDs := []uuid.UUID{ownersA.ID, devsA.ID, ownersB.ID}
		db.Where("agent_pool_id = ? AND is_agent_token = ?", pool.ID, true).Delete(&models.APIKey{})
		db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
		db.Where("team_id IN ?", teamIDs).Delete(&models.TeamMember{})
		db.Where("id IN ?", teamIDs).Delete(&models.Team{})
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
		db.Where("id IN ?", []uuid.UUID{owner.ID, member.ID, outsider.ID}).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	keys := apikey.NewService(repository.NewAPIKeyRepository(db), orgRepo, projectRepo, teamRepo)
	h := NewAgentTokenHandlerV2(keys,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, teamRepo, projectRepo),
		repository.NewAgentPoolRepository(db))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(testUserAuth())
	router.POST("/api/v2/authentication-tokens/:id/actions/rotate", h.Rotate)
	router.GET("/api/v2/authentication-tokens/:id", h.ReadByID)

	return &agentRotateFixture{db: db, router: router, keys: keys, owner: owner, member: member, outsider: outsider, pool: pool}
}

// mint creates an agent token in the fixture pool and returns its record and plaintext.
func (f *agentRotateFixture) mint(t *testing.T) (*models.APIKey, string) {
	t.Helper()
	key, plain, err := f.keys.CreateAgentToken(f.owner.ID, f.pool.ID, f.pool.OrganizationID, "prod agents")
	if err != nil {
		t.Fatalf("create agent token: %v", err)
	}
	return key, plain
}

type rotateResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Token       string `json:"token"`
			Description string `json:"description"`
		} `json:"attributes"`
	} `json:"data"`
	Meta struct {
		RotatedFrom          string     `json:"rotated-from"`
		RotatedFromExpiredAt *time.Time `json:"rotated-from-expired-at"`
	} `json:"meta"`
}

func (f *agentRotateFixture) rotate(t *testing.T, as uuid.UUID, id string, body any) (int, rotateResponse) {
	t.Helper()
	rec := authzRequest(t, f.router, http.MethodPost, "/api/v2/authentication-tokens/"+id+"/actions/rotate", as, body)
	var out rotateResponse
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode rotate response: %v", err)
		}
	}
	return rec.Code, out
}

func gracePeriodBody(hours int) map[string]any {
	return map[string]any{"data": map[string]any{
		"type": "authentication-tokens", "attributes": map[string]any{"grace-period-hours": hours},
	}}
}

func TestAgentTokenRotate_GraceWindow(t *testing.T) {
	f := setupAgentRotateFixture(t)
	old, oldPlain := f.mint(t)

	code, res := f.rotate(t, f.owner.ID, old.ID.String(), gracePeriodBody(2))
	if code != http.StatusCreated {
		t.Fatalf("rotate: got %d, want 201", code)
	}
	if res.Data.Type != "authentication-tokens" || res.Data.ID == old.ID.String() {
		t.Fatalf("rotate must return a new authentication-tokens resource, got %+v", res.Data)
	}
	if res.Data.Attributes.Token == "" || res.Data.Attributes.Description != "prod agents" {
		t.Fatalf("new token must carry its plaintext and the old description, got %+v", res.Data.Attributes)
	}
	if res.Meta.RotatedFrom != old.ID.String() || res.Meta.RotatedFromExpiredAt == nil {
		t.Fatalf("meta must name the retired token and its expiry, got %+v", res.Meta)
	}
	if d := time.Until(*res.Meta.RotatedFromExpiredAt); d < 110*time.Minute || d > 130*time.Minute {
		t.Fatalf("old token expiry %s from now, want about 2h", d)
	}

	// Both tokens authenticate during the grace window, and the new one is still pool-bound.
	newKey, err := f.keys.VerifyAPIKey(res.Data.Attributes.Token)
	if err != nil {
		t.Fatalf("new token rejected: %v", err)
	}
	if !newKey.IsAgentToken || newKey.AgentPoolID == nil || *newKey.AgentPoolID != f.pool.ID {
		t.Fatalf("new token must be an agent token bound to the pool, got %+v", newKey)
	}
	if _, err := f.keys.VerifyAPIKey(oldPlain); err != nil {
		t.Fatalf("old token rejected inside the grace window: %v", err)
	}

	// Rotating the retiring token again with a longer grace must not extend its life.
	before := *res.Meta.RotatedFromExpiredAt
	code, again := f.rotate(t, f.owner.ID, old.ID.String(), gracePeriodBody(168))
	if code != http.StatusCreated {
		t.Fatalf("second rotate: got %d, want 201", code)
	}
	if again.Meta.RotatedFromExpiredAt == nil || again.Meta.RotatedFromExpiredAt.After(before.Add(time.Second)) {
		t.Fatalf("second rotation extended the old expiry from %s to %v", before, again.Meta.RotatedFromExpiredAt)
	}

	// Past the grace window the old token is rejected and the new one still works.
	if err := f.db.Model(&models.APIKey{}).Where("id = ?", old.ID).
		Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("age old token: %v", err)
	}
	if _, err := f.keys.VerifyAPIKey(oldPlain); err == nil {
		t.Fatal("old token still accepted after the grace window")
	}
	if _, err := f.keys.VerifyAPIKey(res.Data.Attributes.Token); err != nil {
		t.Fatalf("new token rejected after the old one expired: %v", err)
	}

	// The retired token reports its expiry on read.
	rec := authzRequest(t, f.router, http.MethodGet, "/api/v2/authentication-tokens/"+old.ID.String(), f.owner.ID, nil)
	var read struct {
		Data struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil || read.Data.Attributes["expired-at"] == nil {
		t.Fatalf("read of a rotated token must surface expired-at, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAgentTokenRotate_DefaultAndZeroGrace(t *testing.T) {
	f := setupAgentRotateFixture(t)

	withDefault, _ := f.mint(t)
	code, res := f.rotate(t, f.owner.ID, withDefault.ID.String(), nil)
	if code != http.StatusCreated {
		t.Fatalf("rotate without body: got %d, want 201", code)
	}
	if d := time.Until(*res.Meta.RotatedFromExpiredAt); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("default grace gave %s, want about 24h", d)
	}

	immediate, immediatePlain := f.mint(t)
	if code, _ := f.rotate(t, f.owner.ID, immediate.ID.String(), gracePeriodBody(0)); code != http.StatusCreated {
		t.Fatalf("rotate with zero grace: got %d, want 201", code)
	}
	if _, err := f.keys.VerifyAPIKey(immediatePlain); err == nil {
		t.Fatal("zero grace must retire the old token immediately")
	}

	if code, _ := f.rotate(t, f.owner.ID, immediate.ID.String(), gracePeriodBody(169)); code != http.StatusUnprocessableEntity {
		t.Fatalf("grace above the cap: got %d, want 422", code)
	}
}

func TestAgentTokenRotate_Authz(t *testing.T) {
	f := setupAgentRotateFixture(t)
	old, oldPlain := f.mint(t)

	cases := []struct {
		name string
		as   uuid.UUID
		id   string
		want int
	}{
		{"anonymous", uuid.Nil, old.ID.String(), http.StatusUnauthorized},
		{"cross-org owner", f.outsider.ID, old.ID.String(), http.StatusForbidden},
		{"same-org member without manage-agent-pools", f.member.ID, old.ID.String(), http.StatusForbidden},
		{"unknown token", f.owner.ID, uuid.NewString(), http.StatusNotFound},
		{"malformed id", f.owner.ID, "not-a-uuid", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := f.rotate(t, tc.as, tc.id, nil); code != tc.want {
				t.Fatalf("got %d, want %d", code, tc.want)
			}
		})
	}

	// A denied rotation must leave the token untouched: no expiry, no sibling minted.
	if _, err := f.keys.VerifyAPIKey(oldPlain); err != nil {
		t.Fatalf("denied rotation affected the token: %v", err)
	}
	reloaded, err := f.keys.GetAgentToken(old.ID)
	if err != nil || reloaded.ExpiresAt != nil {
		t.Fatalf("denied rotation set an expiry: %+v, %v", reloaded, err)
	}
	tokens, err := f.keys.ListAgentTokens(f.pool.ID)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("denied rotation minted a token: %d tokens, %v", len(tokens), err)
	}
}
