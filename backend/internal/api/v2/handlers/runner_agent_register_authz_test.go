// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the registration invariant (#933, D1, AC65): POST /runner/register succeeds
// only with a pool-bound agent token for that pool or an organization key carrying runner:register
// on the pool's organization (the hosted registration identity joins in a later task). Every other
// key is refused with 403 and leaves no runner row behind. A binding that cannot be read is refused
// by poolBindingVerdict, which TestPoolBindingVerdict covers.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRegisterAuthz

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// registerRouter mounts Register behind a stand-in for AuthMiddleware that establishes the key the
// X-Test-Key header names exactly as the real one does (auth.establishAPIKey).
func (f *agentPrepFixture) registerRouter(owner uuid.UUID) *gin.Engine {
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	h := &RunnerAgentHandler{
		db:            f.db,
		runnerRepo:    repository.NewRunnerRepository(f.db),
		poolRepo:      repository.NewAgentPoolRepository(f.db),
		apiKeyService: svc,
	}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		key := f.keys[c.GetHeader("X-Test-Key")]
		if key == nil {
			c.Next()
			return
		}
		if key.ID == uuid.Nil {
			key.ID = uuid.New()
		}
		c.Set("auth_method", "api_key")
		c.Set("api_key", key)
		c.Set("api_key_id", key.ID)
		c.Set("api_key_scopes", []string(key.Scopes))
		c.Set("token_kind", key.Kind)
		if key.UserID != nil {
			c.Set("user_id", *key.UserID)
		}
		c.Next()
	})
	r.POST("/api/v2/runner/register", h.Register)
	return r
}

func TestRegisterAuthz(t *testing.T) {
	f := setupAgentPrepFixture(t)
	sfx := uuid.NewString()[:8]
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "regauthz-" + sfx, Email: "regauthz-" + sfx + "@test.local"}
	if err := f.db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", owner.ID).Delete(&models.User{}) })
	r := f.registerRouter(owner.ID)
	org := f.orgA.String()

	refused := map[string]*models.APIKey{
		"a key with no scopes":         {Kind: models.APIKeyKindOrg, OrganizationID: &f.orgA, UserID: &owner.ID},
		"a wildcard key":               {Kind: models.APIKeyKindOrg, Scopes: models.StringArray{"*"}, OrganizationID: &f.orgA, UserID: &owner.ID},
		"a platform:admin user token":  {Kind: models.APIKeyKindUser, Scopes: models.StringArray{"platform:admin"}, UserID: &owner.ID},
		"an organization admin token":  {Kind: models.APIKeyKindOrg, Scopes: models.StringArray{"org:" + org + ":admin"}, OrganizationID: &f.orgA, UserID: &owner.ID},
		"a user token naming register": {Kind: models.APIKeyKindUser, Scopes: models.StringArray{"org:" + org + ":runner:register"}, UserID: &owner.ID},
		"a runner token":               {Kind: models.APIKeyKindOrg, Scopes: models.StringArray{"runner:" + f.runnerA1.ID.String() + ":heartbeat", "runner:" + f.runnerA1.ID.String() + ":jobs"}, OrganizationID: &f.orgA, UserID: &owner.ID},
		"a job token":                  {Kind: models.APIKeyKindJob, Scopes: models.StringArray{"job:ansible_job:" + uuid.NewString() + ":*"}, OrganizationID: &f.orgA},
	}
	for name, key := range refused {
		t.Run(name, func(t *testing.T) {
			f.keys["k"] = key
			runnerName := "regauthz-" + uuid.NewString()[:8]
			rec := runnerDo(t, r, "k", http.MethodPost, "/api/v2/runner/register", map[string]any{"agent_pool_id": f.poolA.String(), "name": runnerName, "tofu_version": "1.9.0"})
			if rec.Code != http.StatusForbidden {
				t.Errorf("register: status %d, want 403 (%s)", rec.Code, rec.Body.String())
			}
			var n int64
			f.db.Model(&models.Runner{}).Where("name = ?", runnerName).Count(&n)
			if n != 0 {
				t.Errorf("a refused registration left %d runner row(s)", n)
			}
		})
	}

	t.Run("an organization key carrying runner:register", func(t *testing.T) {
		key := &models.APIKey{Name: "regauthz-ok-" + sfx, Kind: models.APIKeyKindOrg, KeyHash: "x", KeyPrefix: "tfe-" + sfx[:4], Scopes: models.StringArray{"org:" + org + ":runner:register"}, OrganizationID: &f.orgA, UserID: &owner.ID}
		if err := f.db.Create(key).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
		f.keys["k"] = key
		runnerName := "regauthz-ok-" + uuid.NewString()[:8]
		rec := runnerDo(t, r, "k", http.MethodPost, "/api/v2/runner/register", map[string]any{"agent_pool_id": f.poolA.String(), "name": runnerName, "tofu_version": "1.9.0"})
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("register: status %d, want success (%s)", rec.Code, rec.Body.String())
		}
		var runner models.Runner
		if err := f.db.First(&runner, "name = ?", runnerName).Error; err != nil {
			t.Fatalf("no runner row after a successful registration: %v", err)
		}
		t.Cleanup(func() {
			f.db.Where("scopes::text LIKE ?", "%runner:"+runner.ID.String()+":%").Delete(&models.APIKey{})
			f.db.Where("id = ?", runner.ID).Delete(&models.Runner{})
		})
	})
}
