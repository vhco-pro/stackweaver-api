// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the hosted registration secret (#933, D9, AC69, AC65): the configured
// secret is stored at API start as one ownerless, organization-less key of kind hosted holding
// only its hash; a changed secret refuses the old value; Register with it creates one hosted runner
// with no organization and no pool and a hosted runner token, and re-registers it by name; no other
// key registers a hosted launcher. Each test uses its own secret name, so a deployment's real secret
// is never touched.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestHostedSecret

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func hostedTestSecret() string {
	return "tfe-" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
}

func TestHostedSecret_StoredAsAnOwnerlessHashAndRotated(t *testing.T) {
	db := setupAuthzTestDB(t)
	svc := apikey.NewService(repository.NewAPIKeyRepository(db), nil, nil, nil)
	name := "hosted-registration-test-" + uuid.NewString()[:8]
	t.Cleanup(func() { db.Where("kind = ? AND name = ?", models.APIKeyKindHosted, name).Delete(&models.APIKey{}) })

	first := hostedTestSecret()
	key, err := svc.UpsertHostedSecret(name, first)
	if err != nil {
		t.Fatal(err)
	}
	if key.UserID != nil || key.OrganizationID != nil || key.Kind != models.APIKeyKindHosted || key.KeyHash == first || !strings.HasPrefix(key.KeyHash, "$2") {
		t.Errorf("stored key = %+v, want an ownerless, organization-less hosted key holding a bcrypt hash", key)
	}
	again, err := svc.UpsertHostedSecret(name, first)
	if err != nil || again.ID != key.ID {
		t.Errorf("a second start with the same secret replaced the key (%v, %v)", again, err)
	}
	if _, err := svc.UpsertHostedSecret(name, "short"); err == nil {
		t.Error("a short secret was accepted")
	}

	second := hostedTestSecret()
	if _, err := svc.UpsertHostedSecret(name, second); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyAPIKey(first); err == nil {
		t.Error("the rotated-out secret still authenticates")
	}
	if got, err := svc.VerifyAPIKey(second); err != nil || !apikey.IsHostedRegistrationKey(got) {
		t.Errorf("the new secret does not authenticate as the hosted registration key: %v", err)
	}
	var n int64
	db.Model(&models.APIKey{}).Where("kind = ? AND name = ?", models.APIKeyKindHosted, name).Count(&n)
	if n != 1 {
		t.Errorf("%d hosted registration keys under one name, want 1", n)
	}
}

func TestHostedSecret_RegistersOneHostedRunner(t *testing.T) {
	f := setupAgentPrepFixture(t)
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	name := "hosted-registration-test-" + uuid.NewString()[:8]
	key, err := svc.UpsertHostedSecret(name, hostedTestSecret())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
	f.keys["hosted"] = key
	r := f.registerRouter(uuid.Nil)
	runnerName := "hosted-launcher-" + uuid.NewString()[:8]
	register := func(keyName string, body map[string]any) (int, string) {
		t.Helper()
		rec := runnerDo(t, r, keyName, http.MethodPost, "/api/v2/runner/register", body)
		var resp struct {
			RunnerID string `json:"runner_id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec.Code, resp.RunnerID
	}
	body := map[string]any{"name": runnerName, "hosted": true, "hosted_group": "eu-west", "engines": []string{"tofu"}, "driver": "kubernetes", "max_concurrent_jobs": 8}

	code, id := register("hosted", body)
	if code != http.StatusCreated {
		t.Fatalf("hosted register = %d", code)
	}
	t.Cleanup(func() {
		f.db.Where("scopes::text LIKE ?", "%runner:"+id+":%").Delete(&models.APIKey{})
		f.db.Where("id = ?", id).Delete(&models.Runner{})
	})
	var runner models.Runner
	if err := f.db.First(&runner, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	if runner.Kind != models.RunnerKindHosted || runner.OrganizationID != nil || runner.AgentPoolID != nil || runner.HostedGroup != "eu-west" || runner.Driver != "kubernetes" || runner.MaxConcurrentJobs != 8 {
		t.Errorf("hosted runner = %+v", runner)
	}
	var tokens []models.APIKey
	f.db.Where("scopes::text LIKE ?", "%runner:"+id+":%").Find(&tokens)
	if len(tokens) != 1 || tokens[0].Kind != models.APIKeyKindHosted || tokens[0].OrganizationID != nil || tokens[0].UserID != nil {
		t.Errorf("hosted runner tokens = %+v, want one ownerless hosted token", tokens)
	}

	// A restart re-registers the same row.
	if code, again := register("hosted", body); code != http.StatusOK || again != id {
		t.Errorf("re-register = %d %s, want 200 with the same runner %s", code, again, id)
	}
	var count int64
	f.db.Model(&models.Runner{}).Where("kind = ? AND name = ?", models.RunnerKindHosted, runnerName).Count(&count)
	if count != 1 {
		t.Errorf("%d hosted runners named %s, want 1", count, runnerName)
	}

	// The hosted runner token is of the same kind but cannot register; an organization key cannot
	// register a hosted launcher.
	f.keys["hostedrunner"] = &tokens[0]
	if code, _ := register("hostedrunner", body); code != http.StatusForbidden {
		t.Errorf("register with a hosted runner token = %d, want 403", code)
	}
	f.keys["org"] = &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindOrg, Scopes: models.StringArray{"org:" + f.orgA.String() + ":runner:register"}, OrganizationID: &f.orgA}
	if code, _ := register("org", body); code != http.StatusForbidden {
		t.Errorf("register a hosted launcher with an organization key = %d, want 403", code)
	}
}
