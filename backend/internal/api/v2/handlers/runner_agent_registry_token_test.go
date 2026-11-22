// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the per-job private-registry token (#933, D2, AC14): the artifacts a job
// token fetches carry a registry token for the platform's own registry host, minted for that job,
// readable for the job's organization's private modules only, and revoked with the job.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRegistryToken

//go:build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func TestTofuTokenEnvName(t *testing.T) {
	for host, want := range map[string]string{
		"app.stackweaver.sh": "TF_TOKEN_app_stackweaver_sh",
		"sw-api.vhco.pro":    "TF_TOKEN_sw__api_vhco_pro",
		"localhost:8103":     "TF_TOKEN_localhost:8103",
	} {
		if got := runnercontract.TofuTokenEnvName(host); got != want {
			t.Errorf("TofuTokenEnvName(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestRegistryToken_MintedPerJobAndScopedToItsOrganization(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.blobRouter(t, store)
	run := f.seedClaimedPlan(t)
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}

	arts, _ := artifactsAs(t, r, "job", run.ID, runnercontract.CapabilityBlob, map[string]string{runnercontract.ArtifactSequenceHeader: "1"})
	if arts.Registry == nil || len(arts.Registry.Hosts) != 1 || arts.Registry.Hosts[0].Host != "registry.example.test" || arts.Registry.Hosts[0].Token == "" {
		t.Fatalf("registry block = %+v, want one token for registry.example.test", arts.Registry)
	}
	token := arts.Registry.Hosts[0].Token

	key, err := svc.VerifyAPIKey(token)
	if err != nil {
		t.Fatalf("the registry token does not verify: %v", err)
	}
	if key.Kind != models.APIKeyKindJob || key.UserID != nil || key.OrganizationID == nil || *key.OrganizationID != f.orgA {
		t.Fatalf("registry token: kind %q owner %v org %v", key.Kind, key.UserID, key.OrganizationID)
	}
	if key.AgentPoolID == nil || *key.AgentPoolID != f.poolA {
		t.Fatalf("registry token pool = %v, want the run's pool %s", key.AgentPoolID, f.poolA)
	}

	// The registry protocol's read check accepts it for organization A's private artifacts and
	// for no other organization's.
	authSvc := auth.NewService(repository.NewUserRepository(f.db))
	authSvc.SetAPIKeyService(svc)
	orgRepo := repository.NewOrganizationRepository(f.db)
	read := func(org string) bool {
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/modules/x", nil)
		c.Request.Header.Set("Authorization", "Bearer "+token)
		id := f.orgA
		if org == "b" {
			id = f.runnerB1.OrgID()
		}
		return authorizeRegistryRead(c, authSvc, orgRepo, nil, id, false)
	}
	if !read("a") {
		t.Error("the registry token was refused on its own organization's private registry")
	}
	if read("b") {
		t.Error("the registry token read another organization's private registry")
	}

	// A registry token without its job's pool, as one minted before registry tokens carried it,
	// cannot be traced to its launcher and is refused.
	if err := f.db.Model(&models.APIKey{}).Where("id = ?", key.ID).Update("agent_pool_id", nil).Error; err != nil {
		t.Fatal(err)
	}
	if read("a") {
		t.Error("a registry token without its job's pool read its organization's private registry")
	}

	// A second fetch replaces the job's registry token rather than adding one.
	second, _ := artifactsAs(t, r, "job", run.ID, runnercontract.CapabilityBlob, map[string]string{runnercontract.ArtifactSequenceHeader: "2"})
	if second.Registry == nil || len(second.Registry.Hosts) != 1 || second.Registry.Hosts[0].Token == "" {
		t.Fatal("replacement did not return a registry credential")
	}
	var n int64
	if err := f.db.Model(&models.APIKey{}).Where("scopes::text LIKE ?", "%job-registry:tofu_run:"+run.ID+"%").Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("registry tokens for the job after two fetches = %d, want 1", n)
	}

	// A run without its own pool is authorized through its workspace's, and its registry token
	// carries that pool.
	var ws models.Workspace
	if err := f.db.First(&ws, "id = ?", run.WorkspaceID).Error; err != nil || ws.AgentPoolID == nil {
		t.Fatalf("the run's workspace has no pool: %v", err)
	}
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("agent_pool_id", nil).Error; err != nil {
		t.Fatal(err)
	}
	arts, _ = artifactsAs(t, r, "job", run.ID, runnercontract.CapabilityBlob, map[string]string{runnercontract.ArtifactSequenceHeader: "3"})
	if arts.Registry == nil || len(arts.Registry.Hosts) != 1 {
		t.Fatalf("registry block for a run without its own pool = %+v, want one token", arts.Registry)
	}
	fallback, err := svc.VerifyAPIKey(arts.Registry.Hosts[0].Token)
	if err != nil || fallback.AgentPoolID == nil || *fallback.AgentPoolID != *ws.AgentPoolID {
		t.Fatalf("registry token of a run without its own pool: pool %v (err %v), want the workspace's %s", fallback, err, *ws.AgentPoolID)
	}
	token = arts.Registry.Hosts[0].Token

	// Revocation with the job's tokens removes it.
	if err := svc.RevokeJobTokens(models.JobTypeTofuRun, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyAPIKey(second.Registry.Hosts[0].Token); err == nil {
		t.Error("the registry token survived the revocation of the job's tokens")
	}
}
