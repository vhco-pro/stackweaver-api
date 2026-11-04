// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test: a customer launcher placing pods is asked, on its heartbeat, to create the
// create-mode pull Secrets of its pool with their credential, and never one declared outside
// Stackweaver or a reference (#933, D8, AC49a, AC49b).
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set.

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

func TestHeartbeat_EnsuresThePoolsPullSecrets(t *testing.T) {
	f := setupAgentPrepFixture(t)
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cs.Encrypt("pull-s3cret")
	if err != nil {
		t.Fatal(err)
	}
	cred := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: f.orgA, Name: "pull-" + uuid.NewString()[:6], Type: models.CredentialTypeRegistry, Username: "robot", Password: enc}
	created := &models.PullSecret{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "ghcr", SecretName: "sw-pull-ghcr", Registry: "ghcr.io", RegistryCredentialID: &cred.ID}
	handedOver := &models.PullSecret{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "flux", SecretName: "sw-pull-flux", Registry: "quay.io", RegistryCredentialID: &cred.ID, DeclaredExternally: true, ExternalManager: "Flux"}
	referenced := &models.PullSecret{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "git", SecretName: "registry-git", Registry: "registry.example", Reference: true}
	for _, o := range []any{cred, created, handedOver, referenced} {
		if err := f.db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Where("agent_pool_id = ?", f.poolA).Delete(&models.PullSecret{})
		f.db.Where("agent_pool_id = ?", f.poolA).Delete(&models.PoolObjectReport{})
		f.db.Where("id = ?", cred.ID).Delete(&models.AnsibleCredential{})
	})
	if err := f.db.Model(&models.Runner{}).Where("id = ?", f.runnerA1.ID).Update("driver", "kubernetes").Error; err != nil {
		t.Fatal(err)
	}
	h := &RunnerAgentHandler{db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), cryptoService: cs}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/heartbeat", middleware.RequireRunnerToken(), h.Heartbeat)
	})
	rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/heartbeat", runnercontract.HeartbeatRequest{RunnerID: f.runnerA1.ID.String(), Status: "online"})
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", rec.Code, rec.Body.String())
	}
	var resp runnercontract.HeartbeatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var secrets []runnercontract.EnsureObject
	for _, o := range resp.Ensure {
		if o.Kind == "Secret" {
			secrets = append(secrets, o)
		}
	}
	if len(secrets) != 1 {
		t.Fatalf("pull Secrets to create = %+v, want only the create-mode one Stackweaver still manages", secrets)
	}
	s := secrets[0]
	if s.Name != "sw-pull-ghcr" || s.Registry != "ghcr.io" || s.Username != "robot" || s.Password != "pull-s3cret" || s.PoolID != f.poolA.String() {
		t.Errorf("pull Secret to create = %+v", s)
	}
}
