// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What GET /api/v2/runner/jobs/:id/artifacts sends a self-hosted runner for a job with a GCP
// credential (#912). The variables a Google module authenticates with name a file, and only the
// runner knows where it wrote it, so the API's half of the contract is to send the key as
// content and to set none of those variables itself: a GCP_AUTH_KIND of the API's own would
// arrive beside the runner's and one of the two would be wrong. The runner's half, from this
// document to ansible-playbook's environment, is TestRunAnsiblePlaybook_GCPCredential in
// cmd/ansible-runner.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Every row is created under
// a unique name and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerJobArtifacts_GCPCredential

//go:build integration

package handlers

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

func TestRunnerJobArtifacts_GCPCredential(t *testing.T) {
	f := setupAgentPrepFixture(t)
	cryptoService, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("creating the crypto service: %v", err)
	}
	// Stands in for a service account file: the handler decrypts and forwards it unread, and it is
	// deliberately not shaped like a real one, which the secret scans match on sight.
	const serviceAccount = `{"fixture": "stands in for a service account file"}`
	encrypted, err := cryptoService.Encrypt(serviceAccount)
	if err != nil {
		t.Fatalf("encrypting the service account: %v", err)
	}
	credential := &models.AnsibleCredential{
		ID: uuid.New(), OrganizationID: f.orgA, Name: "artgcp-" + uuid.NewString()[:8],
		Type: models.CredentialTypeGCP, GCPServiceAccount: encrypted,
	}
	if err := f.db.Create(credential).Error; err != nil {
		t.Fatalf("seeding the credential: %v", err)
	}
	// Registered before the job is seeded, so it runs after the job's own cleanup.
	t.Cleanup(func() { f.db.Where("id = ?", credential.ID).Delete(&models.AnsibleCredential{}) })
	job := f.seedJob(t, nil, nil)
	t.Cleanup(func() { f.db.Exec("DELETE FROM ansible_job_credentials WHERE ansible_job_id = ?", job.ID) })
	if err := f.db.Exec("INSERT INTO ansible_job_credentials (ansible_job_id, ansible_credential_id) VALUES (?, ?)", job.ID, credential.ID).Error; err != nil {
		t.Fatalf("writing the job credential row: %v", err)
	}

	inventoryRepo := repository.NewAnsibleInventoryRepository(f.db)
	h := &RunnerAgentHandler{
		db:               f.db,
		ansibleJobRepo:   repository.NewAnsibleJobRepository(f.db),
		inventoryRepo:    inventoryRepo,
		credentialRepo:   repository.NewAnsibleCredentialRepository(f.db),
		cryptoService:    cryptoService,
		inventoryService: ansible.NewInventoryService(inventoryRepo, repository.NewOrganizationRepository(f.db)),
	}
	router := f.router(func(authed *gin.RouterGroup) {
		authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts)
	})

	doc := getArtifactsAnnouncing(t, router, job.ID, "")

	if got := doc["gcp_service_account"]; got != serviceAccount {
		t.Errorf("gcp_service_account = %v, want the decrypted service account", got)
	}
	env, _ := doc["environment_vars"].(map[string]any)
	for name := range env {
		if strings.HasPrefix(name, "GCP_") || strings.HasPrefix(name, "GOOGLE_") {
			t.Errorf("environment_vars sets %s: the runner decides the GCP variables, from the file it writes", name)
		}
	}
}
