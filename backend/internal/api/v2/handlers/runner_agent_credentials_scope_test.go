// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What GET /api/v2/runner/jobs/:id/artifacts sends a self-hosted runner for a job whose
// credential set names a credential of another organization (#915). The API refuses to store
// such a set, but a job row written before it did may hold one, and this endpoint is where the
// credential is decrypted for an agent: it must not be.
//
// The defect this test was written against: the handler listed the identifiers in the job's
// credential set and decrypted each one, whatever organization it belonged to, so the runner of
// one organization received the other's keys in the response.
//
// This is the agent-mode half. The platform runner reads the same set from the database; see
// TestPrepareCredentials_CredentialOfAnotherOrganization in cmd/ansible-runner.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Every row is created under
// a unique name and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerJobArtifacts_Credential

//go:build integration

package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

func TestRunnerJobArtifacts_CredentialOfAnotherOrganization(t *testing.T) {
	f := setupAgentPrepFixture(t)
	cryptoService, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("creating the crypto service: %v", err)
	}
	encrypt := func(plaintext string) string {
		t.Helper()
		encrypted, err := cryptoService.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypting %q: %v", plaintext, err)
		}
		return encrypted
	}
	sfx := uuid.NewString()[:8]
	otherOrg := f.runnerB1.OrganizationID
	// Everything of the other organization that could reach the runner, each a distinct string.
	const (
		otherAWSSecret = "aws-secret-of-the-other-organization"
		otherPassword  = "password-of-the-other-organization"
		otherUser      = "user-of-the-other-organization"
		ownAWSSecret   = "aws-secret-of-its-own-organization"
	)
	otherAWS := &models.AnsibleCredential{
		ID: uuid.New(), OrganizationID: otherOrg, Name: "artcred-aws-b-" + sfx, Type: models.CredentialTypeAWSAccessKey,
		AWSAccessKeyID: encrypt("AKIAOTHERORGANIZATION"), AWSSecretAccessKey: encrypt(otherAWSSecret),
	}
	otherMachine := &models.AnsibleCredential{
		ID: uuid.New(), OrganizationID: otherOrg, Name: "artcred-ssh-b-" + sfx, Type: models.CredentialTypeMachineSSH,
		Username: otherUser, Password: encrypt(otherPassword),
	}
	ownAWS := &models.AnsibleCredential{
		ID: uuid.New(), OrganizationID: f.orgA, Name: "artcred-aws-a-" + sfx, Type: models.CredentialTypeAWSAccessKey,
		AWSAccessKeyID: encrypt("AKIAOWNORGANIZATION"), AWSSecretAccessKey: encrypt(ownAWSSecret),
	}
	credentials := []*models.AnsibleCredential{otherAWS, otherMachine, ownAWS}
	for _, row := range credentials {
		if err := f.db.Create(row).Error; err != nil {
			t.Fatalf("seeding the credential %s: %v", row.Name, err)
		}
	}
	// Registered before the jobs are seeded, so it runs after their cleanup.
	t.Cleanup(func() {
		for _, row := range credentials {
			f.db.Where("id = ?", row.ID).Delete(&models.AnsibleCredential{})
		}
	})
	// seedJobWith inserts an ad hoc job of organization A's pool and writes its credential set
	// directly: the shape of a job row stored before a launch checked the set.
	seedJobWith := func(t *testing.T, set ...*models.AnsibleCredential) *models.AnsibleJob {
		t.Helper()
		job := f.seedJob(t, nil, nil)
		t.Cleanup(func() { f.db.Exec("DELETE FROM ansible_job_credentials WHERE ansible_job_id = ?", job.ID) })
		for _, credential := range set {
			if err := f.db.Exec("INSERT INTO ansible_job_credentials (ansible_job_id, ansible_credential_id) VALUES (?, ?)", job.ID, credential.ID).Error; err != nil {
				t.Fatalf("writing the job credential row: %v", err)
			}
		}
		return job
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

	t.Run("a job holding credentials of another organization gets none of them", func(t *testing.T) {
		job := seedJobWith(t, ownAWS, otherAWS, otherMachine)
		rec := runnerGet(t, router, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts")
		body := rec.Body.String()
		for what, secret := range map[string]string{
			"AWS secret": otherAWSSecret, "password": otherPassword, "user name": otherUser,
			"AWS credential id": otherAWS.ID.String(), "machine credential id": otherMachine.ID.String(),
		} {
			if strings.Contains(body, secret) {
				t.Errorf("the response carries the other organization's %s", what)
			}
		}
		if rec.Code == http.StatusOK {
			t.Errorf("status = 200, want the job refused: it would run without the credentials it names")
		}
		var stored models.AnsibleJob
		if err := f.db.First(&stored, "id = ?", job.ID).Error; err != nil {
			t.Fatalf("reloading the job: %v", err)
		}
		if stored.Status != models.AnsibleJobStatusFailed {
			t.Errorf("the job is %q, want failed", stored.Status)
		}
	})
	t.Run("a job holding its organization's credential gets it", func(t *testing.T) {
		job := seedJobWith(t, ownAWS)
		doc := getArtifactsAnnouncing(t, router, job.ID, "")
		env, _ := doc["environment_vars"].(map[string]any)
		if got := env["AWS_SECRET_ACCESS_KEY"]; got != ownAWSSecret {
			t.Errorf("AWS_SECRET_ACCESS_KEY = %v, want its own organization's secret", got)
		}
	})
}
