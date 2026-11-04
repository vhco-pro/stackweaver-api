// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the pull-credential route (#933, D6, D8, AC3): a run image's registry
// credential is served, decrypted, to a launcher of the image's organization and to a hosted
// launcher while it holds that organization's work, and to nobody else: not a job token, not
// another organization's launcher, not an idle hosted launcher. An image pulled without a
// credential, or whose credential is gone, answers 404.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Rows are created under unique
// names and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestPullCredential

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

type pullCredentialFixture struct {
	*agentPrepFixture
	r      *gin.Engine
	svc    *apikey.Service
	cs     *crypto.CryptoService
	hosted *models.Runner
}

func setupPullCredentialFixture(t *testing.T) *pullCredentialFixture {
	t.Helper()
	f := setupAgentPrepFixture(t)
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	hosted := &models.Runner{ID: uuid.New(), Kind: models.RunnerKindHosted, HostedGroup: "pullcred-" + sfx, Name: "pullcred-hosted-" + sfx, Status: models.RunnerStatusOnline, MaxConcurrentJobs: 2, RunnerType: models.RunnerTypeTofu}
	if err := f.db.Create(hosted).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", hosted.ID).Delete(&models.Runner{}) })
	f.keys["hosted"] = &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindHosted, Scopes: models.StringArray{"runner:" + hosted.ID.String() + ":heartbeat", "runner:" + hosted.ID.String() + ":jobs"}}

	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	h := &RunnerAgentHandler{
		db: f.db, apiKeyService: svc, runnerRepo: repository.NewRunnerRepository(f.db),
		jobExecRepo: repository.NewRunnerJobExecutionRepository(f.db), ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		cryptoService: cs,
	}
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/images/:id/pull-credential", middleware.RequireRunnerToken(), h.GetPullCredential)
	})
	return &pullCredentialFixture{agentPrepFixture: f, r: r, svc: svc, cs: cs, hosted: hosted}
}

// seedImage stores a run image of organization A on registry.example.com, pulled with a registry
// credential holding password when withCredential is set.
func (f *pullCredentialFixture) seedImage(t *testing.T, withCredential bool, password string) (*models.RunImage, *models.AnsibleCredential) {
	t.Helper()
	return f.seedImageAs(t, uuid.New(), withCredential, password)
}

// seedImageWithID is seedImage with a credential, under a chosen id.
func (f *pullCredentialFixture) seedImageWithID(t *testing.T, id uuid.UUID, password string) (*models.RunImage, *models.AnsibleCredential) {
	t.Helper()
	return f.seedImageAs(t, id, true, password)
}

func (f *pullCredentialFixture) seedImageAs(t *testing.T, id uuid.UUID, withCredential bool, password string) (*models.RunImage, *models.AnsibleCredential) {
	t.Helper()
	sfx := uuid.NewString()[:8]
	img := &models.RunImage{ID: id, OrganizationID: f.orgA, Name: "pullcred-img-" + sfx, Kind: models.RunImageKindTofu, Image: "registry.example.com/acme/tofu:1." + sfx}
	var cred *models.AnsibleCredential
	if withCredential {
		enc, err := f.cs.Encrypt(password)
		if err != nil {
			t.Fatal(err)
		}
		cred = &models.AnsibleCredential{ID: uuid.New(), OrganizationID: f.orgA, Name: "pullcred-" + sfx, Type: models.CredentialTypeRegistry, Username: "robot", Password: enc}
		if err := f.db.Create(cred).Error; err != nil {
			t.Fatal(err)
		}
		img.RegistryCredentialID = &cred.ID
		t.Cleanup(func() { f.db.Where("id = ?", cred.ID).Delete(&models.AnsibleCredential{}) })
	}
	if err := f.db.Create(img).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", img.ID).Delete(&models.RunImage{}) })
	return img, cred
}

func (f *pullCredentialFixture) pull(t *testing.T, key string, img *models.RunImage) (int, runnercontract.PullCredential) {
	t.Helper()
	rec := runnerDo(t, f.r, key, http.MethodGet, "/api/v2/runner/images/"+img.ID.String()+"/pull-credential", nil)
	var pc runnercontract.PullCredential
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &pc); err != nil {
			t.Fatalf("decoding the pull credential: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, pc
}

func TestPullCredential_TheImagesOrganizationsRunnerGetsTheDecryptedPassword(t *testing.T) {
	f := setupPullCredentialFixture(t)
	img, _ := f.seedImage(t, true, "s3cret-registry-password")
	// A launcher that declared the job-token capability still pulls with its runner token.
	f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken)

	code, pc := f.pull(t, "a1", img)
	if code != http.StatusOK {
		t.Fatalf("pull credential for organization A's runner: status %d, want 200", code)
	}
	if pc.Registry != "registry.example.com" || pc.Username != "robot" || pc.Password != "s3cret-registry-password" {
		t.Errorf("pull credential = %+v, want registry.example.com robot and the decrypted password", pc)
	}
}

func TestPullCredential_RefusedToAJobToken(t *testing.T) {
	f := setupPullCredentialFixture(t)
	img, _ := f.seedImage(t, true, "s3cret")
	run := f.seedRun(t, f.runnerA1)
	if code, _ := f.mintJobToken(t, f.r, f.svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if code, pc := f.pull(t, "job", img); code != http.StatusForbidden {
		t.Errorf("pull credential with a job token: status %d (%+v), want 403", code, pc)
	}

	// An image whose id is the job's own id gets past RunnerAuth's same-job check, so only the
	// route's runner-token guard stands between the job token and the credential.
	job := f.seedJob(t, nil, f.runnerA1)
	if code, _ := f.mintJobToken(t, f.r, f.svc, "a1", job.ID.String(), "ansible-job"); code != http.StatusOK {
		t.Fatalf("mint for the Ansible job: %d", code)
	}
	sameID, _ := f.seedImageWithID(t, job.ID, "s3cret-same-id")
	if code, pc := f.pull(t, "ansible-job", sameID); code != http.StatusForbidden {
		t.Errorf("pull credential with a job token whose job id is the image id: status %d (%+v), want 403", code, pc)
	}
}

func TestPullCredential_RefusedToAnotherOrganizationsRunner(t *testing.T) {
	f := setupPullCredentialFixture(t)
	img, _ := f.seedImage(t, true, "s3cret")
	if code, pc := f.pull(t, "b1", img); code != http.StatusForbidden {
		t.Errorf("pull credential for organization B's runner: status %d (%+v), want 403", code, pc)
	}
}

func TestPullCredential_HostedRunnerOnlyWhileItHoldsTheOrganizationsWork(t *testing.T) {
	f := setupPullCredentialFixture(t)
	img, _ := f.seedImage(t, true, "s3cret-hosted")

	if code, pc := f.pull(t, "hosted", img); code != http.StatusForbidden {
		t.Fatalf("pull credential for a hosted runner holding no work of organization A: status %d (%+v), want 403", code, pc)
	}

	run := f.seedRun(t, f.hosted) // organization A's run, reserved by the hosted runner
	code, pc := f.pull(t, "hosted", img)
	if code != http.StatusOK || pc.Password != "s3cret-hosted" {
		t.Fatalf("pull credential for a hosted runner holding organization A's run: status %d %+v, want 200 with the password", code, pc)
	}

	// Once that run is finished the hosted runner holds nothing of the organization again.
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("status", models.RunStatusApplied).Error; err != nil {
		t.Fatal(err)
	}
	if code, _ := f.pull(t, "hosted", img); code != http.StatusForbidden {
		t.Errorf("pull credential after the hosted runner's run finished: status %d, want 403", code)
	}
}

func TestPullCredential_NoCredentialOrADeletedOneIsNotFound(t *testing.T) {
	f := setupPullCredentialFixture(t)

	bare, _ := f.seedImage(t, false, "")
	if code, _ := f.pull(t, "a1", bare); code != http.StatusNotFound {
		t.Errorf("pull credential of an image pulled without one: status %d, want 404", code)
	}

	img, cred := f.seedImage(t, true, "s3cret")
	if err := f.db.Where("id = ?", cred.ID).Delete(&models.AnsibleCredential{}).Error; err != nil {
		t.Fatal(err)
	}
	if code, _ := f.pull(t, "a1", img); code != http.StatusNotFound {
		t.Errorf("pull credential whose credential was deleted: status %d, want 404", code)
	}

	if rec := runnerDo(t, f.r, "a1", http.MethodGet, "/api/v2/runner/images/"+uuid.NewString()+"/pull-credential", nil); rec.Code != http.StatusNotFound {
		t.Errorf("pull credential of an unknown image: status %d, want 404", rec.Code)
	}
}
