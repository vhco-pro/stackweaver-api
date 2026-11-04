// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The per-run identity a job's artifacts carry (#933, D8, AC37): a stable subject for every kind of
// launch, and no job handed its artifacts without an identity its organization configured.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunnerIdentity

//go:build integration

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/oidc"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// identityRouter is the artifacts route over a handler holding the OIDC services. configured seeds
// all four providers on the fixture's organization.
func identityRouter(t *testing.T, f *agentPrepFixture, configured bool) *gin.Engine {
	t.Helper()
	t.Setenv("DEV_INSECURE_KEY", "1")
	signingKey, err := oidc.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if configured {
		sfx := uuid.NewString()[:8]
		azure := &models.AzureOIDCConfiguration{ClientID: "az-" + sfx, SubscriptionID: "sub", TenantID: "tenant", OrganizationID: f.orgA}
		aws := &models.AWSOIDCConfiguration{RoleARN: "arn:aws:iam::123456789012:role/sw-" + sfx, OrganizationID: f.orgA}
		gcp := &models.GCPOIDCConfiguration{ServiceAccountEmail: "sw-" + sfx + "@p.iam.gserviceaccount.com", ProjectNumber: "42", WorkloadProviderName: "projects/42/locations/global/workloadIdentityPools/p/providers/sw", OrganizationID: f.orgA}
		vault := &models.VaultOIDCConfiguration{Address: "https://vault.example.test:8200", RoleName: "sw-" + sfx, OrganizationID: f.orgA}
		for _, cfg := range []any{azure, aws, gcp, vault} {
			if err := f.db.Create(cfg).Error; err != nil {
				t.Fatalf("seeding %T: %v", cfg, err)
			}
		}
		t.Cleanup(func() {
			f.db.Where("id = ?", azure.ID).Delete(&models.AzureOIDCConfiguration{})
			f.db.Where("id = ?", aws.ID).Delete(&models.AWSOIDCConfiguration{})
			f.db.Where("id = ?", gcp.ID).Delete(&models.GCPOIDCConfiguration{})
			f.db.Where("id = ?", vault.ID).Delete(&models.VaultOIDCConfiguration{})
		})
	}
	h := &RunnerAgentHandler{
		db: f.db, ansibleJobRepo: repository.NewAnsibleJobRepository(f.db), playbookRepo: repository.NewAnsiblePlaybookRepository(f.db),
		vcsRegistry: vcs.NewProviderRegistry(nil, nil, nil, nil), storageClient: newSnapshotStore(),
	}
	h.SetOIDCServices(repository.NewAzureOIDCConfigurationRepository(f.db), repository.NewAWSOIDCConfigurationRepository(f.db),
		repository.NewGCPOIDCConfigurationRepository(f.db), repository.NewVaultOIDCConfigurationRepository(f.db),
		oidc.NewTokenService(signingKey, "https://stackweaver.example.com"))
	return f.router(func(authed *gin.RouterGroup) { authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts) })
}

// seedTemplate is a job template of the fixture's project.
func seedTemplate(t *testing.T, f *agentPrepFixture, name string, playbookID uuid.UUID) *models.AnsibleJobTemplate {
	t.Helper()
	tpl := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: f.projectA, PlaybookID: playbookID, InventoryID: f.inventory, Name: name}
	if err := f.db.Create(tpl).Error; err != nil {
		t.Fatalf("seeding the template: %v", err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", tpl.ID).Delete(&models.AnsibleJobTemplate{}) })
	return tpl
}

func pendingOnPool(f *agentPrepFixture, job models.AnsibleJob) *models.AnsibleJob {
	job.Status = models.AnsibleJobStatusPending
	job.AgentPoolID = &f.poolA
	return &job
}

func tokenSubject(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Sub
}

// TestRunnerIdentity_AnsibleSubjectIsStableAcrossLaunches pins that every job kind the platform
// names with a colon gets its tokens, under a subject a cloud trust can name exactly.
func TestRunnerIdentity_AnsibleSubjectIsStableAcrossLaunches(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := identityRouter(t, f, true)
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})
	template := "deploy-" + uuid.NewString()[:8]
	tpl := seedTemplate(t, f, template, pb.ID)

	var project models.Project
	if err := f.db.First(&project, "id = ?", f.projectA).Error; err != nil {
		t.Fatal(err)
	}
	var org models.Organization
	if err := f.db.First(&org, "id = ?", f.orgA).Error; err != nil {
		t.Fatal(err)
	}
	subject := func(name string) string {
		return "organization:" + org.Name + ":project:" + project.Name + ":job:" + name + ":run"
	}

	for _, tt := range []struct {
		name string
		job  models.AnsibleJob
		want string
	}{
		{"ad hoc", models.AnsibleJob{JobType: models.AnsibleJobTypeAdHoc, Module: "shell", ModuleArgs: "true", Name: "Ad hoc: shell"}, "adhoc-shell"},
		{"from a template", models.AnsibleJob{PlaybookID: &pb.ID, TemplateID: &tpl.ID, Name: template + " - 2026-11-02 15:04:05"}, template},
		{"template relaunch", models.AnsibleJob{PlaybookID: &pb.ID, TemplateID: &tpl.ID, Name: "Relaunch: " + template + " - 2026-11-02 15:04:05"}, template},
		{"named job relaunch", models.AnsibleJob{PlaybookID: &pb.ID, Name: "Relaunch: patch-web"}, "patch-web"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			job := f.seedJobRow(t, pendingOnPool(f, tt.job))
			env, _ := getArtifacts(t, r, job.ID)["environment_vars"].(map[string]any)
			for _, k := range []string{"AZURE_FEDERATED_TOKEN", "AWS_WEB_IDENTITY_TOKEN", "GCP_OIDC_RAW_TOKEN", "VAULT_OIDC_RAW_TOKEN"} {
				token, _ := env[k].(string)
				if token == "" {
					t.Fatalf("the artifacts lack %s", k)
				}
				if got := tokenSubject(t, token); got != subject(tt.want) {
					t.Errorf("%s subject = %q, want %q", k, got, subject(tt.want))
				}
			}
		})
	}
}

// TestRunnerIdentity_AJobNeverRunsWithoutItsIdentity pins that both engines refuse the artifacts,
// naming the reason, when an identity the organization configured cannot be minted. A job left to
// run would act as whatever identity its machine has.
func TestRunnerIdentity_AJobNeverRunsWithoutItsIdentity(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := identityRouter(t, f, true)
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})

	refused := func(t *testing.T, id, wantInDetail string) {
		t.Helper()
		rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+id+"/artifacts")
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (%s)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "per-run identity") || !strings.Contains(body, wantInDetail) {
			t.Errorf("the refusal does not give the reason: %s", body)
		}
		if strings.Contains(body, "eyJ") {
			t.Errorf("the refusal carries a token: %s", body)
		}
	}

	t.Run("an Ansible template whose name cannot be a subject", func(t *testing.T) {
		name := "deploy:" + uuid.NewString()[:8]
		tpl := seedTemplate(t, f, name, pb.ID)
		job := f.seedJobRow(t, pendingOnPool(f, models.AnsibleJob{PlaybookID: &pb.ID, TemplateID: &tpl.ID, Name: "run"}))
		refused(t, job.ID.String(), name)
	})
	t.Run("an Ansible job whose own name cannot be a subject", func(t *testing.T) {
		job := f.seedJobRow(t, pendingOnPool(f, models.AnsibleJob{PlaybookID: &pb.ID, Name: "patch:web"}))
		refused(t, job.ID.String(), "patch:web")
	})
	t.Run("an OpenTofu run whose project name cannot be a subject", func(t *testing.T) {
		var project models.Project
		if err := f.db.First(&project, "id = ?", f.projectA).Error; err != nil {
			t.Fatal(err)
		}
		name := "bad:" + project.Name
		if err := f.db.Model(&models.Project{}).Where("id = ?", project.ID).Update("name", name).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.db.Model(&models.Project{}).Where("id = ?", project.ID).Update("name", project.Name) })
		run := f.seedRun(t, f.runnerA1)
		refused(t, run.ID, name)
	})
}

// TestRunnerIdentity_NoConfigurationNoRefusal pins the other side: an organization that configured
// no identity runs the same jobs as before, whatever their names.
func TestRunnerIdentity_NoConfigurationNoRefusal(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r := identityRouter(t, f, false)
	pb := f.seedPlaybook(t, playbookSpec{noVCS: true})
	job := f.seedJobRow(t, pendingOnPool(f, models.AnsibleJob{PlaybookID: &pb.ID, Name: "Relaunch: patch:web"}))
	if rec := runnerGet(t, r, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}
