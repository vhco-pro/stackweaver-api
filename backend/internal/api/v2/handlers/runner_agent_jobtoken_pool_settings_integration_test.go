// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test: the job token carries the job's pool settings (#933, D4, AC24, AC25).
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestJobToken_CarriesThePoolSettings

//go:build integration

package handlers

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// A launcher places a job with its pool's limits and keeps it on failure as long as its pool says,
// so the token it mints for the job carries them: a hosted launcher serves many pools.
func TestJobToken_CarriesThePoolSettings(t *testing.T) {
	f := setupAgentPrepFixture(t)
	if err := f.db.Model(&models.AgentPool{}).Where("id = ?", f.poolA).Updates(map[string]any{
		"keep_failed_jobs_for": 3600, "cpu_limit": "1500m", "memory_limit": "2Gi", "limits_required": true,
		"local_readthrough_disabled": true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	r, svc := f.jobTokenRouter()

	job := f.seedJob(t, nil, f.runnerA1)
	code, tok := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job")
	if code != http.StatusOK {
		t.Fatalf("minting = %d", code)
	}
	p := tok.Pool
	if p == nil || p.KeepFailedForSeconds != 3600 || p.CPULimit != "1500m" || p.MemoryLimit != "2Gi" || !p.LimitsRequired || !p.NoLocalReadthrough {
		t.Errorf("pool settings in the token = %+v, want keep 3600s, 1500m CPU, 2Gi memory, limits required, no local read-through", p)
	}
}

// The job token carries the job's identity binding, resolved by the level rule, for a driver
// that places pods; a binding of another pool refuses the token (#933, D8, AC43, AC44).
func TestJobToken_CarriesTheIdentityBinding(t *testing.T) {
	f := setupAgentPrepFixture(t)
	offered := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "deploy-" + uuid.NewString()[:6], Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-deploy", PerJobSA: true, Annotations: models.JSONB{"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/deploy"}}
	other := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA, Name: "idother-" + uuid.NewString()[:6], OrganizationScoped: true}
	foreign := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: other.ID, Name: "elsewhere", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-elsewhere"}
	for _, o := range []any{offered, other, foreign} {
		if err := f.db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("identity_binding_id", nil)
		f.db.Where("id IN ?", []uuid.UUID{offered.ID, foreign.ID}).Delete(&models.IdentityBinding{})
		f.db.Where("id = ?", other.ID).Delete(&models.AgentPool{})
	})
	r, svc := f.jobTokenRouter()

	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("identity_binding_id", offered.ID).Error; err != nil {
		t.Fatal(err)
	}
	job := f.seedJob(t, nil, f.runnerA1)
	code, tok := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job")
	if code != http.StatusOK {
		t.Fatalf("minting = %d", code)
	}
	id := tok.Identity
	if id == nil || id.BindingID != offered.ID.String() || id.Mechanism != "aws-irsa" || id.ServiceAccount != "sw-deploy" || !id.PerJob || id.Annotations["eks.amazonaws.com/role-arn"] == "" {
		t.Errorf("identity in the token = %+v", id)
	}
	var stored models.AnsibleJob
	f.db.First(&stored, "id = ?", job.ID)
	if stored.Placement.IdentityBindingID == nil || *stored.Placement.IdentityBindingID != offered.ID {
		t.Errorf("the placement does not record the binding: %+v", stored.Placement)
	}

	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("identity_binding_id", foreign.ID).Error; err != nil {
		t.Fatal(err)
	}
	job2 := f.seedJob(t, nil, f.runnerA1)
	if code, _ := f.mintJobToken(t, r, svc, "a1", job2.ID.String(), "job2"); code != http.StatusConflict {
		t.Errorf("minting for a job whose binding its pool does not offer = %d, want 409", code)
	}
}

// A job whose run image's registry has a pull Secret in the job's pool carries its name, so a
// launcher placing pods uses it rather than a per-job Secret (#933, D8, AC48).
func TestJobToken_CarriesThePoolsPullSecret(t *testing.T) {
	f := setupAgentPrepFixture(t)
	img := &models.RunImage{ID: uuid.New(), OrganizationID: f.orgA, Name: "pull-img-" + uuid.NewString()[:6], Kind: "ansible", Image: "ghcr.io/acme/ee:2"}
	pull := &models.PullSecret{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "ghcr", SecretName: "registry-ghcr", Registry: "ghcr.io", Reference: true}
	for _, o := range []any{img, pull} {
		if err := f.db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("ansible_run_image_id", nil)
		f.db.Where("id = ?", pull.ID).Delete(&models.PullSecret{})
		f.db.Where("id = ?", img.ID).Delete(&models.RunImage{})
	})
	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("ansible_run_image_id", img.ID).Error; err != nil {
		t.Fatal(err)
	}
	r, svc := f.jobTokenRouter()
	job := f.seedJob(t, nil, f.runnerA1)
	code, tok := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job")
	if code != http.StatusOK {
		t.Fatalf("minting = %d", code)
	}
	if tok.Image == nil || tok.Image.PullSecret != "registry-ghcr" {
		t.Errorf("image in the token = %+v, want the pool's pull Secret registry-ghcr", tok.Image)
	}
}
