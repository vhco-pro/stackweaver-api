// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The identity a VCS inventory file sync claims with (#1113, D2, D3; AC-03, AC-04, AC-06, AC-09,
// AC-19): its inventory's effective binding as it stands at the claim, checked against the pool the
// sync was queued on and recorded on its placement. Constructed rebuilds keep the platform identity,
// and hosted work receives the configured hosted binding.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// fileSyncInventory is a VCS inventory of project A.
func (f *workItemRunnerFixture) fileSyncInventory(t *testing.T, typ models.InventoryType) *models.AnsibleInventory {
	t.Helper()
	inv := &models.AnsibleInventory{
		ID: uuid.New(), OrganizationID: f.orgA, ProjectID: &f.projectA, Name: "wi-id-inv-" + uuid.NewString()[:8], Type: typ,
	}
	if typ != models.InventoryTypeConstructed {
		inv.VCSConnectionID, inv.VCSRepository, inv.VCSBranch, inv.InventoryPath = &f.vcsConn, "acme/inventories", "main", "hosts.yml"
	}
	if err := f.db.Create(inv).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.WorkItem{})
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.AnsibleInventorySync{})
		f.db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{})
	})
	return inv
}

// binding is a binding of organization A on pool.
func (f *workItemRunnerFixture) binding(t *testing.T, pool uuid.UUID, name string) *models.IdentityBinding {
	t.Helper()
	b := &models.IdentityBinding{
		OrganizationID: f.orgA, AgentPoolID: pool, Name: name + "-" + uuid.NewString()[:6], Mechanism: models.IdentityMechanismAzureWorkloadIdentity,
		ServiceAccount: "sw-" + name, Annotations: models.JSONB{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
	}
	if err := f.db.Create(b).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", b.ID).Delete(&models.IdentityBinding{}) })
	return b
}

func (f *workItemRunnerFixture) selectOnProject(t *testing.T, binding any) {
	t.Helper()
	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("identity_binding_id", binding).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Update("identity_binding_id", nil) })
}

func configureHosted(t *testing.T, name string) uuid.UUID {
	t.Helper()
	repository.SetHostedBinding(&repository.HostedBindingConfig{
		Name: name, Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity",
		Annotations: map[string]string{"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"},
	})
	t.Cleanup(func() { repository.SetHostedBinding(nil) })
	return models.HostedIdentityBindingID(name)
}

func TestFileSyncIdentity_CustomerBindingOnTheToken(t *testing.T) {
	f := setupWorkItemRunner(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)

	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if item.AgentPoolID == nil || *item.AgentPoolID != f.poolA {
		t.Fatalf("file sync queued on %v, want the binding's pool %s", item.AgentPoolID, f.poolA)
	}
	tok := f.claim(t, "a1", item.ID, "fs")
	if id := tok.Identity; id == nil || id.BindingID != b.ID.String() || id.Mechanism != models.IdentityMechanismAzureWorkloadIdentity || id.ServiceAccount != "sw-files" {
		t.Errorf("identity in the file sync's token = %+v, want binding %s", id, b.ID)
	}
	if got := f.reload(t, item.ID); got.Placement.IdentityBindingID == nil || *got.Placement.IdentityBindingID != b.ID {
		t.Errorf("the placement records binding %v, want %s", got.Placement.IdentityBindingID, b.ID)
	}
}

func TestFileSyncIdentity_ConstructedRebuildHasNone(t *testing.T) {
	f := setupWorkItemRunner(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv := f.fileSyncInventory(t, models.InventoryTypeConstructed)
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.h.jobIdentity(models.JobTypeWorkItem, item.ID, item.AgentPoolID)
	if err != nil || id != nil {
		t.Errorf("constructed rebuild's identity = %+v, %v; want the platform identity", id, err)
	}
}

func TestFileSyncIdentity_HostedBindingOnHostedWork(t *testing.T) {
	f := setupWorkItemRunner(t)
	hosted := configureHosted(t, "hosted-workload-identity")
	hostedPool, _, err := repository.HostedPoolOf(f.db, f.orgA)
	if err != nil {
		t.Fatal(err)
	}
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(inv).Update("identity_binding_id", hosted).Error; err != nil {
		t.Fatal(err)
	}
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if item.AgentPoolID == nil || *item.AgentPoolID != hostedPool {
		t.Fatalf("file sync selecting the hosted binding queued on %v, want the hosted pool %s", item.AgentPoolID, hostedPool)
	}
	id, err := f.h.jobIdentity(models.JobTypeWorkItem, item.ID, item.AgentPoolID)
	if err != nil || id == nil || id.BindingID != hosted.String() || id.ServiceAccount != "stackweaver-hosted-identity" || id.PerJob {
		t.Errorf("hosted file sync identity = %+v, %v; want the hosted binding", id, err)
	}
	// Resolving records nothing: only the attempt's first job token records its decision
	// (TestJobTokenIdentity_HostedRenameReplays).

	// An Ansible job on hosted capacity whose project selects the hosted binding receives it, and
	// the same job on a customer pool is refused.
	f.selectOnProject(t, hosted)
	job := f.seedJob(t, nil, f.runnerA1)
	if id, err := f.h.jobIdentity(models.JobTypeAnsibleJob, job.ID.String(), &hostedPool); err != nil || id == nil || id.BindingID != hosted.String() {
		t.Errorf("hosted job identity = %+v, %v; want the hosted binding", id, err)
	}
	if _, err := f.h.jobIdentity(models.JobTypeAnsibleJob, job.ID.String(), &f.poolA); !errors.Is(err, repository.ErrBindingNotOffered) {
		t.Errorf("hosted binding for a job on a customer pool: err = %v, want ErrBindingNotOffered", err)
	}

	// A customer binding resolved for a hosted job is refused.
	customer := f.binding(t, f.poolA, "customer")
	f.selectOnProject(t, customer.ID)
	if _, err := f.h.jobIdentity(models.JobTypeAnsibleJob, job.ID.String(), &hostedPool); !errors.Is(err, repository.ErrBindingNotOffered) {
		t.Errorf("customer binding for a hosted job: err = %v, want ErrBindingNotOffered", err)
	}
}

func TestFileSyncIdentity_OldHostedIDRefused(t *testing.T) {
	f := setupWorkItemRunner(t)
	old := configureHosted(t, "hosted-workload-identity")
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	if err := f.db.Model(inv).Update("identity_binding_id", old).Error; err != nil {
		t.Fatal(err)
	}
	configureHosted(t, "renamed-identity")
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatalf("a file sync selecting an old hosted ID must still be accepted: %v", err)
	}
	_, err = f.h.jobIdentity(models.JobTypeWorkItem, item.ID, item.AgentPoolID)
	if !errors.Is(err, repository.ErrBindingNotOffered) || !strings.Contains(err.Error(), "no longer exists") {
		t.Errorf("old hosted ID at the claim: err = %v, want ErrBindingNotOffered naming the binding as no longer existing", err)
	}
}

func TestFileSyncIdentity_SelectionChangedBeforeTheClaim(t *testing.T) {
	f := setupWorkItemRunner(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}

	// The project now selects a binding of another pool: the queued pool does not offer it.
	other := &models.AgentPool{ID: uuid.New(), OrganizationID: f.orgA, Name: "wi-id-other-" + uuid.NewString()[:6], OrganizationScoped: true}
	if err := f.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", other.ID).Delete(&models.AgentPool{}) })
	elsewhere := f.binding(t, other.ID, "elsewhere")
	f.selectOnProject(t, elsewhere.ID)
	if rec := runnerDoStart(t, f, "a1", item.ID); rec != http.StatusOK {
		t.Fatalf("claiming: %d", rec)
	}
	// a1 is a non-strict Kubernetes launcher, so only the queued pool's offer check can refuse it.
	f.kubernetesRunners(t)
	rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/token", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "belongs to another pool than the one the job runs on") {
		t.Errorf("token for a file sync whose binding its queued pool no longer offers = %d %s, want 409 with the not-offered reason", rec.Code, rec.Body.String())
	}

	// A cleared selection runs with the platform identity.
	f.selectOnProject(t, nil)
	id, err := f.h.jobIdentity(models.JobTypeWorkItem, item.ID, item.AgentPoolID)
	if err != nil || id != nil {
		t.Errorf("identity after the selection was cleared = %+v, %v; want the platform identity", id, err)
	}
}

// runnerDoStart claims a work item as the runner behind key and returns the status.
func runnerDoStart(t *testing.T, f *workItemRunnerFixture, key, id string) int {
	t.Helper()
	rec := runnerDo(t, f.r, key, http.MethodPost, "/api/v2/runner/jobs/"+id+"/start", map[string]string{"runner_id": f.keyRunner(key)})
	return rec.Code
}
