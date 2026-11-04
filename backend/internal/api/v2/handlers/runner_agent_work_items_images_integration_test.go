// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the image and identity a work item is placed with (#933, D2, D6, D8,
// AC10): at the claim, a dynamic-source sync takes the run image and the identity binding resolved
// for its inventory source, and records both on its placement; every other sync (a playbook
// snapshot, a VCS inventory file sync, a constructed rebuild) runs in the platform image with the
// platform identity, whatever the project and the organization set for Ansible jobs.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.
// Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestWorkItemRunner_(DynamicSourceSync|OtherSyncs)'

//go:build integration

package handlers

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/settings"
)

// workItemImageFixture holds two Ansible run images and two identity bindings of organization A's
// pool A, so a test can tell which level a placement took its image and identity from.
type workItemImageFixture struct {
	*workItemRunnerFixture
	sourceImage, projectImage     *models.RunImage
	sourceBinding, projectBinding *models.IdentityBinding
}

func setupWorkItemImages(t *testing.T) *workItemImageFixture {
	t.Helper()
	f := setupWorkItemRunner(t)
	sfx := uuid.NewString()[:6]
	sourceImage := &models.RunImage{ID: uuid.New(), OrganizationID: f.orgA, Name: "wi-src-img-" + sfx, Kind: models.RunImageKindAnsible, Image: "ghcr.io/acme/aws-ee:3", Digest: "sha256:" + strings.Repeat("a", 64)}
	projectImage := &models.RunImage{ID: uuid.New(), OrganizationID: f.orgA, Name: "wi-proj-img-" + sfx, Kind: models.RunImageKindAnsible, Image: "ghcr.io/acme/project-ee:1"}
	sourceBinding := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "wi-src-" + sfx, Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-inventory"}
	projectBinding := &models.IdentityBinding{ID: uuid.New(), OrganizationID: f.orgA, AgentPoolID: f.poolA, Name: "wi-proj-" + sfx, Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-project"}
	for _, o := range []any{sourceImage, projectImage, sourceBinding, projectBinding} {
		if err := f.db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Updates(map[string]any{"ansible_run_image_id": nil, "identity_binding_id": nil})
		f.db.Model(&models.Organization{}).Where("id = ?", f.orgA).Updates(map[string]any{"ansible_run_image_id": nil, "identity_binding_id": nil})
		f.db.Where("id IN ?", []uuid.UUID{sourceBinding.ID, projectBinding.ID}).Delete(&models.IdentityBinding{})
		f.db.Where("id IN ?", []uuid.UUID{sourceImage.ID, projectImage.ID}).Delete(&models.RunImage{})
	})
	return &workItemImageFixture{workItemRunnerFixture: f, sourceImage: sourceImage, projectImage: projectImage, sourceBinding: sourceBinding, projectBinding: projectBinding}
}

// projectDefaults gives project A, and organization A, an Ansible run image and an identity
// binding, which an Ansible job of the project would take.
func (f *workItemImageFixture) projectDefaults(t *testing.T) {
	t.Helper()
	if err := f.db.Model(&models.Project{}).Where("id = ?", f.projectA).Updates(map[string]any{"ansible_run_image_id": f.projectImage.ID, "identity_binding_id": f.projectBinding.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgA).Updates(map[string]any{"ansible_run_image_id": f.projectImage.ID, "identity_binding_id": f.projectBinding.ID}).Error; err != nil {
		t.Fatal(err)
	}
}

// projectInventory stores an inventory of project A of the given type.
func (f *workItemImageFixture) projectInventory(t *testing.T, typ models.InventoryType) *models.AnsibleInventory {
	t.Helper()
	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: f.orgA, ProjectID: &f.projectA, Name: "wi-img-inv-" + uuid.NewString()[:8], Type: typ}
	if typ == models.InventoryTypeVCS {
		inv.VCSConnectionID, inv.VCSRepository, inv.VCSBranch, inv.InventoryPath = &f.vcsConn, "acme/inventories", "main", "hosts.yml"
	}
	if err := f.db.Create(inv).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.AnsibleInventorySource{})
		f.db.Where("inventory_id = ?", inv.ID).Delete(&models.AnsibleInventorySync{})
		f.db.Where("id = ?", inv.ID).Delete(&models.AnsibleInventory{})
	})
	return inv
}

// source stores a dynamic source on inv with the given run image and identity binding (nil defers).
func (f *workItemImageFixture) source(t *testing.T, inv *models.AnsibleInventory, image, binding *uuid.UUID) *models.AnsibleInventorySource {
	t.Helper()
	src := &models.AnsibleInventorySource{ID: uuid.New(), InventoryID: inv.ID, Name: "wi-img-src-" + uuid.NewString()[:8], Type: models.InventorySourceTypeAWS, RunImageID: image, IdentityBindingID: binding}
	if err := f.db.Create(src).Error; err != nil {
		t.Fatal(err)
	}
	return src
}

func TestWorkItemRunner_DynamicSourceSyncTakesItsSourcesImageAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ownSettings  bool // the source sets its own image and binding; otherwise it defers to the project
		wantLevel    settings.Level
		wantImage    func(f *workItemImageFixture) *models.RunImage
		wantBindings func(f *workItemImageFixture) *models.IdentityBinding
	}{
		{
			name: "the source's own", ownSettings: true, wantLevel: settings.LevelInventorySource,
			wantImage:    func(f *workItemImageFixture) *models.RunImage { return f.sourceImage },
			wantBindings: func(f *workItemImageFixture) *models.IdentityBinding { return f.sourceBinding },
		},
		{
			name: "deferred to the project", wantLevel: settings.LevelProject,
			wantImage:    func(f *workItemImageFixture) *models.RunImage { return f.projectImage },
			wantBindings: func(f *workItemImageFixture) *models.IdentityBinding { return f.projectBinding },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupWorkItemImages(t)
			f.projectDefaults(t)
			inv := f.projectInventory(t, models.InventoryTypeDynamic)
			var image, binding *uuid.UUID
			if tc.ownSettings {
				image, binding = &f.sourceImage.ID, &f.sourceBinding.ID
			}
			src := f.source(t, inv, image, binding)
			item, err := f.items.RequestSourceSync(t.Context(), src, "manual")
			if err != nil {
				t.Fatal(err)
			}
			want, wantBinding := tc.wantImage(f), tc.wantBindings(f)
			if item.Image != want.Reference() || item.ImageLevel != string(tc.wantLevel) {
				t.Errorf("work item image = %q level %q, want %q level %s", item.Image, item.ImageLevel, want.Reference(), tc.wantLevel)
			}
			f.onPool(t, item)

			tok := f.claim(t, "a1", item.ID, "wi")
			if tok.Image == nil || tok.Image.ID != want.ID.String() || tok.Image.Ref != want.Reference() || tok.Image.Level != string(tc.wantLevel) {
				t.Errorf("image in the token = %+v, want %s (%s) from level %s", tok.Image, want.Name, want.Reference(), tc.wantLevel)
			}
			if tok.Identity == nil || tok.Identity.BindingID != wantBinding.ID.String() || tok.Identity.ServiceAccount != wantBinding.ServiceAccount {
				t.Errorf("identity in the token = %+v, want binding %s", tok.Identity, wantBinding.Name)
			}

			got := f.reload(t, item.ID)
			p := got.Placement
			if p.Image != want.Reference() || p.ImageDigest != want.Digest || p.ImageLevel != string(tc.wantLevel) {
				t.Errorf("placement image = %q digest %q level %q, want %q %q %q", p.Image, p.ImageDigest, p.ImageLevel, want.Reference(), want.Digest, tc.wantLevel)
			}
			if p.IdentityBindingID == nil || *p.IdentityBindingID != wantBinding.ID {
				t.Errorf("placement identity binding = %v, want %s", p.IdentityBindingID, wantBinding.ID)
			}
		})
	}
}

func TestWorkItemRunner_AnOrganizationInventorysSourceTakesItsOrganizationsImage(t *testing.T) {
	f := setupWorkItemImages(t)
	f.projectDefaults(t)
	inv := f.projectInventory(t, models.InventoryTypeDynamic)
	if err := f.db.Model(inv).Update("project_id", nil).Error; err != nil {
		t.Fatal(err)
	}
	item, err := f.items.RequestSourceSync(t.Context(), f.source(t, inv, nil, nil), "manual")
	if err != nil {
		t.Fatal(err)
	}
	want := f.projectImage // projectDefaults sets the same image on the organization.
	if item.Image != want.Reference() || item.ImageLevel != string(settings.LevelOrganization) {
		t.Errorf("work item image = %q level %q, want %q from the organization", item.Image, item.ImageLevel, want.Reference())
	}
	f.onPool(t, item)
	tok := f.claim(t, "a1", item.ID, "wi")
	if tok.Image == nil || tok.Image.Ref != want.Reference() || tok.Image.Level != string(settings.LevelOrganization) {
		t.Errorf("image in the token = %+v, want %q from the organization", tok.Image, want.Reference())
	}
	if tok.Identity == nil || tok.Identity.BindingID != f.projectBinding.ID.String() {
		t.Errorf("identity in the token = %+v, want the organization's binding %s", tok.Identity, f.projectBinding.Name)
	}
}

func TestWorkItemRunner_OtherSyncsRunInThePlatformImage(t *testing.T) {
	f := setupWorkItemImages(t)
	f.projectDefaults(t)

	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	snapshot, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
	if err != nil {
		t.Fatal(err)
	}
	fileSync, err := f.items.RequestInventorySync(t.Context(), f.projectInventory(t, models.InventoryTypeVCS), "manual")
	if err != nil {
		t.Fatal(err)
	}
	rebuild, err := f.items.RequestInventorySync(t.Context(), f.projectInventory(t, models.InventoryTypeConstructed), "manual")
	if err != nil {
		t.Fatal(err)
	}

	for _, item := range []*models.WorkItem{snapshot, fileSync, rebuild} {
		t.Run(item.Kind, func(t *testing.T) {
			f.onPool(t, item)
			tok := f.claim(t, "a1", item.ID, "wi-"+item.Kind)
			if tok.Image != nil {
				t.Errorf("image in the token = %+v, want none: the %s runs in the platform image", tok.Image, item.Kind)
			}
			if tok.Identity != nil {
				t.Errorf("identity in the token = %+v, want none: the %s runs with the platform identity", tok.Identity, item.Kind)
			}
			got := f.reload(t, item.ID)
			if got.Placement.Image != "" || got.Placement.ImageLevel != "" || got.Placement.IdentityBindingID != nil {
				t.Errorf("placement = %+v, want no image and no identity binding recorded", got.Placement)
			}
			if got.Image != "" || got.ImageLevel != "platform" {
				t.Errorf("work item image = %q level %q, want the platform image", got.Image, got.ImageLevel)
			}
		})
	}
}
