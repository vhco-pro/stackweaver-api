// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the level references (#933, D0, D6, D8): a level selects a run image of its
// own organization and engine and an identity binding of its own organization, an empty value
// clears the selection, and an absent one leaves it.
//
//	go test -tags integration ./internal/api/v2/levelrefs/

//go:build integration

package levelrefs

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
)

func TestChecker(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	db, err := dbtest.Open(t, dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	orgA := &models.Organization{ID: uuid.New(), Name: "levelrefs-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "levelrefs-b-" + sfx}
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: orgA.ID, Name: "levelrefs-" + sfx}
	tofu := &models.RunImage{OrganizationID: orgA.ID, Name: "tofu-" + sfx, Kind: models.RunImageKindTofu, Image: "ghcr.io/acme/tofu:1"}
	ee := &models.RunImage{OrganizationID: orgA.ID, Name: "ee-" + sfx, Kind: models.RunImageKindAnsible, Image: "ghcr.io/acme/ee:1"}
	foreign := &models.RunImage{OrganizationID: orgB.ID, Name: "b-" + sfx, Kind: models.RunImageKindTofu, Image: "ghcr.io/b/tofu:1"}
	for _, o := range []any{orgA, orgB, pool, tofu, ee, foreign} {
		if err := db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	binding := &models.IdentityBinding{OrganizationID: orgA.ID, AgentPoolID: pool.ID, Name: "deploy", Mechanism: models.IdentityMechanismAWSIRSA, ServiceAccount: "sw-deploy"}
	if err := db.Create(binding).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.RunImage{})
		db.Where("id = ?", binding.ID).Delete(&models.IdentityBinding{})
		db.Where("id = ?", pool.ID).Delete(&models.AgentPool{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
	})
	c := New(db)
	str := func(s string) *string { return &s }

	if id, set, err := c.RunImage(orgA.ID, models.RunImageKindTofu, nil); err != nil || set || id != nil {
		t.Errorf("absent = %v %v %v, want untouched", id, set, err)
	}
	if id, set, err := c.RunImage(orgA.ID, models.RunImageKindTofu, str("")); err != nil || !set || id != nil {
		t.Errorf("empty = %v %v %v, want cleared", id, set, err)
	}
	if id, set, err := c.RunImage(orgA.ID, models.RunImageKindTofu, str(tofu.ID.String())); err != nil || !set || id == nil || *id != tofu.ID {
		t.Errorf("own tofu image = %v %v %v", id, set, err)
	}
	for name, raw := range map[string]string{
		"the other engine's image":     ee.ID.String(),
		"another organization's image": foreign.ID.String(),
		"no image":                     uuid.NewString(),
		"not an id":                    "nope",
	} {
		if _, _, err := c.RunImage(orgA.ID, models.RunImageKindTofu, str(raw)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if id, set, err := c.IdentityBinding(orgA.ID, str(binding.ID.String())); err != nil || !set || *id != binding.ID {
		t.Errorf("own binding = %v %v %v", id, set, err)
	}
	if _, _, err := c.IdentityBinding(orgB.ID, str(binding.ID.String())); err == nil {
		t.Error("another organization's binding was accepted")
	}
	if id, set, err := c.IdentityBinding(orgA.ID, str("")); err != nil || !set || id != nil {
		t.Errorf("empty binding = %v %v %v, want cleared", id, set, err)
	}
}
