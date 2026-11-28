// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The hosted binding as a level reference (#1113, D3, AC-05, AC-09): while it is configured any
// organization may select it, and once it is not, selecting its ID is the same 422 as an unknown
// binding.
//
//	go test -tags integration ./internal/api/v2/levelrefs/ -run TestCheckerHostedBinding

//go:build integration

package levelrefs

import (
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestCheckerHostedBinding(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	db, err := dbtest.Open(t, dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:8]
	orgA := &models.Organization{ID: uuid.New(), Name: "levelrefs-hb-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "levelrefs-hb-b-" + sfx}
	pool := &models.AgentPool{ID: uuid.New(), OrganizationID: orgA.ID, Name: "levelrefs-hb-" + sfx}
	for _, o := range []any{orgA, orgB, pool} {
		if err := db.Create(o).Error; err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		db.Where("organization_id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.AgentPool{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
	})
	c := New(db)
	hosted := models.HostedIdentityBindingID("hosted-workload-identity").String()

	if _, _, err := c.IdentityBinding(orgA.ID, &hosted); !errors.Is(err, ErrInvalid) {
		t.Errorf("hosted ID with no hosted binding configured: err = %v, want ErrInvalid (a 422)", err)
	}

	repository.SetHostedBinding(&repository.HostedBindingConfig{Name: "hosted-workload-identity", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity"})
	t.Cleanup(func() { repository.SetHostedBinding(nil) })
	for _, org := range []uuid.UUID{orgA.ID, orgB.ID} {
		id, set, err := c.IdentityBinding(org, &hosted)
		if err != nil || !set || id == nil || id.String() != hosted {
			t.Errorf("hosted ID for organization %s = %v, %v, %v; want it accepted", org, id, set, err)
		}
	}
	hostedID := models.HostedIdentityBindingID("hosted-workload-identity")
	if err := c.Offered(orgA.ID, &hostedID, nil); err != nil {
		t.Errorf("hosted ID on hosted capacity: %v, want it offered", err)
	}
	if err := c.Offered(orgA.ID, &hostedID, &pool.ID); !errors.Is(err, repository.ErrBindingNotOffered) {
		t.Errorf("hosted ID on a customer pool: err = %v, want ErrBindingNotOffered", err)
	}

	// After a rename the old ID is unknown again.
	repository.SetHostedBinding(&repository.HostedBindingConfig{Name: "renamed", Mechanism: models.IdentityMechanismAzureWorkloadIdentity, ServiceAccount: "stackweaver-hosted-identity"})
	if _, _, err := c.IdentityBinding(orgA.ID, &hosted); !errors.Is(err, ErrInvalid) {
		t.Errorf("old hosted ID after a rename: err = %v, want ErrInvalid (a 422)", err)
	}
}
