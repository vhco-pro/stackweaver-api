// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An inventory host created with `enabled: false` must be stored disabled and left out of the
// generated inventory, and one created without the attribute must be enabled. A disabled host is
// one Ansible must not run against, so a create that silently enables it is a host targeted by
// the next job.
//
// The defect this test was written against: AnsibleInventoryHost.Enabled carried
// `gorm:"default:true"`, and GORM substitutes a literal default for a zero value in the INSERT
// (and writes it back into the struct), so a false sent on create was stored and answered as
// true. The default lives in HostHandler.Create instead.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestHostCreate_Enabled

//go:build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
)

func TestHostCreate_EnabledIsStoredAsSent(t *testing.T) {
	// Org A with an owner and an inventory. The fixture's cleanup deletes every host of that
	// inventory, which covers the ones created below.
	f := setupAnsibleSubResourceAuthz(t)
	db := f.db
	inventoryID := uuid.MustParse(f.inventoryID)

	orgRepo := repository.NewOrganizationRepository(db)
	inventoryService := ansiblesvc.NewInventoryService(f.inventoryRepo, orgRepo)
	h := NewHostHandler(
		inventoryService,
		f.inventoryRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db)),
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/ansible/inventories/:id/hosts", h.Create)
	router.GET("/api/v2/ansible/hosts/:id", h.Get)

	sent := func(v bool) *bool { return &v }
	cases := []struct {
		name    string
		enabled *bool // nil leaves the attribute out
		want    bool
	}{
		{"explicit false", sent(false), false},
		{"explicit true", sent(true), true},
		{"absent", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hostName := "hostenabled-" + uuid.NewString()[:8]
			attrs := map[string]any{"name": hostName, "hostname": "10.87.1.1"}
			if tc.enabled != nil {
				attrs["enabled"] = *tc.enabled
			}
			raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "ansible-hosts", "attributes": attrs}})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			code, body := storedAsSentCall(t, router, http.MethodPost,
				"/api/v2/ansible/inventories/"+f.inventoryID+"/hosts", f.owner.ID, string(raw))
			if code != http.StatusCreated {
				t.Fatalf("create = %d, want 201 (%s)", code, body)
			}
			var created struct {
				Data storedAsSentResource `json:"data"`
			}
			if err := json.Unmarshal(body, &created); err != nil {
				t.Fatalf("decode create response: %v\n%s", err, body)
			}
			assertStoredBool(t, "create response", created.Data.Attributes, "enabled", tc.want)

			code, body = storedAsSentCall(t, router, http.MethodGet, "/api/v2/ansible/hosts/"+created.Data.ID, f.owner.ID, "")
			if code != http.StatusOK {
				t.Fatalf("read = %d, want 200 (%s)", code, body)
			}
			var read struct {
				Data storedAsSentResource `json:"data"`
			}
			if err := json.Unmarshal(body, &read); err != nil {
				t.Fatalf("decode read response: %v\n%s", err, body)
			}
			assertStoredBool(t, "read back", read.Data.Attributes, "enabled", tc.want)

			inventoryJSON, err := inventoryService.GenerateInventoryJSON(inventoryID)
			if err != nil {
				t.Fatalf("generate inventory: %v", err)
			}
			if inInventory := strings.Contains(inventoryJSON, hostName); inInventory != tc.want {
				t.Errorf("host in the generated inventory = %t, want %t", inInventory, tc.want)
			}
		})
	}
}
