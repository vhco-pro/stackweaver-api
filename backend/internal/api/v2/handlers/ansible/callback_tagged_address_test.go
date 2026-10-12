// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A provisioning callback finds the calling machine among the inventory's hosts by its address,
// and one place it looks is the host's stored ansible_host variable (#910). For a host a dynamic
// source discovered, that variable is stored as the engine printed it:
// {"__ansible_unsafe": "10.0.0.5"}. The handler read it with a plain string assertion, so a
// machine that a cloud source had discovered could not call back: its name is a DNS name, its
// Hostname was that same name, and the one field holding its address was not seen.
//
// The row below is one written before the parser read the address through the tag, so its
// Hostname is still its name; the callback must find it without waiting for the next sync.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. The fixture's cleanup
// deletes every host of its inventory. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestProvisioningCallback_

//go:build integration

package ansible

import (
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestProvisioningCallback_FindsAHostByItsTaggedAddress(t *testing.T) {
	f := setupAnsibleSubResourceAuthz(t)
	inventoryID := uuid.MustParse(f.inventoryID)
	sfx := uuid.NewString()[:8]
	seed := func(name string, variables models.InventoryVariables) {
		t.Helper()
		host := &models.AnsibleInventoryHost{InventoryID: inventoryID, Name: name, Hostname: name, Enabled: true, Variables: variables}
		if err := f.inventoryRepo.CreateHost(host); err != nil {
			t.Fatalf("seeding host %s: %v", name, err)
		}
	}
	tagged := "ip-10-87-2-5-" + sfx + ".compute.internal"
	bare := "ip-10-87-2-6-" + sfx + ".compute.internal"
	vaulted := "ip-10-87-2-7-" + sfx + ".compute.internal"
	seed(tagged, models.InventoryVariables{"ansible_host": map[string]any{"__ansible_unsafe": "10.87.2.5"}})
	seed(bare, models.InventoryVariables{"ansible_host": "10.87.2.6"})
	// Ciphertext is not an address: a caller cannot match a host by sending it.
	const ciphertext = "$ANSIBLE_VAULT;1.1;AES256\n30393936\n"
	seed(vaulted, models.InventoryVariables{"ansible_host": map[string]any{"__ansible_vault": ciphertext}})
	h := &ProvisioningCallbackHandler{inventoryRepo: f.inventoryRepo}

	tests := []struct {
		name     string
		clientIP string
		want     string
	}{
		{"an address the engine tagged as untrusted", "10.87.2.5", tagged},
		{"an address stored bare", "10.87.2.6", bare},
		{"an address nobody has", "10.87.2.99", ""},
		{"the ciphertext of a vault-encrypted address", ciphertext, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.findRequestingHost(inventoryID, tt.clientIP); got != tt.want {
				t.Errorf("findRequestingHost(%q) = %q, want %q", tt.clientIP, got, tt.want)
			}
		})
	}
}
