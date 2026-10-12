// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What an inventory source may name (#915): a credential of the organization of its inventory,
// and of the type the source authenticates with. A credential of another organization is a 400
// with the very same bytes as an identifier that names nothing. The fixture and the assertions
// are in referent_scope_neighbours_test.go.
//
// The defect these tests were written against, driven by a member of one organization only: a
// create checked the type of the credential it was given and not its organization, and an update
// stored the identifier without looking it up at all, so it accepted another organization's
// credential, a credential of the wrong type and an identifier that named nothing alike. The
// sync decrypts the credential the source names.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestInventorySourceReferents

//go:build integration

package ansible

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func (f *neighbourScopeFixture) sourcePaths() (create, update string) {
	return "/api/v2/ansible/inventories/" + f.inventoryID + "/sources",
		"/api/v2/ansible/inventory-sources/" + f.source.String()
}

func sourceDocument(t *testing.T, attrs map[string]any) string {
	t.Helper()
	return neighbourDocument(t, "ansible-inventory-sources", attrs, nil, nil)
}

func TestInventorySourceReferents_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupNeighbourScope(t)
	create, update := f.sourcePaths()
	f.assertReadAsNotFound(t, []neighbourWrite{
		{"an inventory source naming a credential", func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPost, create, sourceDocument(t, map[string]any{
				"name": "nbref-src-" + uuid.NewString()[:8], "source-type": "aws", "credential-id": id,
			}))
		}, f.otherAWS, "credential not found"},
		{"an inventory source update naming a credential", func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPatch, update, sourceDocument(t, map[string]any{"credential-id": id}))
		}, f.otherAWS, "credential not found"},
		// Of another organization and of the wrong type: still "not found". The type of a row the
		// caller may not name is not theirs to learn.
		{"an inventory source update naming a credential of the wrong type", func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPatch, update, sourceDocument(t, map[string]any{"credential-id": id}))
		}, f.otherSSH, "credential not found"},
	})
}

func TestInventorySourceReferents_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupNeighbourScope(t)
	create, update := f.sourcePaths()
	storedCredential := func(t *testing.T, id any) *uuid.UUID {
		t.Helper()
		var row models.AnsibleInventorySource
		if err := f.db.First(&row, "id = ?", id).Error; err != nil {
			t.Fatalf("loading the source: %v", err)
		}
		return row.CredentialID
	}

	t.Run("a create with its organization's credential", func(t *testing.T) {
		code, body := f.call(t, http.MethodPost, create, sourceDocument(t, map[string]any{
			"name": "nbref-src-" + uuid.NewString()[:8], "source-type": "aws", "credential-id": f.awsCred,
		}))
		created := createdResource(t, code, body)
		if got := storedCredential(t, created.ID); got == nil || got.String() != f.awsCred {
			t.Errorf("stored credential %v, want %s", got, f.awsCred)
		}
	})
	t.Run("an update to its organization's credential", func(t *testing.T) {
		code, body := f.call(t, http.MethodPatch, update, sourceDocument(t, map[string]any{"credential-id": f.awsCred}))
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		if got := storedCredential(t, f.source); got == nil || got.String() != f.awsCred {
			t.Errorf("stored credential %v, want %s", got, f.awsCred)
		}
	})
	// An update holds the credential to the source's type, as a create does.
	t.Run("an update to its organization's credential of the wrong type is refused", func(t *testing.T) {
		code, body := f.call(t, http.MethodPatch, update, sourceDocument(t, map[string]any{"credential-id": f.sshCred}))
		assertBadRequest(t, code, body, "credential type ssh is not valid for source type aws")
		if got := storedCredential(t, f.source); got == nil || got.String() != f.awsCred {
			t.Errorf("the refused update left the source naming %v, want %s", got, f.awsCred)
		}
	})
	t.Run("an update with an empty credential clears it", func(t *testing.T) {
		code, body := f.call(t, http.MethodPatch, update, sourceDocument(t, map[string]any{"credential-id": ""}))
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", code, body)
		}
		if got := storedCredential(t, f.source); got != nil {
			t.Errorf("the source still names %v", got)
		}
	})
}
