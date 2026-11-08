// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An inventory sync node names the inventory source it syncs (#1057). The node API takes it as the
// `inventory-source` relationship on create and update and returns it on read; the source must
// belong to the workflow's organization, and to the node's inventory when the node names one. An
// inventory sync node needs a source and no other node type takes one.
//
// The defect: the node API parsed `job-template`, `inventory` and `credential` only, so an
// inventory sync node created through it had no source and failed when its workflow reached it.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. It extends the referent scope
// fixture, and its own rows are removed by id before the fixture's. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestWorkflowNodeSource

//go:build integration

package ansible

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// nodeSourceFixture is the referent scope fixture with an inventory source in each organization,
// and a second inventory of the first organization holding a source of its own.
type nodeSourceFixture struct {
	*referentScopeFixture
	source, siblingSource, otherSource string
	siblingInventory                   string
}

func setupNodeSource(t *testing.T) *nodeSourceFixture {
	t.Helper()
	base := setupReferentScope(t)
	// Every table, not only the fixture's: the permission check reads more of them.
	if err := models.AutoMigrate(base.db); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	sfx := uuid.NewString()[:8]
	sibling := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: base.orgID, Name: "wfsrc-inv-" + sfx, Type: models.InventoryTypeStatic}
	mk := func(inventory string) *models.AnsibleInventorySource {
		return &models.AnsibleInventorySource{
			ID: uuid.New(), InventoryID: uuid.MustParse(inventory), Name: "wfsrc-" + uuid.NewString()[:8],
			Type: models.InventorySourceTypeCustom, Enabled: true,
		}
	}
	own, siblingSource, other := mk(base.inventory), mk(sibling.ID.String()), mk(base.otherInventory)
	// Registered after the fixture's cleanup, so it runs first: the sources hold the inventories.
	t.Cleanup(func() {
		base.db.Where("id IN ?", []uuid.UUID{own.ID, siblingSource.ID, other.ID}).Delete(&models.AnsibleInventorySource{})
		base.db.Where("workflow_id = ? AND inventory_id = ?", base.workflow, sibling.ID).Delete(&models.AnsibleWorkflowNode{})
		base.db.Where("id = ?", sibling.ID).Delete(&models.AnsibleInventory{})
	})
	for _, row := range []any{sibling, own, siblingSource, other} {
		if err := base.db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	base.router.GET("/api/v2/ansible/workflows/:id/nodes", base.handler.ListNodes)
	return &nodeSourceFixture{
		referentScopeFixture: base, source: own.ID.String(), siblingSource: siblingSource.ID.String(),
		otherSource: other.ID.String(), siblingInventory: sibling.ID.String(),
	}
}

func (f *nodeSourceFixture) createNode(t *testing.T, nodeType string, relationships map[string]string) (int, []byte) {
	t.Helper()
	return storedAsSentCall(t, f.router, http.MethodPost, "/api/v2/ansible/workflows/"+f.workflow.String()+"/nodes", f.admin,
		workflowDocument(t, "ansible-workflow-nodes", map[string]any{"node-type": nodeType, "identifier": "sync-" + uuid.NewString()[:8]}, relationships))
}

// patchNode sends a node update whose relationships object is raw JSON.
func (f *nodeSourceFixture) patchNode(t *testing.T, nodeID, relationships string) (int, []byte) {
	t.Helper()
	body := `{"data":{"type":"ansible-workflow-nodes","attributes":{},"relationships":` + relationships + `}}`
	return storedAsSentCall(t, f.router, http.MethodPatch, "/api/v2/ansible/workflow-nodes/"+nodeID, f.admin, body)
}

func (f *nodeSourceFixture) storedSource(t *testing.T, nodeID string) *uuid.UUID {
	t.Helper()
	var node models.AnsibleWorkflowNode
	if err := f.db.First(&node, "id = ?", nodeID).Error; err != nil {
		t.Fatalf("loading node %s: %v", nodeID, err)
	}
	return node.InventorySourceID
}

// sourceRelationship returns the inventory-source relationship of a node document, or "" when it
// has none.
func sourceRelationship(t *testing.T, raw json.RawMessage) (typ, id string) {
	t.Helper()
	var node struct {
		Relationships map[string]struct {
			Data *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal(raw, &node); err != nil {
		t.Fatalf("decoding the node: %v\n%s", err, raw)
	}
	rel, ok := node.Relationships["inventory-source"]
	if !ok || rel.Data == nil {
		return "", ""
	}
	return rel.Data.Type, rel.Data.ID
}

func TestWorkflowNodeSource_CreateReadAndUpdate(t *testing.T) {
	f := setupNodeSource(t)

	code, body := f.createNode(t, "inventory_sync", map[string]string{"inventory-source": f.source})
	created := createdResource(t, code, body)
	if got := f.storedSource(t, created.ID); got == nil || got.String() != f.source {
		t.Fatalf("the node stores source %v, want %s", got, f.source)
	}
	var doc struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if typ, id := sourceRelationship(t, doc.Data); typ != "inventory-sources" || id != f.source {
		t.Errorf("the created node's inventory-source is %s %s, want inventory-sources %s", typ, id, f.source)
	}

	// Read back through the node listing.
	code, body = storedAsSentCall(t, f.router, http.MethodGet, "/api/v2/ansible/workflows/"+f.workflow.String()+"/nodes", f.admin, "")
	if code != http.StatusOK {
		t.Fatalf("listing nodes = %d (%s)", code, body)
	}
	var list struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range list.Data {
		if _, id := sourceRelationship(t, raw); id == f.source {
			found = true
		}
	}
	if !found {
		t.Errorf("the node listing names no node with inventory-source %s:\n%s", f.source, body)
	}

	// Update to another source of the organization.
	code, body = f.patchNode(t, created.ID, `{"inventory-source":{"data":{"type":"inventory-sources","id":"`+f.siblingSource+`"}}}`)
	if code != http.StatusOK {
		t.Fatalf("updating the source = %d (%s)", code, body)
	}
	if got := f.storedSource(t, created.ID); got == nil || got.String() != f.siblingSource {
		t.Errorf("after the update the node stores source %v, want %s", got, f.siblingSource)
	}
	// An update that leaves the relationship out keeps it.
	if code, body = f.patchNode(t, created.ID, `{}`); code != http.StatusOK {
		t.Fatalf("an update without relationships = %d (%s)", code, body)
	}
	if got := f.storedSource(t, created.ID); got == nil || got.String() != f.siblingSource {
		t.Errorf("an update without the relationship changed the source to %v", got)
	}
}

func TestWorkflowNodeSource_Refusals(t *testing.T) {
	f := setupNodeSource(t)
	rows := func(t *testing.T) int64 {
		return f.count(t, &models.AnsibleWorkflowNode{}, "workflow_id = ?", f.workflow)
	}

	t.Run("a source of another organization reads like one that does not exist", func(t *testing.T) {
		before := rows(t)
		code, body := f.createNode(t, "inventory_sync", map[string]string{"inventory-source": f.otherSource})
		assertBadRequest(t, code, body, "inventory source not found")
		missingCode, missingBody := f.createNode(t, "inventory_sync", map[string]string{"inventory-source": uuid.NewString()})
		assertBadRequest(t, missingCode, missingBody, "inventory source not found")
		if !bytes.Equal(body, missingBody) {
			t.Errorf("another organization's source and a missing one are answered differently:\n%s\n%s", body, missingBody)
		}
		if got := rows(t) - before; got != 0 {
			t.Errorf("the refused creates left %d node(s)", got)
		}
	})
	t.Run("an inventory sync node without a source", func(t *testing.T) {
		code, body := f.createNode(t, "inventory_sync", nil)
		assertBadRequest(t, code, body, "inventory-source is required for inventory_sync nodes")
	})
	t.Run("a source on a node of another type", func(t *testing.T) {
		code, body := f.createNode(t, "approval", map[string]string{"inventory-source": f.source})
		assertBadRequest(t, code, body, "inventory-source applies only to inventory_sync nodes")
	})
	t.Run("a source outside the inventory the node names", func(t *testing.T) {
		code, body := f.createNode(t, "inventory_sync", map[string]string{"inventory-source": f.source, "inventory": f.siblingInventory})
		assertBadRequest(t, code, body, "inventory source not found")
	})
	t.Run("an identifier that does not parse", func(t *testing.T) {
		code, body := f.createNode(t, "inventory_sync", map[string]string{"inventory-source": "not-a-uuid"})
		assertBadRequest(t, code, body, "Invalid inventory source ID")
	})

	code, body := f.createNode(t, "inventory_sync", map[string]string{"inventory-source": f.source})
	node := createdResource(t, code, body)
	t.Run("an update to a source of another organization", func(t *testing.T) {
		code, body := f.patchNode(t, node.ID, `{"inventory-source":{"data":{"type":"inventory-sources","id":"`+f.otherSource+`"}}}`)
		assertBadRequest(t, code, body, "inventory source not found")
		if got := f.storedSource(t, node.ID); got == nil || got.String() != f.source {
			t.Errorf("the refused update left source %v, want %s", got, f.source)
		}
	})
	t.Run("an update that clears the source", func(t *testing.T) {
		code, body := f.patchNode(t, node.ID, `{"inventory-source":{"data":null}}`)
		assertBadRequest(t, code, body, "inventory-source is required for inventory_sync nodes")
		if got := f.storedSource(t, node.ID); got == nil {
			t.Error("the refused update cleared the source")
		}
	})
	t.Run("an update giving a node of another type a source", func(t *testing.T) {
		code, body := f.patchNode(t, f.nodeA, `{"inventory-source":{"data":{"type":"inventory-sources","id":"`+f.source+`"}}}`)
		assertBadRequest(t, code, body, "inventory-source applies only to inventory_sync nodes")
	})
}
