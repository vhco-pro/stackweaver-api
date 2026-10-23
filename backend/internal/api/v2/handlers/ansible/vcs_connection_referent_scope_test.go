// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a playbook may name as its VCS connection (#916): a connection of its own organization.
// Anything else is a 400 in the JSON:API errors document, and a connection that exists in another
// organization gets the very same bytes as an identifier that names nothing. It is the rule
// schedules (#884), workflows (#905) and job credentials (#915) follow.
//
// The defect these tests were written against: a playbook create and update stored the connection
// identifier the body named, and everything that syncs or runs a playbook clones with the token
// of the connection it names. A member of one organization could clone any repository another
// organization's connection can read.
//
// Every request is sent by a member of the first organization who has no part in the second.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'VCSConnection'

//go:build integration

package ansible

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// capturedQueue records what a handler queued.
type capturedQueue struct{ payloads []any }

func (q *capturedQueue) Enqueue(_ context.Context, _ string, job any) error {
	q.payloads = append(q.payloads, job)
	return nil
}

func (q *capturedQueue) Close() error { return nil }

// The tokens the fixture's connections clone with. They are distinct strings, so that a clone
// URL shows whose connection built it.
const (
	ownVCSToken   = "token-of-its-own-organization"
	otherVCSToken = "token-of-the-other-organization"
)

// vcsConnectionScopeFixture is neighbourScopeFixture with VCS connections: two in the first
// organization and one in the second. The handlers are mounted over a queue that records and a
// VCS registry that needs no network (GitLab builds its clone URL from the stored token).
type vcsConnectionScopeFixture struct {
	*neighbourScopeFixture
	router *gin.Engine
	queue  *capturedQueue
	orgID  uuid.UUID // the first organization

	ownConnection, ownConnection2, otherConnection string
}

func setupVCSConnectionScope(t *testing.T) *vcsConnectionScopeFixture {
	t.Helper()
	base := setupNeighbourScope(t)
	db := base.db
	if err := db.AutoMigrate(&models.VCSConnection{}); err != nil {
		t.Fatalf("migrating the tables: %v", err)
	}
	sfx := uuid.NewString()[:8]
	var project models.Project
	if err := db.First(&project, "id = ?", base.projectID).Error; err != nil {
		t.Fatalf("reading the first organization's project: %v", err)
	}
	orgID := project.OrganizationID
	connection := func(organizationID uuid.UUID, token, name string) *models.VCSConnection {
		return &models.VCSConnection{
			ID: uuid.New(), OrganizationID: organizationID, Provider: models.VCSProviderGitLab,
			AccessToken: token, AccountName: name + sfx,
		}
	}
	own, own2 := connection(orgID, ownVCSToken, "vcsscope-a-"), connection(orgID, ownVCSToken, "vcsscope-a2-")
	other := connection(base.otherOrgID, otherVCSToken, "vcsscope-b-")
	for _, row := range []*models.VCSConnection{own, own2, other} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding the VCS connection %s: %v", row.AccountName, err)
		}
	}
	// Registered after the shared fixture's cleanup, so it runs before it: the connections are
	// detached from the playbooks the shared cleanup removes, then deleted, each by identifier.
	connectionIDs := []uuid.UUID{own.ID, own2.ID, other.ID}
	t.Cleanup(func() {
		db.Model(&models.AnsiblePlaybook{}).Where("vcs_connection_id IN ?", connectionIDs).Update("vcs_connection_id", nil)
		// The inventories a test created or wrote directly are not among the shared fixture's.
		db.Where("vcs_connection_id IN ?", connectionIDs).Delete(&models.AnsibleInventory{})
		db.Where("id IN ?", connectionIDs).Delete(&models.VCSConnection{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	playbookRepo := repository.NewAnsiblePlaybookRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo)
	queue := &capturedQueue{}

	playbooks := NewPlaybookHandler(
		playbookRepo, repository.NewAnsibleJobTemplateRepository(db), repository.NewAnsibleJobRepository(db),
		repository.NewAnsibleScheduleRepository(db), projectRepo, orgRepo, authService, rbacService,
		queue, vcs.NewProviderRegistry(nil, nil, nil, nil), repository.NewVCSConnectionRepository(db), nil,
	)

	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	inventories := NewInventoryHandler(
		ansiblesvc.NewInventoryService(inventoryRepo, orgRepo), inventoryRepo, orgRepo, projectRepo,
		authService, rbacService, queue, vcs.NewProviderRegistry(nil, nil, nil, nil), repository.NewVCSConnectionRepository(db),
	)

	router := storedAsSentRouter()
	router.POST("/api/v2/organizations/:name/ansible/inventories", inventories.Create)
	router.PATCH("/api/v2/ansible/inventories/:id", inventories.Update)
	router.POST("/api/v2/ansible/inventories/:id/actions/sync", inventories.SyncInventory)
	router.POST("/api/v2/organizations/:name/ansible/playbooks", playbooks.CreatePlaybookByOrganization)
	router.PATCH("/api/v2/ansible/playbooks/:id", playbooks.UpdatePlaybook)

	return &vcsConnectionScopeFixture{
		neighbourScopeFixture: base, router: router, queue: queue, orgID: orgID,
		ownConnection: own.ID.String(), ownConnection2: own2.ID.String(), otherConnection: other.ID.String(),
	}
}

func (f *vcsConnectionScopeFixture) send(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return storedAsSentCall(t, f.router, method, path, f.member, body)
}

// naming counts the rows of a table that name one of the second organization's connection.
func (f *vcsConnectionScopeFixture) naming(t *testing.T, table string) int64 {
	t.Helper()
	return f.rows(t, "SELECT count(*) FROM "+table+" WHERE vcs_connection_id = ?", f.otherConnection)
}

// connectionOf reads the connection a row names, empty when it names none.
func (f *vcsConnectionScopeFixture) connectionOf(t *testing.T, table, id string) string {
	t.Helper()
	var connection *string
	if err := f.db.Raw("SELECT vcs_connection_id FROM "+table+" WHERE id = ?", id).Scan(&connection).Error; err != nil {
		t.Fatalf("reading the connection of %s %s: %v", table, id, err)
	}
	if connection == nil {
		return ""
	}
	return *connection
}

// assertConnectionRefused sends a write twice, naming the second organization's connection and
// naming nothing, and requires the same 400 with the same bytes for both.
func assertConnectionRefused(t *testing.T, send func(connection string) (int, []byte), foreign string) {
	t.Helper()
	code, body := send(foreign)
	assertBadRequest(t, code, body, "VCS connection not found")
	missingCode, missingBody := send(uuid.NewString())
	assertBadRequest(t, missingCode, missingBody, "VCS connection not found")
	if code != missingCode || !bytes.Equal(body, missingBody) {
		t.Errorf("a connection of another organization and one that does not exist are answered differently:\n  other organization: %d %s\n  does not exist:     %d %s",
			code, body, missingCode, missingBody)
	}
}

func (f *vcsConnectionScopeFixture) playbookDocument(t *testing.T, connection string) string {
	t.Helper()
	return neighbourDocument(t, "ansible-playbooks",
		map[string]any{"name": "vcsscope-" + uuid.NewString()[:8], "vcs-repository": "acme/playbooks", "playbook-path": "site.yml"},
		map[string]string{"project": f.project, "vcs-connection": connection}, nil)
}

func TestPlaybookVCSConnection_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupVCSConnectionScope(t)
	playbooksOf := func(t *testing.T) int64 {
		t.Helper()
		return f.rows(t, "SELECT count(*) FROM ansible_playbooks WHERE project_id = ?", f.projectID)
	}
	before := playbooksOf(t)

	writes := map[string]func(connection string) (int, []byte){
		"a create in the organization": func(connection string) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/playbooks", f.playbookDocument(t, connection))
		},
		"an update": func(connection string) (int, []byte) {
			return f.send(t, http.MethodPatch, "/api/v2/ansible/playbooks/"+f.playbook,
				neighbourDocument(t, "ansible-playbooks", map[string]any{}, map[string]string{"vcs-connection": connection}, nil))
		},
	}
	for name, send := range writes {
		t.Run(name, func(t *testing.T) {
			assertConnectionRefused(t, send, f.otherConnection)
		})
	}

	if got := playbooksOf(t) - before; got != 0 {
		t.Errorf("the refused requests left %d playbook(s) behind", got)
	}
	if got := f.naming(t, "ansible_playbooks"); got != 0 {
		t.Errorf("%d playbook(s) name the other organization's connection", got)
	}
	if len(f.queue.payloads) != 0 {
		t.Errorf("the refused requests queued %d sync(s)", len(f.queue.payloads))
	}
}

func TestPlaybookVCSConnection_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupVCSConnectionScope(t)

	code, body := f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/playbooks", f.playbookDocument(t, f.ownConnection))
	if code != http.StatusCreated {
		t.Fatalf("creating a playbook with its organization's connection: %d %s", code, body)
	}
	// The create queues the first sync, with the clone URL its own connection builds.
	if len(f.queue.payloads) != 1 {
		t.Fatalf("the create queued %d sync(s), want 1", len(f.queue.payloads))
	}
	message, ok := f.queue.payloads[0].(ansiblesvc.PlaybookSyncMessage)
	if !ok || !strings.Contains(message.CloneURL, ownVCSToken) {
		t.Errorf("the create queued %+v, want a sync with a clone URL built from the organization's own token", f.queue.payloads[0])
	}
	created := message.PlaybookID.String()
	if got := f.connectionOf(t, "ansible_playbooks", created); got != f.ownConnection {
		t.Errorf("the playbook names connection %q, want %q", got, f.ownConnection)
	}

	// An update loads the playbook with its connection attached, and must still be able to
	// change it and to clear it.
	patch := func(connection string) (int, []byte) {
		return f.send(t, http.MethodPatch, "/api/v2/ansible/playbooks/"+created,
			neighbourDocument(t, "ansible-playbooks", map[string]any{}, map[string]string{"vcs-connection": connection}, nil))
	}
	if code, body := patch(f.ownConnection2); code != http.StatusOK {
		t.Fatalf("changing to another connection of the organization: %d %s", code, body)
	}
	if got := f.connectionOf(t, "ansible_playbooks", created); got != f.ownConnection2 {
		t.Errorf("after the change the playbook names %q, want %q", got, f.ownConnection2)
	}
	if code, body := patch(""); code != http.StatusOK {
		t.Fatalf("clearing the connection: %d %s", code, body)
	}
	if got := f.connectionOf(t, "ansible_playbooks", created); got != "" {
		t.Errorf("after clearing, the playbook still names %q", got)
	}
}

// An inventory names its VCS connection the same way, and creating one queues a sync straight
// away with the clone URL resolved from the connection.

func (f *vcsConnectionScopeFixture) inventoryDocument(t *testing.T, connection string) string {
	t.Helper()
	return neighbourDocument(t, "ansible-inventories",
		map[string]any{
			"name": "vcsscope-" + uuid.NewString()[:8], "inventory-type": "vcs",
			"vcs_repository": "acme/inventories", "inventory_path": "hosts.yml",
		},
		map[string]string{"project": f.project, "vcs_connection": connection}, nil)
}

// createInventory creates a VCS inventory naming the first organization's own connection and
// returns its identifier.
func (f *vcsConnectionScopeFixture) createInventory(t *testing.T) string {
	t.Helper()
	code, body := f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/inventories", f.inventoryDocument(t, f.ownConnection))
	if code != http.StatusCreated {
		t.Fatalf("creating an inventory with its organization's connection: %d %s", code, body)
	}
	var doc struct {
		Data storedAsSentResource `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Data.ID == "" {
		t.Fatalf("decoding the created inventory: %v (%s)", err, body)
	}
	return doc.Data.ID
}

// queuedCloneURLs is the clone URL of every inventory sync the handlers queued.
func (f *vcsConnectionScopeFixture) queuedCloneURLs(t *testing.T) []string {
	t.Helper()
	var urls []string
	for _, payload := range f.queue.payloads {
		message, ok := payload.(InventorySyncMessage)
		if !ok {
			t.Fatalf("queued %T, want an InventorySyncMessage", payload)
		}
		urls = append(urls, message.CloneURL)
	}
	return urls
}

func TestInventoryVCSConnection_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupVCSConnectionScope(t)
	own := f.createInventory(t)
	f.queue.payloads = nil
	inventoriesOf := func(t *testing.T) int64 {
		t.Helper()
		return f.rows(t, "SELECT count(*) FROM ansible_inventories WHERE project_id = ?", f.projectID)
	}
	before := inventoriesOf(t)

	t.Run("a create", func(t *testing.T) {
		assertConnectionRefused(t, func(connection string) (int, []byte) {
			return f.send(t, http.MethodPost, "/api/v2/organizations/"+f.orgName+"/ansible/inventories", f.inventoryDocument(t, connection))
		}, f.otherConnection)
	})
	t.Run("an update", func(t *testing.T) {
		assertConnectionRefused(t, func(connection string) (int, []byte) {
			return f.send(t, http.MethodPatch, "/api/v2/ansible/inventories/"+own,
				neighbourDocument(t, "ansible-inventories", map[string]any{}, map[string]string{"vcs_connection": connection}, nil))
		}, f.otherConnection)
	})

	if got := inventoriesOf(t) - before; got != 0 {
		t.Errorf("the refused requests left %d inventor(ies) behind", got)
	}
	if got := f.naming(t, "ansible_inventories"); got != 0 {
		t.Errorf("%d inventor(ies) name the other organization's connection", got)
	}
	if got := f.connectionOf(t, "ansible_inventories", own); got != f.ownConnection {
		t.Errorf("after the refused updates the inventory names %q, want %q", got, f.ownConnection)
	}
	if len(f.queue.payloads) != 0 {
		t.Errorf("the refused requests queued %d sync(s)", len(f.queue.payloads))
	}
}

func TestInventoryVCSConnection_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupVCSConnectionScope(t)

	created := f.createInventory(t)
	if got := f.connectionOf(t, "ansible_inventories", created); got != f.ownConnection {
		t.Errorf("the inventory names connection %q, want %q", got, f.ownConnection)
	}
	// The create queues the first sync, with the clone URL its own connection builds.
	if urls := f.queuedCloneURLs(t); len(urls) != 1 || !strings.Contains(urls[0], ownVCSToken) {
		t.Errorf("the create queued clone URLs %q, want one built with the organization's own token", urls)
	}

	code, body := f.send(t, http.MethodPatch, "/api/v2/ansible/inventories/"+created,
		neighbourDocument(t, "ansible-inventories", map[string]any{}, map[string]string{"vcs_connection": f.ownConnection2}, nil))
	if code != http.StatusOK {
		t.Fatalf("changing to another connection of the organization: %d %s", code, body)
	}
	if got := f.connectionOf(t, "ansible_inventories", created); got != f.ownConnection2 {
		t.Errorf("after the change the inventory names %q, want %q", got, f.ownConnection2)
	}
}

// TestInventoryVCSConnection_StoredRowIsNotTrusted writes an inventory row directly, the way one
// stored before the API checked the connection would be, and asks for a sync of it.
func TestInventoryVCSConnection_StoredRowIsNotTrusted(t *testing.T) {
	f := setupVCSConnectionScope(t)
	other := uuid.MustParse(f.otherConnection)
	stored := &models.AnsibleInventory{
		ID: uuid.New(), OrganizationID: f.orgID, ProjectID: &f.projectID, Name: "vcsscope-stored-" + uuid.NewString()[:8],
		Type: models.InventoryTypeVCS, VCSConnectionID: &other, VCSRepository: "acme/inventories", VCSBranch: "main", InventoryPath: "hosts.yml",
	}
	if err := f.db.Create(stored).Error; err != nil {
		t.Fatalf("writing the inventory row: %v", err)
	}

	code, body := f.send(t, http.MethodPost, "/api/v2/ansible/inventories/"+stored.ID.String()+"/actions/sync", "")
	if code >= 500 {
		t.Errorf("the sync request failed on the server: %d %s", code, body)
	}
	for _, cloneURL := range f.queuedCloneURLs(t) {
		if cloneURL != "" {
			t.Errorf("a sync was queued with a clone URL for an inventory naming another organization's connection")
		}
		if strings.Contains(cloneURL, otherVCSToken) {
			t.Errorf("the queued sync carries the other organization's token")
		}
	}
}
