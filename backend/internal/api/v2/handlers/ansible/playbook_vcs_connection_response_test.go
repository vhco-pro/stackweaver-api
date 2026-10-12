// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a playbook response says of the VCS connection the playbook names (#916). A response
// describes the connection by its provider and its account name, and it describes only a
// connection of the playbook's own organization.
//
// The defect this test was written against: the response took both from the connection the
// playbook row was loaded with, which is whatever row the playbook names. The API refuses to
// store a connection of another organization, but a playbook row written before it did may name
// one, and reading such a playbook showed the other organization's account name.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestPlaybookVCSConnection_StoredRowIsNotDescribed

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
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// TestPlaybookVCSConnection_StoredRowIsNotDescribed writes a playbook row directly, the way one
// stored before the API checked the connection would be, and reads it: on its own, and in the
// organization's and the project's list.
func TestPlaybookVCSConnection_StoredRowIsNotDescribed(t *testing.T) {
	f := setupVCSConnectionScope(t)
	db := f.db
	account := func(connection string) string {
		t.Helper()
		var row models.VCSConnection
		if err := db.First(&row, "id = ?", connection).Error; err != nil {
			t.Fatalf("reading connection %s: %v", connection, err)
		}
		return row.AccountName
	}
	ownAccount, otherAccount := account(f.ownConnection), account(f.otherConnection)

	// The read routes, over a handler of this test's own: the shared fixture mounts the writes.
	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	playbooks := NewPlaybookHandler(
		repository.NewAnsiblePlaybookRepository(db), repository.NewAnsibleJobTemplateRepository(db), repository.NewAnsibleJobRepository(db),
		repository.NewAnsibleScheduleRepository(db), projectRepo, orgRepo, auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo),
		nil, nil, repository.NewVCSConnectionRepository(db), nil,
	)
	router := storedAsSentRouter()
	router.GET("/api/v2/ansible/playbooks/:id", playbooks.GetPlaybook)
	router.GET("/api/v2/organizations/:name/ansible/playbooks", playbooks.ListPlaybooksByOrganization)
	router.GET("/api/v2/projects/:id/ansible/playbooks", playbooks.ListPlaybooks)

	stored := func(connection string) string {
		t.Helper()
		id := uuid.MustParse(connection)
		playbook := &models.AnsiblePlaybook{
			ID: uuid.New(), ProjectID: f.projectID, Name: "vcsscope-stored-" + uuid.NewString()[:8],
			PlaybookPath: "site.yml", SourceMode: models.PlaybookSourceModeCached,
			VCSConnectionID: &id, VCSRepository: "acme/playbooks", VCSBranch: "main",
		}
		if err := db.Create(playbook).Error; err != nil {
			t.Fatalf("writing the playbook row: %v", err)
		}
		return playbook.ID.String()
	}
	storedEarlier, own := stored(f.otherConnection), stored(f.ownConnection)

	// description is what a response says of one playbook's connection.
	type description struct{ provider, account string }
	described := func(t *testing.T, path string) map[string]description {
		t.Helper()
		code, body := storedAsSentCall(t, router, http.MethodGet, path, f.member, "")
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, code, body)
		}
		if strings.Contains(string(body), otherAccount) {
			t.Errorf("GET %s carries the other organization's account name", path)
		}
		var doc struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("decoding the response of %s: %v", path, err)
		}
		// A list is an array of resources and a read is one.
		var resources []storedAsSentResource
		if err := json.Unmarshal(doc.Data, &resources); err != nil {
			var one storedAsSentResource
			if err := json.Unmarshal(doc.Data, &one); err != nil {
				t.Fatalf("decoding the data of %s: %v", path, err)
			}
			resources = []storedAsSentResource{one}
		}
		out := map[string]description{}
		for _, r := range resources {
			provider, _ := r.Attributes["vcs-provider"].(string)
			name, _ := r.Attributes["vcs-account-name"].(string)
			out[r.ID] = description{provider, name}
		}
		return out
	}

	reads := []struct {
		name, path string
		lists      []string // the playbooks the response must hold
	}{
		{"a read of the playbook", "/api/v2/ansible/playbooks/" + storedEarlier, []string{storedEarlier}},
		{"a read of a playbook naming its own organization's connection", "/api/v2/ansible/playbooks/" + own, []string{own}},
		{"the organization's list", "/api/v2/organizations/" + f.orgName + "/ansible/playbooks?page[size]=100", []string{storedEarlier, own}},
		{"the project's list", "/api/v2/projects/" + f.project + "/ansible/playbooks?page[size]=100", []string{storedEarlier, own}},
	}
	for _, read := range reads {
		t.Run(read.name, func(t *testing.T) {
			got := described(t, read.path)
			for _, id := range read.lists {
				if _, ok := got[id]; !ok {
					t.Fatalf("the response does not hold playbook %s", id)
				}
			}
			if d, ok := got[storedEarlier]; ok && d != (description{}) {
				t.Errorf("the playbook naming another organization's connection is described as %+v, want nothing", d)
			}
			if d, ok := got[own]; ok && d != (description{provider: "gitlab", account: ownAccount}) {
				t.Errorf("the playbook naming its organization's connection is described as %+v, want its provider and account name", d)
			}
		})
	}
}
