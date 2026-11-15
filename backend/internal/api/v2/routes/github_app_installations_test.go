// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// GET /api/v2/github-app/installations and GET /api/v2/github-app/installation/:id are the TFE
// routes behind terraform-provider-tfe's tfe_github_app_installation data source (#938, AC-10,
// AC-11). Installations are organization-bound: a caller sees the installations connected in
// organizations they belong to, an organization token only those of its organization, each
// installation once however many organizations connected it.

//go:build integration

package routes_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

type installationDoc struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		InstallationID   int64  `json:"installation-id"`
		Name             string `json:"name"`
		InstallationType string `json:"installation-type"`
		InstallationURL  string `json:"installation-url"`
	} `json:"attributes"`
}

func TestGitHubAppInstallations_OrganizationBound(t *testing.T) {
	h := setupGoldenHarness(t)
	var owner models.User
	if err := h.db.Raw(`
		SELECT u.* FROM users u JOIN api_keys k ON k.user_id = u.id
		WHERE k.name = 'golden-harness' LIMIT 1`).Scan(&owner).Error; err != nil || owner.ID == uuid.Nil {
		t.Fatalf("find the harness user: %v", err)
	}
	sfx := uuid.NewString()[:8]
	member := func(name string) models.Organization {
		org := models.Organization{ID: uuid.New(), Name: name + "-" + sfx}
		owners := models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
		for _, row := range []any{&org, &owners, &models.TeamMember{TeamID: owners.ID, UserID: owner.ID}} {
			if err := h.db.Create(row).Error; err != nil {
				t.Fatalf("seed %T: %v", row, err)
			}
		}
		return org
	}
	orgA, orgB := member("ghinst-a"), member("ghinst-b")
	stranger := models.Organization{ID: uuid.New(), Name: "ghinst-c-" + sfx}
	if err := h.db.Create(&stranger).Error; err != nil {
		t.Fatalf("seed stranger: %v", err)
	}
	base := time.Now().UnixNano() % 10_000_000
	inst := func(n int) string { return fmt.Sprintf("71%07d%d", base, n) }
	shared, onlyB, foreign := inst(1), inst(2), inst(3)
	for _, c := range []models.VCSConnection{
		{OrganizationID: orgA.ID, InstallationID: shared, AccountName: "acme-" + sfx, AccountType: "Organization"},
		{OrganizationID: orgB.ID, InstallationID: shared, AccountName: "acme-" + sfx, AccountType: "Organization"},
		{OrganizationID: orgB.ID, InstallationID: onlyB, AccountName: "octo-" + sfx, AccountType: "User"},
		{OrganizationID: stranger.ID, InstallationID: foreign, AccountName: "other-" + sfx, AccountType: "Organization"},
	} {
		c.ID, c.Provider = uuid.New(), models.VCSProviderGitHub
		if err := h.db.Create(&c).Error; err != nil {
			t.Fatalf("seed connection: %v", err)
		}
	}

	get := func(t *testing.T, path, token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		return rec
	}
	list := func(t *testing.T, query, token string) []installationDoc {
		t.Helper()
		rec := get(t, "/api/v2/github-app/installations"+query, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("list%s = %d, want 200.\nbody: %s", query, rec.Code, rec.Body.String())
		}
		var doc struct {
			Data []installationDoc `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return doc.Data
	}
	ids := func(docs []installationDoc) []string {
		out := make([]string, 0, len(docs))
		for _, d := range docs {
			out = append(out, d.ID)
		}
		sort.Strings(out)
		return out
	}
	equal := func(got []string, want ...string) bool {
		sort.Strings(want)
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	t.Run("a member sees each installation of their organizations once", func(t *testing.T) {
		docs := list(t, "", h.token)
		var mine []installationDoc
		for _, d := range docs {
			if d.ID == shared || d.ID == onlyB || d.ID == foreign {
				mine = append(mine, d)
			}
		}
		if got := ids(mine); !equal(got, shared, onlyB) {
			t.Fatalf("listed %v, want %s and %s once each and never %s", got, shared, onlyB, foreign)
		}
		for _, d := range mine {
			if d.Type != "github-app-installations" || d.Attributes.InstallationID == 0 || d.Attributes.Name == "" || d.Attributes.InstallationType == "" || d.Attributes.InstallationURL == "" {
				t.Errorf("installation %s has an incomplete document: %+v", d.ID, d)
			}
			if d.ID == shared && d.Attributes.Name != "acme-"+sfx {
				t.Errorf("installation %s is named %q, want acme-%s", d.ID, d.Attributes.Name, sfx)
			}
		}
	})
	t.Run("filter by name and by installation id", func(t *testing.T) {
		if got := ids(list(t, "?filter[name]=octo-"+sfx, h.token)); !equal(got, onlyB) {
			t.Errorf("filter[name] listed %v, want %s", got, onlyB)
		}
		if got := ids(list(t, "?filter[installation_id]="+shared, h.token)); !equal(got, shared) {
			t.Errorf("filter[installation_id] listed %v, want %s", got, shared)
		}
	})
	t.Run("one installation by id", func(t *testing.T) {
		if rec := get(t, "/api/v2/github-app/installation/"+shared, h.token); rec.Code != http.StatusOK {
			t.Errorf("a visible installation = %d, want 200.\nbody: %s", rec.Code, rec.Body.String())
		}
		for _, id := range []string{foreign, "9999999999"} {
			if rec := get(t, "/api/v2/github-app/installation/"+id, h.token); rec.Code != http.StatusNotFound {
				t.Errorf("installation %s = %d, want 404", id, rec.Code)
			}
		}
	})
	t.Run("an organization token sees only its organization's installations", func(t *testing.T) {
		keys := apikey.NewService(repository.NewAPIKeyRepository(h.db), repository.NewOrganizationRepository(h.db),
			repository.NewProjectRepository(h.db), repository.NewTeamRepository(h.db))
		_, token, err := keys.CreateAPIKey(owner.ID, "ghinst-"+sfx, []string{"org:" + orgA.ID.String() + ":read"}, nil)
		if err != nil {
			t.Fatalf("mint an organization token: %v", err)
		}
		var mine []installationDoc
		for _, d := range list(t, "", token) {
			if d.ID == shared || d.ID == onlyB || d.ID == foreign {
				mine = append(mine, d)
			}
		}
		if got := ids(mine); !equal(got, shared) {
			t.Errorf("an organization A token listed %v, want only %s", got, shared)
		}
		if rec := get(t, "/api/v2/github-app/installation/"+onlyB, token); rec.Code != http.StatusNotFound {
			t.Errorf("organization B's installation through an organization A token = %d, want 404", rec.Code)
		}
	})
	t.Run("a user token an organization's policy turns away sees none of its installations", func(t *testing.T) {
		// The user belongs to this organization through a team that does not own it, and the
		// organization disables user tokens: the org wall refuses this token there, so neither
		// route may show that organization's installation.
		off := false
		closed := models.Organization{ID: uuid.New(), Name: "ghinst-d-" + sfx, UserTokensEnabled: &off}
		devs := models.Team{ID: uuid.New(), OrganizationID: closed.ID, Name: "devs"}
		policyInst := inst(4)
		for _, row := range []any{
			&closed, &devs, &models.TeamMember{TeamID: devs.ID, UserID: owner.ID},
			&models.OrganizationMember{ID: uuid.New(), OrganizationID: closed.ID, UserID: owner.ID},
			&models.VCSConnection{ID: uuid.New(), OrganizationID: closed.ID, Provider: models.VCSProviderGitHub, InstallationID: policyInst, AccountName: "closed-" + sfx, AccountType: "Organization"},
		} {
			if err := h.db.Create(row).Error; err != nil {
				t.Fatalf("seed %T: %v", row, err)
			}
		}
		// UserTokensEnabled carries a default, so false is written explicitly.
		if err := h.db.Model(&models.Organization{}).Where("id = ?", closed.ID).Update("user_tokens_enabled", false).Error; err != nil {
			t.Fatal(err)
		}
		if rec := get(t, "/api/v2/organizations/"+closed.Name, h.token); rec.Code != http.StatusForbidden {
			t.Fatalf("precondition: reading the organization with this user token = %d, want 403", rec.Code)
		}
		for _, d := range list(t, "", h.token) {
			if d.ID == policyInst {
				t.Errorf("the list shows installation %s of an organization that refuses this token", policyInst)
			}
		}
		if rec := get(t, "/api/v2/github-app/installation/"+policyInst, h.token); rec.Code != http.StatusNotFound {
			t.Errorf("the installation of an organization that refuses this token = %d, want 404", rec.Code)
		}
	})
}
