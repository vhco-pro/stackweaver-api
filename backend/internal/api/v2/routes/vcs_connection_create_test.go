// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// POST /api/v2/organizations/:name/vcs-connections answered 409 "VCS connection for this
// provider already exists" for every valid request, on an organization with no connection at
// all. The handler asked the repository for an existing connection and tested the returned
// pointer for nil, and the repository returned a pointer to an empty connection together with
// its not-found error.
//
// This drives the router the server mounts: the first create for a provider is accepted, another
// account of that provider is accepted too (#938), and the same account again is the conflict
// the check exists for.

//go:build integration

package routes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestVCSConnectionCreate_ConflictsOnlyWithAnExistingConnection(t *testing.T) {
	h := setupGoldenHarness(t)

	var owner models.User
	if err := h.db.Raw(`
		SELECT u.* FROM users u JOIN api_keys k ON k.user_id = u.id
		WHERE k.name = 'golden-harness' LIMIT 1`).Scan(&owner).Error; err != nil || owner.ID == uuid.Nil {
		t.Fatalf("find the harness user: %v", err)
	}

	// An organization of its own, so "no connection at all" is true by construction rather than
	// by what the seeder happens to create. The harness database is a throwaway, dropped when
	// the test ends.
	org := models.Organization{ID: uuid.New(), Name: "vcs-create-" + uuid.NewString()[:8]}
	owners := models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	for _, row := range []any{&org, &owners, &models.TeamMember{TeamID: owners.ID, UserID: owner.ID}} {
		if err := h.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	create := func(t *testing.T, provider models.VCSProvider, account string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"data": map[string]any{"type": "vcs-connections", "attributes": map[string]string{
			"provider":     string(provider),
			"access_token": "not-a-real-token",
			"account_name": account,
			"account_type": "organization",
		}}})
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"/api/v2/organizations/"+org.Name+"/vcs-connections", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+h.token)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		return rec
	}
	stored := func(t *testing.T, provider models.VCSProvider) []models.VCSConnection {
		t.Helper()
		var rows []models.VCSConnection
		if err := h.db.Where("organization_id = ? AND provider = ?", org.ID, provider).Find(&rows).Error; err != nil {
			t.Fatalf("load %s connections: %v", provider, err)
		}
		return rows
	}

	// The steps build on each other, so a failed one stops the test. They use GitHub token
	// connections: an Azure DevOps create must prove its token against the Azure DevOps
	// organization it names, which a fake token cannot (the last step). This test used Azure
	// DevOps for the first two steps until that check existed.
	rec := create(t, models.VCSProviderGitHub, "first")
	if rec.Code != http.StatusCreated {
		t.Fatalf("the first %s connection of an organization with none = %d, want 201.\nbody: %s",
			models.VCSProviderGitHub, rec.Code, rec.Body.String())
	}
	var doc struct {
		Data struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the 201 body is not JSON: %v\nbody: %s", err, rec.Body.String())
	}
	rows := stored(t, models.VCSProviderGitHub)
	if len(rows) != 1 || rows[0].ID.String() != doc.Data.ID || rows[0].AccountName != "first" {
		t.Fatalf("after the create the organization holds %d %s connection(s), want the one the response names (%s)",
			len(rows), models.VCSProviderGitHub, doc.Data.ID)
	}

	// One connection per account, not per provider (#938): another account of the same provider
	// is accepted, and the same account in any case is the conflict.
	rec = create(t, models.VCSProviderGitHub, "second")
	if rec.Code != http.StatusCreated {
		t.Fatalf("a %s connection for another account = %d, want 201.\nbody: %s", models.VCSProviderGitHub, rec.Code, rec.Body.String())
	}
	rec = create(t, models.VCSProviderGitHub, "FIRST")
	if rec.Code != http.StatusConflict {
		t.Fatalf("a second %s connection for the same account in another case = %d, want 409.\nbody: %s", models.VCSProviderGitHub, rec.Code, rec.Body.String())
	}
	if rows := stored(t, models.VCSProviderGitHub); len(rows) != 2 {
		t.Fatalf("after a refused create the organization holds %d %s connection(s), want 2", len(rows), models.VCSProviderGitHub)
	}

	// An Azure DevOps connection whose token cannot reach the Azure DevOps organization it names
	// is refused and not stored, so nobody can claim another tenant's Azure DevOps organization.
	// The check fails closed, so this holds with or without network access.
	rec = create(t, models.VCSProviderAzureDevOps, "contoso-"+uuid.NewString()[:8])
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an %s connection with an unprovable token = %d, want 422.\nbody: %s",
			models.VCSProviderAzureDevOps, rec.Code, rec.Body.String())
	}
	if rows := stored(t, models.VCSProviderAzureDevOps); len(rows) != 0 {
		t.Fatalf("a refused %s create stored %d connection(s)", models.VCSProviderAzureDevOps, len(rows))
	}

	// The resource carries installation_id (#938, AC-13): the installation of an App connection,
	// empty for a token connection. It is an identifier GitHub shows in the installation's
	// settings URL, not a secret.
	app := models.VCSConnection{ID: uuid.New(), OrganizationID: org.ID, Provider: models.VCSProviderGitHub, InstallationID: "424242", AccountName: "app-account", AccountType: "Organization"}
	if err := h.db.Create(&app).Error; err != nil {
		t.Fatalf("seed an App connection: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/organizations/"+org.Name+"/vcs-connections", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	rec = httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list connections = %d.\nbody: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Data []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	seen := 0
	for _, d := range list.Data {
		got, present := d.Attributes["installation_id"]
		if !present {
			t.Errorf("connection %s has no installation_id attribute", d.ID)
			continue
		}
		seen++
		want := ""
		if d.ID == app.ID.String() {
			want = "424242"
		}
		if got != want {
			t.Errorf("connection %s installation_id = %v, want %q", d.ID, got, want)
		}
	}
	if seen < 3 {
		t.Errorf("checked %d connection(s), want the two token connections and the App connection", seen)
	}
}
