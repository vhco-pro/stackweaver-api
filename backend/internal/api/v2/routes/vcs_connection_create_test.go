// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// POST /api/v2/organizations/:name/vcs-connections answered 409 "VCS connection for this
// provider already exists" for every valid request, on an organization with no connection at
// all. The handler asked the repository for an existing connection and tested the returned
// pointer for nil, and the repository returned a pointer to an empty connection together with
// its not-found error.
//
// This drives the router the server mounts: the first create for a provider is accepted, a
// second for the same provider is the conflict the check exists for, and another provider is
// still accepted afterwards.

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

	// The steps build on each other, so a failed one stops the test.
	rec := create(t, models.VCSProviderGitLab, "first")
	if rec.Code != http.StatusCreated {
		t.Fatalf("the first %s connection of an organization with none = %d, want 201.\nbody: %s",
			models.VCSProviderGitLab, rec.Code, rec.Body.String())
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
	rows := stored(t, models.VCSProviderGitLab)
	if len(rows) != 1 || rows[0].ID.String() != doc.Data.ID || rows[0].AccountName != "first" {
		t.Fatalf("after the create the organization holds %d %s connection(s), want the one the response names (%s)",
			len(rows), models.VCSProviderGitLab, doc.Data.ID)
	}

	rec = create(t, models.VCSProviderGitLab, "second")
	if rec.Code != http.StatusConflict {
		t.Fatalf("a second %s connection = %d, want 409.\nbody: %s", models.VCSProviderGitLab, rec.Code, rec.Body.String())
	}
	if rows := stored(t, models.VCSProviderGitLab); len(rows) != 1 || rows[0].AccountName != "first" {
		t.Fatalf("a refused create left %d %s connection(s), want the first one untouched", len(rows), models.VCSProviderGitLab)
	}

	// The conflict is per provider, not per organization.
	rec = create(t, models.VCSProviderBitbucket, "third")
	if rec.Code != http.StatusCreated {
		t.Fatalf("a %s connection beside a %s one = %d, want 201.\nbody: %s",
			models.VCSProviderBitbucket, models.VCSProviderGitLab, rec.Code, rec.Body.String())
	}
}
