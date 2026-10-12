// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-124 webhook event attribution. recordWebhookEvent determined the owning org by
// "the first workspace matching this repo name" (FindByVCSRepository, Limit(1), no org
// scope). On a repo-name collision an attacker's payloads are filed into a victim org's
// webhook-event log. The fix derives the org from the validated installation instead.
// This test drives the real handler + Postgres and proves attribution follows the
// installation, not the repo name - with a control showing the old heuristic mis-attributes.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestWebhookEventAttribution

//go:build integration
// +build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

func TestWebhookEventAttribution(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.Organization{}, &models.Project{}, &models.Workspace{},
		&models.VCSConnection{}, &models.WebhookEvent{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	// orgA owns the GitHub App installation "111". orgB happens to have a workspace for the
	// SAME repo full_name "acme/infra" - the collision the attacker exploits.
	orgA := &models.Organization{ID: uuid.New(), Name: "wha-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "wha-b-" + sfx}
	connA := &models.VCSConnection{ID: uuid.New(), OrganizationID: orgA.ID, Provider: models.VCSProviderGitHub, InstallationID: "111-" + sfx}
	projB := &models.Project{ID: uuid.New(), OrganizationID: orgB.ID, Name: "projB-" + sfx}
	wsB := &models.Workspace{ID: "ws-" + sfx, ProjectID: projB.ID, Name: "wsB-" + sfx, VCSRepository: "acme/infra"}

	const repo = "acme/infra"
	newMarker := "new-" + sfx // commit marker for the fixed-path event
	oldMarker := "old-" + sfx // commit marker for the control (heuristic) event

	t.Cleanup(func() {
		db.Where("commit IN ?", []string{newMarker, oldMarker}).Delete(&models.WebhookEvent{})
		db.Where("id = ?", wsB.ID).Delete(&models.Workspace{})
		db.Where("id = ?", projB.ID).Delete(&models.Project{})
		db.Where("id = ?", connA.ID).Delete(&models.VCSConnection{})
		db.Where("id IN ?", []uuid.UUID{orgA.ID, orgB.ID}).Delete(&models.Organization{})
	})
	for _, obj := range []interface{}{orgA, orgB, connA, projB, wsB} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	h := &VCSAppInstallationHandlerV2{
		webhookEventRepo:  repository.NewWebhookEventRepository(db),
		workspaceRepo:     repository.NewWorkspaceRepository(db),
		vcsConnectionRepo: repository.NewVCSConnectionRepository(db),
	}

	// orgFromInstallation resolves strictly by installation id.
	if got := h.orgFromInstallation(connA.InstallationID); got == nil || *got != orgA.ID {
		t.Fatalf("orgFromInstallation(%q) = %v, want orgA %v", connA.InstallationID, got, orgA.ID)
	}
	if got := h.orgFromInstallation("999-" + sfx); got != nil {
		t.Fatalf("orgFromInstallation(unknown) = %v, want nil", got)
	}

	orgOf := func(marker string) *uuid.UUID {
		var ev models.WebhookEvent
		if err := db.Where("commit = ?", marker).First(&ev).Error; err != nil {
			t.Fatalf("load webhook event %q: %v", marker, err)
		}
		return ev.OrganizationID
	}

	// FIXED path: attribution derived from the validated installation "111" (orgA) - even
	// though the only workspace matching repo "acme/infra" belongs to orgB.
	h.recordWebhookEvent(h.orgFromInstallation(connA.InstallationID), "push", "github", repo, "main", newMarker, "ignored", "test", 200, "{}")
	if org := orgOf(newMarker); org == nil || *org != orgA.ID {
		t.Fatalf("AUD-124: event attributed to %v, want installation org orgA %v", org, orgA.ID)
	}

	// CONTROL (pre-fix behavior): with no trusted org, the repo-name heuristic mis-attributes
	// the very same delivery to orgB - the victim. This is exactly the bug the fix removes.
	h.recordWebhookEvent(nil, "push", "github", repo, "main", oldMarker, "ignored", "test", 200, "{}")
	if org := orgOf(oldMarker); org == nil || *org != orgB.ID {
		t.Fatalf("control expectation broken: heuristic attributed to %v, want orgB %v (collision victim)", org, orgB.ID)
	}
}

// TestWebhookEventList_OneProjection pins that the webhook-events list has a single wire shape
// (#844, AC5): `webhook-events` resources with dash-case attributes and the standard
// `meta.pagination` block, whatever the `format` parameter in the URL says.
//
// `?format=simple` used to select a second projection: flat snake_case rows under `data` with a
// `{total, page_size, page_number}` meta. The parameter is now ignored, the way Terraform
// Enterprise ignores a query parameter it does not know, so every value below must produce the
// same document.
func TestWebhookEventList_OneProjection(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(&models.Organization{}, &models.WebhookEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "whl-" + sfx}
	delivered := time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC)
	event := &models.WebhookEvent{
		ID: uuid.New(), OrganizationID: &org.ID,
		EventType: "push", Provider: "github", Repository: "acme/infra-" + sfx, Branch: "main",
		Commit: "c0ffee" + sfx, Status: "success", ResponseCode: 200, Message: "queued run",
		DeliveredAt: delivered,
	}
	t.Cleanup(func() {
		db.Where("id = ?", event.ID).Delete(&models.WebhookEvent{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})
	for _, obj := range []any{org, event} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	h := NewWebhookEventHandlerV2(repository.NewWebhookEventRepository(db), repository.NewOrganizationRepository(db))
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/organizations/:name/webhook-events", h.List)

	for _, suffix := range []string{"", "?format=simple", "?format=json", "?format=anything", "?format="} {
		t.Run("url suffix "+suffix, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/organizations/"+org.Name+"/webhook-events"+suffix, nil)
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}

			var doc struct {
				Data []struct {
					ID         string         `json:"id"`
					Type       string         `json:"type"`
					Attributes map[string]any `json:"attributes"`
					// Members of the retired flat projection; they must never appear on a row.
					EventType   *string `json:"event_type"`
					DeliveredAt *string `json:"delivered_at"`
				} `json:"data"`
				Meta struct {
					Pagination *struct {
						CurrentPage int   `json:"current-page"`
						PageSize    int   `json:"page-size"`
						TotalPages  int   `json:"total-pages"`
						TotalCount  int64 `json:"total-count"`
					} `json:"pagination"`
					// Members of the retired flat meta.
					Total    *int64 `json:"total"`
					PageSize *int   `json:"page_size"`
				} `json:"meta"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
			}

			if len(doc.Data) != 1 {
				t.Fatalf("data has %d rows, want the one seeded delivery (%s)", len(doc.Data), rec.Body.String())
			}
			row := doc.Data[0]
			if row.Type != "webhook-events" || row.ID != event.ID.String() {
				t.Errorf("resource = %s/%s, want webhook-events/%s", row.Type, row.ID, event.ID)
			}
			if row.EventType != nil || row.DeliveredAt != nil {
				t.Error("row carries the flat projection's top-level event_type or delivered_at")
			}
			want := map[string]any{
				"event-type": "push", "provider": "github", "repository": event.Repository,
				"branch": "main", "commit": event.Commit, "status": "success",
				"response-code": float64(200), "message": "queued run",
			}
			for key, wantValue := range want {
				if got := row.Attributes[key]; got != wantValue {
					t.Errorf("attributes[%q] = %v, want %v", key, got, wantValue)
				}
			}
			// Compared as an instant: the zone the timestamp is rendered in follows the database
			// session, which is not what this test is about.
			deliveredAt, _ := row.Attributes["delivered-at"].(string)
			if got, err := time.Parse(time.RFC3339, deliveredAt); err != nil || !got.Equal(delivered) {
				t.Errorf("attributes[\"delivered-at\"] = %q (%v), want the instant %s", deliveredAt, err, delivered.Format(time.RFC3339))
			}

			if doc.Meta.Total != nil || doc.Meta.PageSize != nil {
				t.Error("meta carries the flat projection's total or page_size")
			}
			p := doc.Meta.Pagination
			if p == nil {
				t.Fatalf("meta.pagination is missing (%s)", rec.Body.String())
			}
			if p.CurrentPage != 1 || p.PageSize != 50 || p.TotalPages != 1 || p.TotalCount != 1 {
				t.Errorf("meta.pagination = %+v, want page 1 of 1, size 50, one delivery", *p)
			}
		})
	}
}
