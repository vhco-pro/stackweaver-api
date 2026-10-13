// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A GitHub App `installation created` delivery is acknowledged and changes nothing.
//
// The handler used to carry a branch that connected the organization whose NAME equalled the
// installing GitHub account's login. A broken lookup kept that branch from ever writing a row,
// which hid what it would have done: on an app installable by any account, whoever holds a
// GitHub login equal to an organization's name could give that organization a connection to
// their own account, or point its existing connection at their own installation. The branch
// was removed rather than repaired. A connection is made through the interactive flow, where a
// signed-in user names the organization (InitiateInstallation, then
// CreateConnectionFromInstallation), and by nothing else.
//
// So the cases here hold a delivery whose login equals an organization's name to leaving that
// organization exactly as it was, with no connection and with one, and a third pins the
// `deleted` event, which shares the handler and must keep working.
//
// The webhook route is registered only when a GitHub App is configured, which a test cannot do
// without a real app's private key, so this calls the handler with a signed delivery instead of
// going through the router. The route has no path parameters for a handler to misread.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the dev DB has no backup).

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// installationWebhookFixture is the handler with a webhook secret, on the test database.
type installationWebhookFixture struct {
	db      *gorm.DB
	handler *VCSAppInstallationHandlerV2
	secret  string
	// nextInstallation hands out installation ids unique to this run, so cleanup can reach a
	// row by its installation even when it was written for the wrong organization.
	nextInstallation int64
}

func setupInstallationWebhook(t *testing.T) *installationWebhookFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	// The whole schema: deleting a connection detaches workspaces and modules first.
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	f := &installationWebhookFixture{
		db:               db,
		secret:           "installation-webhook-test-secret",
		nextInstallation: time.Now().UnixNano() % 1_000_000_000_000,
	}
	t.Setenv("GITHUB_WEBHOOK_SECRET", f.secret)
	t.Setenv("GITHUB_APP_ID", "") // a disabled manager still carries the secret
	manager, err := vcs.NewGitHubAppManager()
	if err != nil {
		t.Fatalf("NewGitHubAppManager: %v", err)
	}
	f.handler = &VCSAppInstallationHandlerV2{
		vcsConnectionRepo: repository.NewVCSConnectionRepository(db),
		orgRepo:           repository.NewOrganizationRepository(db),
		githubAppManager:  manager,
	}
	gin.SetMode(gin.TestMode)
	return f
}

// installation returns a fresh installation id and registers the removal of any connection
// that ends up carrying it.
func (f *installationWebhookFixture) installation(t *testing.T) int64 {
	t.Helper()
	f.nextInstallation++
	id := f.nextInstallation
	t.Cleanup(func() {
		f.db.Delete(&models.VCSConnection{}, "installation_id = ?", strconv.FormatInt(id, 10))
	})
	return id
}

// organization seeds an organization and registers its removal, connections first.
func (f *installationWebhookFixture) organization(t *testing.T) *models.Organization {
	t.Helper()
	org := &models.Organization{ID: uuid.New(), Name: "wh-install-" + uuid.NewString()[:8]}
	if err := f.db.Create(org).Error; err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	t.Cleanup(func() {
		f.db.Delete(&models.VCSConnection{}, "organization_id = ?", org.ID)
		f.db.Delete(&models.Organization{}, "id = ?", org.ID)
	})
	return org
}

// deliver sends a signed `installation` event for an organization account with the given login.
func (f *installationWebhookFixture) deliver(t *testing.T, action, login string, installationID int64) *httptest.ResponseRecorder {
	t.Helper()
	var event struct {
		Action       string `json:"action"`
		Installation struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
				Type  string `json:"type"`
			} `json:"account"`
		} `json:"installation"`
	}
	event.Action = action
	event.Installation.ID = installationID
	event.Installation.Account.Login = login
	event.Installation.Account.Type = "Organization"
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal delivery: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v2/vcs-connections/github/webhook", bytes.NewReader(payload))
	c.Request.Header.Set("X-GitHub-Event", "installation")
	c.Request.Header.Set("X-Hub-Signature-256", githubSign(payload, f.secret))
	f.handler.HandleInstallationWebhook(c)
	c.Writer.WriteHeaderNow()
	return w
}

func (f *installationWebhookFixture) connections(t *testing.T, orgID uuid.UUID) []models.VCSConnection {
	t.Helper()
	var rows []models.VCSConnection
	if err := f.db.Where("organization_id = ?", orgID).Find(&rows).Error; err != nil {
		t.Fatalf("load connections: %v", err)
	}
	return rows
}

// withInstallation counts the connections, of any organization, that carry the installation.
func (f *installationWebhookFixture) withInstallation(t *testing.T, installationID int64) int64 {
	t.Helper()
	var n int64
	if err := f.db.Model(&models.VCSConnection{}).
		Where("installation_id = ?", strconv.FormatInt(installationID, 10)).Count(&n).Error; err != nil {
		t.Fatalf("count connections of installation %d: %v", installationID, err)
	}
	return n
}

func TestInstallationCreatedWebhook_LeavesConnectionsAlone(t *testing.T) {
	f := setupInstallationWebhook(t)

	t.Run("an organization with no connection gets none", func(t *testing.T) {
		org := f.organization(t)
		installation := f.installation(t)

		w := f.deliver(t, "created", org.Name, installation)

		if w.Code != http.StatusOK {
			t.Errorf("delivery = %d, want 200.\nbody: %s", w.Code, w.Body.String())
		}
		if rows := f.connections(t, org.ID); len(rows) != 0 {
			t.Errorf("an account named like the organization installed the app, and the organization now "+
				"holds %d connection(s) (installation %q, account %q); want none",
				len(rows), rows[0].InstallationID, rows[0].AccountName)
		}
		if n := f.withInstallation(t, installation); n != 0 {
			t.Errorf("%d connection(s) carry the delivery's installation; want none", n)
		}
	})

	t.Run("an existing connection is not re-pointed", func(t *testing.T) {
		org := f.organization(t)
		original := f.installation(t)
		existing := &models.VCSConnection{
			ID:             uuid.New(),
			OrganizationID: org.ID,
			Provider:       models.VCSProviderGitHub,
			InstallationID: strconv.FormatInt(original, 10),
			AccountName:    "the-real-account",
			AccountType:    "user",
		}
		if err := f.db.Create(existing).Error; err != nil {
			t.Fatalf("seed connection: %v", err)
		}
		installation := f.installation(t)

		w := f.deliver(t, "created", org.Name, installation)

		if w.Code != http.StatusOK {
			t.Errorf("delivery = %d, want 200.\nbody: %s", w.Code, w.Body.String())
		}
		rows := f.connections(t, org.ID)
		if len(rows) != 1 {
			t.Fatalf("the organization holds %d connection(s), want the one it had", len(rows))
		}
		got := rows[0]
		if got.ID != existing.ID || got.InstallationID != existing.InstallationID ||
			got.AccountName != existing.AccountName || got.AccountType != existing.AccountType {
			t.Errorf("the connection now holds installation %q, account %q (%s); want it untouched at %q, %q (%s)",
				got.InstallationID, got.AccountName, got.AccountType,
				existing.InstallationID, existing.AccountName, existing.AccountType)
		}
		if n := f.withInstallation(t, installation); n != 0 {
			t.Errorf("%d connection(s) carry the delivery's installation; want none", n)
		}
	})
}

// Removing the `created` branch must not take the rest of the installation handling with it:
// when the app is uninstalled, the connection made from that installation still goes.
func TestInstallationDeletedWebhook_RemovesTheConnection(t *testing.T) {
	f := setupInstallationWebhook(t)
	org := f.organization(t)
	installation := f.installation(t)
	other := f.installation(t)
	for _, id := range []int64{installation, other} {
		// Two providers, because an organization holds one connection per provider.
		provider := models.VCSProviderGitHub
		if id == other {
			provider = models.VCSProviderGitLab
		}
		if err := f.db.Create(&models.VCSConnection{
			ID: uuid.New(), OrganizationID: org.ID, Provider: provider,
			InstallationID: strconv.FormatInt(id, 10), AccountName: org.Name, AccountType: "organization",
		}).Error; err != nil {
			t.Fatalf("seed connection for installation %d: %v", id, err)
		}
	}

	w := f.deliver(t, "deleted", org.Name, installation)

	if w.Code != http.StatusOK {
		t.Errorf("delivery = %d, want 200.\nbody: %s", w.Code, w.Body.String())
	}
	if n := f.withInstallation(t, installation); n != 0 {
		t.Errorf("%d connection(s) still carry the uninstalled installation; want none", n)
	}
	if n := f.withInstallation(t, other); n != 1 {
		t.Errorf("%d connection(s) carry the other installation; want the one that was there", n)
	}
}
