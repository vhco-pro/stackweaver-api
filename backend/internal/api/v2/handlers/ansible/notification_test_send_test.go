// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The test-send action delivers through the same guarded transport as the scheduler's
// deliveries: a webhook or Teams template naming a loopback, link-local, private address, or a
// hostname that resolves to one, is refused with 502 and nothing reaches the address, while a
// permitted address is delivered to and answers 204.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestNotificationTestSend

//go:build integration

package ansible

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
)

// testSendHarness is a router serving only the test-send action, over a notification service
// built from the environment at the time of the call.
type testSendHarness struct {
	db     *gorm.DB
	org    models.Organization
	owner  uuid.UUID
	router http.Handler
}

func newTestSendHarness(t *testing.T) *testSendHarness {
	t.Helper()
	f := setupAnsibleSubResourceAuthz(t) // org A with an owner; cleans up after itself
	db := f.db
	if err := db.AutoMigrate(&models.AnsibleNotificationTemplate{}, &models.AnsibleNotificationAttachment{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var org models.Organization
	if err := db.Joins("JOIN ansible_inventories ON ansible_inventories.organization_id = organizations.id").
		Where("ansible_inventories.id = ?", f.inventoryID).First(&org).Error; err != nil {
		t.Fatalf("find the fixture organization: %v", err)
	}

	notificationRepo := repository.NewAnsibleNotificationRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	h := NewNotificationHandler(
		notificationRepo,
		repository.NewAnsibleJobTemplateRepository(db),
		repository.NewAnsibleWorkflowRepository(db),
		orgRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db)),
		nil, // cryptoService - these templates carry no secret
		ansiblesvc.NewNotificationService(notificationRepo, repository.NewAnsibleJobRepository(db), nil),
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/ansible/notification-templates/:id/test", h.TestSend)
	return &testSendHarness{db: db, org: org, owner: f.owner.ID, router: router}
}

// template stores a notification template of the given type delivering to url.
func (h *testSendHarness) template(t *testing.T, kind models.NotificationType, url string) uuid.UUID {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"url": url})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	tmpl := &models.AnsibleNotificationTemplate{
		ID: uuid.New(), OrganizationID: h.org.ID, Name: "testsend-" + uuid.NewString()[:8], Type: kind, Config: raw,
	}
	if err := h.db.Create(tmpl).Error; err != nil {
		t.Fatalf("seed notification template: %v", err)
	}
	t.Cleanup(func() { h.db.Where("id = ?", tmpl.ID).Delete(&models.AnsibleNotificationTemplate{}) })
	return tmpl.ID
}

// send calls the test-send action on a template and returns the status and body.
func (h *testSendHarness) send(t *testing.T, id uuid.UUID) (int, []byte) {
	t.Helper()
	return storedAsSentCall(t, h.router, http.MethodPost, "/api/v2/ansible/notification-templates/"+id.String()+"/test", h.owner, "")
}

// countingReceiver is a loopback listener that counts the deliveries reaching it.
func countingReceiver(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestNotificationTestSend_RefusesNonPublicDestinations(t *testing.T) {
	h := newTestSendHarness(t)
	receiver, hits := countingReceiver(t)
	_, port, err := net.SplitHostPort(receiver.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	destinations := map[string]string{
		"loopback":                       receiver.URL + "/hook",
		"link-local metadata":            "http://169.254.169.254/latest/meta-data/",
		"private":                        "http://10.0.0.1/hook",
		"hostname resolving to loopback": "http://localhost:" + port + "/hook",
	}
	for _, kind := range []models.NotificationType{models.NotificationTypeWebhook, models.NotificationTypeTeams} {
		for name, url := range destinations {
			t.Run(string(kind)+" to "+name, func(t *testing.T) {
				code, body := h.send(t, h.template(t, kind, url))
				if code != http.StatusBadGateway {
					t.Fatalf("test send = %d, want 502 (%s)", code, body)
				}
				if !strings.Contains(string(body), "non-public address") {
					t.Fatalf("test send was not refused by the address guard: %s", body)
				}
			})
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the loopback receiver got %d delivery(ies), want 0", n)
	}
}

func TestNotificationTestSend_DeliversWhenPrivateDestinationsAreAllowed(t *testing.T) {
	t.Setenv("STACKWEAVER_ANSIBLE_NOTIFICATIONS_ALLOW_PRIVATE", "true")
	h := newTestSendHarness(t) // the service reads the switch when it is built
	receiver, hits := countingReceiver(t)

	for _, kind := range []models.NotificationType{models.NotificationTypeWebhook, models.NotificationTypeTeams} {
		if code, body := h.send(t, h.template(t, kind, receiver.URL+"/hook")); code != http.StatusNoContent {
			t.Fatalf("%s test send = %d, want 204 (%s)", kind, code, body)
		}
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("the receiver got %d deliveries, want 2", n)
	}
}
