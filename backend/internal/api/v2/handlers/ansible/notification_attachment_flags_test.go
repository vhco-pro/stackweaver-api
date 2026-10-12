// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// A notification attachment created with `on_success: false` and `on_failure: false` must be
// stored with both off, so that "on start only" can be configured, and one created without the
// keys must have both on. The template notifications card sends all three flags on every attach,
// and the stackweaver Terraform provider sends both as plain booleans.
//
// The defect this test was written against: AnsibleNotificationAttachment.OnSuccess and OnFailure
// carried `gorm:"default:true"`, and GORM substitutes a literal default for a zero value in the
// INSERT (and writes it back into the struct), so an unticked flag was stored and answered as
// true. There is no update endpoint, so false could not be stored by any path. The default lives
// in NotificationHandler.Attach instead.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestNotificationAttachment_Flags

//go:build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// storedAsSentRouter is a gin engine that authenticates the caller from the X-Test-User header.
func storedAsSentRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	return router
}

// storedAsSentCall sends one request as the given user and returns the status and the raw body.
func storedAsSentCall(t *testing.T, router http.Handler, method, path string, asUser uuid.UUID, body string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-User", asUser.String())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec.Code, rec.Body.Bytes()
}

// storedAsSentResource is one JSON:API resource of a response: its id and attributes.
type storedAsSentResource struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
}

// assertStoredBool checks one boolean attribute of a response: present, a boolean, and want.
func assertStoredBool(t *testing.T, where string, attrs map[string]any, attr string, want bool) {
	t.Helper()
	got, ok := attrs[attr].(bool)
	if !ok {
		t.Errorf("%s: %s is %v (%T), want a boolean", where, attr, attrs[attr], attrs[attr])
		return
	}
	if got != want {
		t.Errorf("%s: %s = %t, want %t", where, attr, got, want)
	}
}

func TestNotificationAttachment_FlagsAreStoredAsSent(t *testing.T) {
	f := setupAnsibleSubResourceAuthz(t) // org A with an owner and a job template; cleans up after itself
	db := f.db
	if err := db.AutoMigrate(
		&models.AnsibleNotificationTemplate{}, &models.AnsibleNotificationAttachment{}, &models.AnsibleWorkflow{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	templateID := uuid.MustParse(f.templateID)

	var org models.Organization
	if err := db.Joins("JOIN ansible_inventories ON ansible_inventories.organization_id = organizations.id").
		Where("ansible_inventories.id = ?", f.inventoryID).First(&org).Error; err != nil {
		t.Fatalf("find the fixture organization: %v", err)
	}
	channel := &models.AnsibleNotificationTemplate{
		ID: uuid.New(), OrganizationID: org.ID, Name: "attflags-" + uuid.NewString()[:8], Type: models.NotificationTypeWebhook,
	}
	if err := db.Create(channel).Error; err != nil {
		t.Fatalf("seed notification template: %v", err)
	}
	t.Cleanup(func() {
		// Registered after the fixture's cleanup, so it runs first: the attachments go before the
		// job template they point at. Row-scoped to this test's own channel.
		db.Where("notification_template_id = ?", channel.ID).Delete(&models.AnsibleNotificationAttachment{})
		db.Where("id = ?", channel.ID).Delete(&models.AnsibleNotificationTemplate{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	h := NewNotificationHandler(
		repository.NewAnsibleNotificationRepository(db),
		repository.NewAnsibleJobTemplateRepository(db),
		repository.NewAnsibleWorkflowRepository(db),
		orgRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db)),
		nil, // cryptoService - attachments carry no secret
		nil, // notificationSvc - only reached by the test-send action
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/organizations/:name/ansible/notification-attachments", h.Attach)
	router.GET("/api/v2/ansible/job-templates/:id/notifications", h.ListForJobTemplate)

	sent := func(v bool) *bool { return &v }
	cases := []struct {
		name                 string
		onSuccess, onFailure *bool // nil leaves the key out
		wantSuccess          bool
		wantFailure          bool
	}{
		{"both false", sent(false), sent(false), false, false},
		{"failure false only", sent(true), sent(false), true, false},
		{"both true", sent(true), sent(true), true, true},
		{"both absent", nil, nil, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The attach body is flat JSON with snake_case keys; the response is JSON:API with
			// kebab-case attributes.
			req := map[string]any{
				"notification_template_id": channel.ID.String(),
				"job_template_id":          templateID.String(),
				"on_started":               true,
			}
			if tc.onSuccess != nil {
				req["on_success"] = *tc.onSuccess
			}
			if tc.onFailure != nil {
				req["on_failure"] = *tc.onFailure
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			code, body := storedAsSentCall(t, router, http.MethodPost,
				"/api/v2/organizations/"+org.Name+"/ansible/notification-attachments", f.owner.ID, string(raw))
			if code != http.StatusCreated {
				t.Fatalf("attach = %d, want 201 (%s)", code, body)
			}
			var created struct {
				Data storedAsSentResource `json:"data"`
			}
			if err := json.Unmarshal(body, &created); err != nil {
				t.Fatalf("decode attach response: %v\n%s", err, body)
			}
			assertStoredBool(t, "attach response", created.Data.Attributes, "on-success", tc.wantSuccess)
			assertStoredBool(t, "attach response", created.Data.Attributes, "on-failure", tc.wantFailure)
			assertStoredBool(t, "attach response", created.Data.Attributes, "on-started", true)

			code, body = storedAsSentCall(t, router, http.MethodGet,
				"/api/v2/ansible/job-templates/"+templateID.String()+"/notifications", f.owner.ID, "")
			if code != http.StatusOK {
				t.Fatalf("list = %d, want 200 (%s)", code, body)
			}
			var listed struct {
				Data []storedAsSentResource `json:"data"`
			}
			if err := json.Unmarshal(body, &listed); err != nil {
				t.Fatalf("decode list response: %v\n%s", err, body)
			}
			for _, item := range listed.Data {
				if item.ID != created.Data.ID {
					continue
				}
				assertStoredBool(t, "attachment list", item.Attributes, "on-success", tc.wantSuccess)
				assertStoredBool(t, "attachment list", item.Attributes, "on-failure", tc.wantFailure)
				return
			}
			t.Errorf("the attachment list for the template does not contain %s", created.Data.ID)
		})
	}
}
