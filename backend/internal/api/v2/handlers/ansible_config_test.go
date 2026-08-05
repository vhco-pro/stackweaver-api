// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Unit tests for the ansible-config JSON:API envelope (#608): responses must
// nest attributes under data.attributes with dasherized keys and express scope
// parents as relationships; requests must arrive in the same envelope. The
// pre-#608 handler emitted flat snake_case attributes on `data`, which the
// SPA and terraform-provider-stackweaver could not consume with the shared
// JSON:API codec.

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

func TestBuildAnsibleConfigResponse_JSONAPIEnvelope(t *testing.T) {
	orgID := uuid.New()
	projectID := uuid.New()
	workspaceID := "ws-123"
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

	t.Run("org-scoped config nests attributes and emits an organization relationship", func(t *testing.T) {
		cfg := &models.AnsibleConfig{
			ID:             uuid.New(),
			OrganizationID: &orgID,
			ConfigContent:  "[defaults]\nforks = 10\n",
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		raw, err := json.Marshal(buildAnsibleConfigResponse(cfg))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var resp struct {
			Type       string `json:"type"`
			ID         string `json:"id"`
			Attributes struct {
				Scope         string `json:"scope"`
				ConfigContent string `json:"config-content"`
				CreatedAt     string `json:"created-at"`
				UpdatedAt     string `json:"updated-at"`
			} `json:"attributes"`
			Relationships struct {
				Organization *struct {
					Data struct {
						Type string `json:"type"`
						ID   string `json:"id"`
					} `json:"data"`
				} `json:"organization"`
				Project *json.RawMessage `json:"project"`
			} `json:"relationships"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Type != "ansible-configs" {
			t.Errorf("type = %q, want ansible-configs", resp.Type)
		}
		if resp.ID != cfg.ID.String() {
			t.Errorf("id = %q, want %q", resp.ID, cfg.ID)
		}
		if resp.Attributes.ConfigContent != cfg.ConfigContent {
			t.Errorf("attributes.config-content = %q, want the config body", resp.Attributes.ConfigContent)
		}
		if resp.Attributes.Scope != "organization" {
			t.Errorf("attributes.scope = %q, want organization", resp.Attributes.Scope)
		}
		if resp.Attributes.CreatedAt != "2026-08-05T12:00:00Z" || resp.Attributes.UpdatedAt != "2026-08-05T12:00:00Z" {
			t.Errorf("timestamps not dasherized/formatted: %+v", resp.Attributes)
		}
		if resp.Relationships.Organization == nil {
			t.Fatal("relationships.organization missing")
		}
		if got := resp.Relationships.Organization.Data; got.Type != "organizations" || got.ID != orgID.String() {
			t.Errorf("organization relationship = %+v, want organizations/%s", got, orgID)
		}
		if resp.Relationships.Project != nil {
			t.Error("relationships.project must be absent for an org-scoped config")
		}

		// The pre-#608 flat keys must be gone from the wire format entirely.
		for _, legacy := range []string{"config_content", "organization_id", "project_id", "workspace_id", "created_at", "updated_at"} {
			if strings.Contains(string(raw), `"`+legacy+`"`) {
				t.Errorf("legacy flat key %q leaked into the JSON:API resource: %s", legacy, raw)
			}
		}
	})

	t.Run("project- and workspace-scoped configs emit their own relationships", func(t *testing.T) {
		cfg := &models.AnsibleConfig{
			ID:            uuid.New(),
			ProjectID:     &projectID,
			WorkspaceID:   &workspaceID,
			ConfigContent: "x",
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		raw, _ := json.Marshal(buildAnsibleConfigResponse(cfg))
		var resp struct {
			Relationships map[string]struct {
				Data struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"data"`
			} `json:"relationships"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := resp.Relationships["project"].Data; got.Type != "projects" || got.ID != projectID.String() {
			t.Errorf("project relationship = %+v", got)
		}
		if got := resp.Relationships["workspace"].Data; got.Type != "workspaces" || got.ID != workspaceID {
			t.Errorf("workspace relationship = %+v", got)
		}
	})
}

func TestAnsibleConfigRequest_Binding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	bind := func(body string) error {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		var req AnsibleConfigRequest
		return c.ShouldBindJSON(&req)
	}

	t.Run("JSON:API envelope binds", func(t *testing.T) {
		if err := bind(`{"data":{"type":"ansible-configs","attributes":{"config-content":"[defaults]\n"}}}`); err != nil {
			t.Fatalf("valid envelope rejected: %v", err)
		}
	})

	t.Run("pre-#608 flat body is rejected", func(t *testing.T) {
		if err := bind(`{"config_content":"[defaults]\n"}`); err == nil {
			t.Fatal("legacy flat body must not bind")
		}
	})

	t.Run("missing config-content is rejected", func(t *testing.T) {
		if err := bind(`{"data":{"type":"ansible-configs","attributes":{}}}`); err == nil {
			t.Fatal("empty attributes must not bind")
		}
	})
}
