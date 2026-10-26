// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// grant_admin and revoke_admin (#132, AC8 to AC11): the TFE admin users actions, with the
// declared administrators read-only, each transition audited, and the target's next request
// judged by the new state with no sign-out.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAdminUsersActions

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
)

func userAttrs(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var doc struct {
		Data struct {
			Type       string         `json:"type"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Data.Type != "users" {
		t.Fatalf("decode users resource: %v\n%s", err, body)
	}
	return doc.Data.Attributes
}

func (f *platformAdminFixture) auditActions(t *testing.T, target uuid.UUID) []models.AuditLog {
	t.Helper()
	var rows []models.AuditLog
	if err := f.db.Where("resource_type = ? AND resource_id = ?", "user", target).Order("created_at").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAdminUsersActions(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	router := platformAdminRouter()
	f.adminUserRoutes(router, f.admins)
	versions := f.versionRoutes(t, router, f.admins)
	listVersions := versions[0]
	action := func(as identity, target uuid.UUID, name string) (int, []byte) {
		rec := platformAdminCall(t, router, http.MethodPost, "/api/v2/admin/users/"+target.String()+"/actions/"+name, as, "")
		return rec.Code, rec.Body.Bytes()
	}
	reach := func(as identity) int {
		return platformAdminCall(t, router, listVersions.method, listVersions.path, as, "").Code
	}

	// AC8: a grant sets the flag, a second grant is 400, and the target's next request is let in.
	if code := reach(browserAs(f.plain)); code != http.StatusNotFound {
		t.Fatalf("before the grant the target reached the catalogue (%d)", code)
	}
	code, body := action(browserAs(f.admin), f.plain.ID, "grant_admin")
	if code != http.StatusOK || userAttrs(t, body)["is-admin"] != true {
		t.Fatalf("grant_admin = %d %s, want 200 with is-admin true", code, body)
	}
	if code, body := action(browserAs(f.admin), f.plain.ID, "grant_admin"); code != http.StatusBadRequest {
		t.Errorf("second grant_admin = %d %s, want 400", code, body)
	}
	if code := reach(browserAs(f.plain)); code != http.StatusOK {
		t.Errorf("after the grant the target's next request = %d, want 200", code)
	}
	// A platform:admin token the target mints while holding the flag (AC9).
	targetToken := identity{user: f.plain.ID, method: "api_key", tokenKind: models.APIKeyKindUser, scopes: []string{"platform:admin"}}
	if code := reach(targetToken); code != http.StatusOK {
		t.Errorf("the target's platform:admin token while the flag is held = %d, want 200", code)
	}

	// AC9: a revoke clears it and the target's next request is refused.
	if code, body := action(browserAs(f.admin), f.plain.ID, "revoke_admin"); code != http.StatusOK || userAttrs(t, body)["is-admin"] != false {
		t.Fatalf("revoke_admin = %d %s, want 200 with is-admin false", code, body)
	}
	if code, _ := action(browserAs(f.admin), f.plain.ID, "revoke_admin"); code != http.StatusBadRequest {
		t.Errorf("second revoke_admin = %d, want 400", code)
	}
	if code := reach(browserAs(f.plain)); code != http.StatusNotFound {
		t.Errorf("after the revoke the target's next request = %d, want 404", code)
	}
	if code := reach(targetToken); code != http.StatusNotFound {
		t.Errorf("after the revoke the platform:admin token minted while the flag was held = %d, want 404", code)
	}

	// AC10: a declared administrator cannot be revoked, and granting one changes nothing.
	code, body = action(browserAs(f.admin), f.declared.ID, "revoke_admin")
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "STACKWEAVER_PLATFORM_ADMINS") {
		t.Errorf("revoke_admin on a declared administrator = %d %s, want 422 naming the deployment configuration", code, body)
	}
	code, body = action(browserAs(f.admin), f.declared.ID, "grant_admin")
	if code != http.StatusOK || userAttrs(t, body)["platform-admin-declared"] != true {
		t.Errorf("grant_admin on a declared administrator = %d %s, want 200 still declared", code, body)
	}
	if u, _ := f.users.GetByID(f.declared.ID); u != nil {
		if admin, declared := platformadmin.Status(u); !admin || !declared {
			t.Errorf("declared administrator changed: admin=%v declared=%v", admin, declared)
		}
	}
	if rows := f.auditActions(t, f.declared.ID); len(rows) != 0 {
		t.Errorf("the declared administrator's no-op actions wrote %d audit rows", len(rows))
	}

	// An administrator may revoke themselves; the declared administrators always remain.
	second := f.user(t, "second")
	if code, _ := action(browserAs(f.admin), second.ID, "grant_admin"); code != http.StatusOK {
		t.Fatalf("grant second = %d", code)
	}
	if code, _ := action(browserAs(second), second.ID, "revoke_admin"); code != http.StatusOK {
		t.Errorf("self-revoke = %d, want 200", code)
	}

	// Unknown ids and refused callers both get 404.
	if code, _ := action(browserAs(f.admin), uuid.New(), "grant_admin"); code != http.StatusNotFound {
		t.Errorf("grant_admin on an unknown id = %d, want 404", code)
	}
	if code, _ := action(browserAs(f.admin), uuid.Nil, "grant_admin"); code != http.StatusNotFound {
		t.Errorf("grant_admin on the nil id = %d, want 404", code)
	}
	for _, who := range []identity{browserAs(f.owner), browserAs(f.member), browserAs(f.plain)} {
		for _, name := range []string{"grant_admin", "revoke_admin"} {
			if code, _ := action(who, f.admin.ID, name); code != http.StatusNotFound {
				t.Errorf("non-administrator %s %s = %d, want 404", who.user, name, code)
			}
		}
	}

	// AC11: every grant and revoke is audited with the actor and the target and no organization.
	rows := f.auditActions(t, f.plain.ID)
	if len(rows) != 2 || rows[0].Action != platformadmin.ActionGranted || rows[1].Action != platformadmin.ActionRevoked {
		t.Fatalf("audit rows for the target = %+v, want granted then revoked", rows)
	}
	for _, r := range rows {
		if r.OrganizationID != nil || r.UserID == nil || *r.UserID != f.admin.ID || r.Details["actor"] != f.admin.ID.String() {
			t.Errorf("audit row %s: org %v actor %v details %v", r.Action, r.OrganizationID, r.UserID, r.Details)
		}
	}
	selfRows := f.auditActions(t, second.ID)
	if len(selfRows) != 2 || selfRows[1].UserID == nil || *selfRows[1].UserID != second.ID {
		t.Errorf("self-revoke audit rows = %+v", selfRows)
	}
}
