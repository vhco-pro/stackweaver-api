// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An admin terraform version created with `enabled: false` must be stored disabled, and one
// created without the attribute must be enabled.
//
// The defect this test was written against: TofuVersion.Enabled carried `gorm:"default:true"`,
// and GORM substitutes a literal default for a zero value in the INSERT (and writes it back into
// the struct), so a false sent on create was stored and answered as true. The default lives in
// AdminTofuVersionsHandler.Create instead.
//
// tofu_versions is a global table on a database other suites share, so the rows this test creates
// are shaped to stay out of everyone's way: a well-formed low version (0.0.<n>), which keeps the
// integer-cast ordering in ListEnabled working, and `beta: true`, which keeps the row from ever
// being picked as an organization's default version.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAdminTofuVersionCreate_Enabled

//go:build integration

package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// storedAsSentCall sends one request as the given user and returns the status and the raw body.
// The router must read the caller from the X-Test-User header (see storedAsSentRouter).
func storedAsSentCall(t *testing.T, router http.Handler, method, path string, asUser uuid.UUID, body string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/vnd.api+json")
	r.Header.Set("X-Test-User", asUser.String())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec.Code, rec.Body.Bytes()
}

// storedAsSentRouter is a gin engine that authenticates the caller from the X-Test-User header,
// as a signed-in person (a browser session).
func storedAsSentRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
			c.Set("auth_method", "session")
		}
		c.Next()
	})
	return router
}

// storedAsSentDocument is a JSON:API document with one resource.
func storedAsSentDocument(t *testing.T, resourceType string, attrs map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": resourceType, "attributes": attrs}})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(raw)
}

// storedAsSentResource decodes data.id and data.attributes of a JSON:API response.
func storedAsSentResource(t *testing.T, body []byte) (string, map[string]any) {
	t.Helper()
	var doc struct {
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode response: %v\n%s", err, body)
	}
	return doc.Data.ID, doc.Data.Attributes
}

// assertStoredBool checks one boolean attribute of a response.
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

func TestAdminTofuVersionCreate_EnabledIsStoredAsSent(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.TofuVersion{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	// The admin routes are reserved to a platform administrator (#132). This test used to seed an
	// owners-team member, which was the admin check before the platform administrator existed.
	admin := &models.User{ID: uuid.New(), ZitadelSubject: "tvenabled-" + sfx, Email: "tvenabled-" + sfx + "@test.local"}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	userRepo := repository.NewUserRepository(db)
	if _, err := userRepo.SetPlatformAdmin(admin.ID, true, false); err != nil {
		t.Fatalf("flag admin: %v", err)
	}
	var versionIDs []string
	t.Cleanup(func() {
		// Row-scoped only: exactly the versions the cases below created, by id.
		if len(versionIDs) > 0 {
			db.Where("id IN ?", versionIDs).Delete(&models.TofuVersion{})
		}
		db.Where("id = ?", admin.ID).Delete(&models.User{})
	})

	admins := platformadmin.NewService(userRepo, auth.NewService(userRepo), nil, platformadmin.Config{})
	h := NewAdminTofuVersionsHandler(db, admins)
	router := storedAsSentRouter()
	router.POST("/api/v2/admin/terraform-versions", h.Create)
	router.GET("/api/v2/admin/terraform-versions/:id", h.Read)

	// A random patch number in a range no release uses, so concurrent runs do not collide on the
	// unique version column.
	base := 100000 + rand.IntN(800000)

	sent := func(v bool) *bool { return &v }
	cases := []struct {
		name    string
		enabled *bool // nil leaves the attribute out
		want    bool
	}{
		{"explicit false", sent(false), false},
		{"explicit true", sent(true), true},
		{"absent", nil, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]any{"version": fmt.Sprintf("0.0.%d", base+i), "beta": true}
			if tc.enabled != nil {
				attrs["enabled"] = *tc.enabled
			}
			code, body := storedAsSentCall(t, router, http.MethodPost, "/api/v2/admin/terraform-versions",
				admin.ID, storedAsSentDocument(t, "terraform-versions", attrs))
			if code != http.StatusCreated {
				t.Fatalf("create = %d, want 201 (%s)", code, body)
			}
			id, created := storedAsSentResource(t, body)
			versionIDs = append(versionIDs, id)
			assertStoredBool(t, "create response", created, "enabled", tc.want)

			code, body = storedAsSentCall(t, router, http.MethodGet, "/api/v2/admin/terraform-versions/"+id, admin.ID, "")
			if code != http.StatusOK {
				t.Fatalf("read = %d, want 200 (%s)", code, body)
			}
			_, read := storedAsSentResource(t, body)
			assertStoredBool(t, "read back", read, "enabled", tc.want)
		})
	}
}
