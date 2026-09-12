// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration test for #798 - the duplicate-email guard on organization-membership creation.
//
// The guard used to compare an invited address against ListMembers(org, 1000, 0, ...), a page
// ordered created_at DESC, so in an organization past 1000 members an address held by an older
// member fell outside the window it checked. Two things followed:
//
//   - The specific "User with email 'x' is already a member" conflict was replaced by the generic
//     one from the membership check further down, i.e. the guard silently stopped firing.
//   - Where a second user row spelled that address differently (the old email index was
//     case-sensitive), the invite resolved to the row that was NOT the member, and a second
//     membership for one address was created.
//
// Drives the real handler against real Postgres. Gated behind `integration`; skips unless
// $TEST_DATABASE_URL is set. Cleanup is strictly row-scoped (the dev DB has no backup). Run with:
//
//	cd backend && go test -tags integration ./internal/api/v2/handlers/ -run TestOrganizationMembershipDuplicateGuard

//go:build integration
// +build integration

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// dupGuardMembers is one more than the limit the old guard passed to ListMembers, so the oldest
// membership provably sits outside the window that scan could see.
const dupGuardMembers = 1001

func TestOrganizationMembershipDuplicateGuard(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "dupguard-h-" + sfx}
	owners := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	admin := &models.User{
		ID:             uuid.New(),
		ZitadelSubject: "dupguard-admin-" + sfx,
		Email:          "dupguard-admin-" + sfx + "@test.local",
	}

	// The member the old capped scan could not see: oldest by a wide margin, spelled in mixed case.
	oldest := &models.User{
		ID:             uuid.New(),
		ZitadelSubject: "dupguard-oldest-" + sfx,
		Email:          fmt.Sprintf("Oldest-%s@Example.test", sfx),
	}

	t.Cleanup(func() {
		db.Where("team_id = ?", owners.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", owners.ID).Delete(&models.Team{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("name = ?", org.Name).Delete(&models.ReservedOrganizationName{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("zitadel_subject LIKE ?", "dupguard-%-"+sfx).Delete(&models.User{})
	})

	base := time.Now().Add(-48 * time.Hour)
	seed := []any{
		org, owners, admin, oldest,
		&models.TeamMember{ID: uuid.New(), TeamID: owners.ID, UserID: admin.ID},
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: admin.ID, CreatedAt: time.Now()},
		// Explicit created_at puts the target outside ORDER BY created_at DESC LIMIT 1000.
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: oldest.ID, CreatedAt: base},
	}
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	// Filler members, all newer than the target, to push it out of the window.
	fillerUsers := make([]models.User, 0, dupGuardMembers)
	fillerMembers := make([]models.OrganizationMember, 0, dupGuardMembers)
	for i := range dupGuardMembers {
		id := uuid.New()
		fillerUsers = append(fillerUsers, models.User{
			ID:             id,
			ZitadelSubject: fmt.Sprintf("dupguard-fill%d-%s", i, sfx),
			Email:          fmt.Sprintf("dupguard-fill%d-%s@example.test", i, sfx),
		})
		fillerMembers = append(fillerMembers, models.OrganizationMember{
			ID:             uuid.New(),
			OrganizationID: org.ID,
			UserID:         id,
			CreatedAt:      base.Add(time.Duration(i+1) * time.Minute),
		})
	}
	if err := db.CreateInBatches(&fillerUsers, 200).Error; err != nil {
		t.Fatalf("seed filler users: %v", err)
	}
	if err := db.CreateInBatches(&fillerMembers, 200).Error; err != nil {
		t.Fatalf("seed filler memberships: %v", err)
	}

	orgRepo := repository.NewOrganizationRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	userRepo := repository.NewUserRepository(db)
	authService := auth.NewService(userRepo)
	rbacService := rbac.NewServiceWithTeams(orgRepo, teamRepo, repository.NewProjectRepository(db))

	newRouter := func(repo OrganizationMembershipRepository) *gin.Engine {
		memH := NewOrganizationMembershipHandlerV2(repo, userRepo, teamRepo, authService, rbacService)
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(func(c *gin.Context) {
			if v := c.GetHeader("X-Test-User"); v != "" {
				if id, err := uuid.Parse(v); err == nil {
					c.Set("user_id", id)
				}
			}
			c.Next()
		})
		router.POST("/organizations/:name/organization-memberships", memH.Create)
		return router
	}

	invite := func(router *gin.Engine, email string) (int, string) {
		body := fmt.Sprintf(`{"data":{"type":"organization-memberships","attributes":{"email":%q}}}`, email)
		r := httptest.NewRequest(http.MethodPost, "/organizations/"+org.Name+"/organization-memberships", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Test-User", admin.ID.String())
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}

	countMembershipsFor := func(t *testing.T, email string) int64 {
		t.Helper()
		var n int64
		if err := db.Model(&models.OrganizationMember{}).
			Joins("JOIN users ON users.id = organization_members.user_id").
			Where("organization_members.organization_id = ? AND LOWER(users.email) = LOWER(?)", org.ID, email).
			Count(&n).Error; err != nil {
			t.Fatalf("count memberships for %q: %v", email, err)
		}
		return n
	}

	detailOf := func(t *testing.T, body string) string {
		t.Helper()
		var doc struct {
			Errors []struct {
				Detail string `json:"detail"`
			} `json:"errors"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("parse error document %q: %v", body, err)
		}
		if len(doc.Errors) == 0 {
			t.Fatalf("expected an error document, got %q", body)
		}
		return doc.Errors[0].Detail
	}

	router := newRouter(orgRepo)

	// AC1 + AC2: the guard itself refuses the invite, whatever the spelling and however far the
	// membership sits outside the old window. The detail is what distinguishes the guard from the
	// generic membership check further down the handler: only the guard names the address.
	t.Run("out of window member is refused by the guard", func(t *testing.T) {
		for _, spelling := range []string{oldest.Email, strings.ToLower(oldest.Email), strings.ToUpper(oldest.Email)} {
			code, body := invite(router, spelling)
			if code != http.StatusConflict {
				t.Fatalf("invite %q: got %d, want 409 - body %s", spelling, code, body)
			}
			if detail := detailOf(t, body); !strings.Contains(detail, oldest.Email) {
				t.Errorf("invite %q: detail %q does not name the member's stored address %q, so the "+
					"duplicate-email guard did not fire", spelling, detail, oldest.Email)
			}
			// AC3: nothing was created by the refused invite.
			if n := countMembershipsFor(t, oldest.Email); n != 1 {
				t.Fatalf("invite %q: organization holds %d memberships for the address, want 1", spelling, n)
			}
		}
	})

	// The defect's sharp edge: a second user row spelling one address differently. The invite used
	// to resolve to that row, find no membership for it, and create a duplicate. Once the
	// case-insensitive email index exists this state is unrepresentable, which is the stronger
	// outcome, so the insert failing is an accepted pass.
	t.Run("case variant user row does not defeat the guard", func(t *testing.T) {
		variant := &models.User{
			ID:             uuid.New(),
			ZitadelSubject: "dupguard-variant-" + sfx,
			Email:          strings.ToLower(oldest.Email),
		}
		if err := db.Create(variant).Error; err != nil {
			t.Logf("a case-variant user row is rejected by the email index, so the duplicate is "+
				"unrepresentable: %v", err)
			return
		}
		t.Cleanup(func() {
			// Memberships first: before the fix this invite created one, and the user row cannot
			// be removed while it is referenced.
			db.Delete(&models.OrganizationMember{}, "user_id = ?", variant.ID)
			db.Delete(&models.User{}, "id = ?", variant.ID)
		})

		code, body := invite(router, variant.Email)
		if code != http.StatusConflict {
			t.Fatalf("invite %q with a case-variant user row present: got %d, want 409 - body %s",
				variant.Email, code, body)
		}
		if n := countMembershipsFor(t, oldest.Email); n != 1 {
			t.Fatalf("organization holds %d memberships for one address, want 1", n)
		}
	})

	// The guard must refuse duplicates without refusing anything else: a genuinely new address
	// still gets its placeholder user and its membership. This is the regression the TFE
	// compatibility fixture covers end to end; it is asserted here too, because that fixture can
	// only run against the shared stack.
	t.Run("a new address is still invited", func(t *testing.T) {
		fresh := fmt.Sprintf("dupguard-new-%s@example.test", sfx)
		t.Cleanup(func() {
			db.Exec(`DELETE FROM organization_members WHERE user_id IN
				(SELECT id FROM users WHERE LOWER(email) = LOWER(?))`, fresh)
			db.Where("LOWER(email) = LOWER(?)", fresh).Delete(&models.User{})
		})

		code, body := invite(router, fresh)
		if code != http.StatusCreated {
			t.Fatalf("invite a new address: got %d, want 201 - body %s", code, body)
		}
		if n := countMembershipsFor(t, fresh); n != 1 {
			t.Fatalf("organization holds %d memberships for the new address, want 1", n)
		}

		// A placeholder user was created for it, carrying the synthetic invited- subject.
		var placeholder models.User
		if err := db.Where("LOWER(email) = LOWER(?)", fresh).First(&placeholder).Error; err != nil {
			t.Fatalf("expected a placeholder user for %q: %v", fresh, err)
		}
		if !strings.HasPrefix(placeholder.ZitadelSubject, "invited-") {
			t.Errorf("placeholder subject %q does not carry the invited- prefix", placeholder.ZitadelSubject)
		}

		// Inviting the same address again is now refused by the guard, naming it.
		code, body = invite(router, strings.ToUpper(fresh))
		if code != http.StatusConflict {
			t.Fatalf("re-invite of %q: got %d, want 409 - body %s", fresh, code, body)
		}
		if detail := detailOf(t, body); !strings.Contains(detail, fresh) {
			t.Errorf("re-invite detail %q does not name the address", detail)
		}
		if n := countMembershipsFor(t, fresh); n != 1 {
			t.Fatalf("re-invite left %d memberships for one address, want 1", n)
		}
	})

	// AC4: a failing duplicate lookup refuses the request instead of skipping the check. The guard
	// used to run under `if err == nil`, so a database error on the listing silently proceeded to
	// create the membership.
	t.Run("a failing lookup refuses the request", func(t *testing.T) {
		fresh := fmt.Sprintf("dupguard-fresh-%s@example.test", sfx)
		failing := newRouter(failingMemberByEmail{OrganizationMembershipRepository: orgRepo})
		code, body := invite(failing, fresh)
		if code != http.StatusInternalServerError {
			t.Fatalf("invite with a failing duplicate lookup: got %d, want 500 - body %s", code, body)
		}
		if n := countMembershipsFor(t, fresh); n != 0 {
			t.Fatalf("a failed duplicate lookup created %d memberships, want 0", n)
		}
	})
}

// failingMemberByEmail is the real repository with only the duplicate lookup broken, which is the
// one branch that cannot be staged from outside: org resolution and the RBAC check both run
// against the database before the guard is reached.
type failingMemberByEmail struct {
	OrganizationMembershipRepository
}

func (failingMemberByEmail) GetMemberByEmail(uuid.UUID, string) (*models.OrganizationMember, error) {
	return nil, fmt.Errorf("simulated database failure")
}
