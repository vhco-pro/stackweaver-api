// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package platformadmin

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/activity"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"gorm.io/gorm"
)

// The activity actions a platform administrator transition writes. Every row has no
// organization, the target user as its resource, and the actor in its details: a user id, or
// "system" when the deployment's declared list caused it.
const (
	ActionDeclared   = "platform_admin.declared"
	ActionUndeclared = "platform_admin.undeclared"
	ActionGranted    = "platform_admin.granted"
	ActionRevoked    = "platform_admin.revoked"
)

// Errors Grant and Revoke return for a request the target's state does not allow.
var (
	ErrUserNotFound  = errors.New("user not found")
	ErrAlreadyAdmin  = errors.New("user is already a platform administrator")
	ErrNotAdmin      = errors.New("user is not a platform administrator")
	ErrDeclaredAdmin = errors.New("platform administrator is declared by the deployment configuration (STACKWEAVER_PLATFORM_ADMINS) and cannot be revoked here")
)

// Users is the user storage the service reads and writes.
type Users interface {
	GetByID(id uuid.UUID) (*models.User, error)
	SetPlatformAdmin(id uuid.UUID, admin, declared bool) (bool, error)
	ClearDeclaredNotIn(lowerEmails []string) ([]uuid.UUID, error)
}

// ActivityLog records the platform administrator transitions.
type ActivityLog interface {
	LogActivity(ctx context.Context, action, resourceType string, resourceID *uuid.UUID, details map[string]any, activityCtx activity.ActivityContext) error
}

// Config is the deployment's platform administration settings.
type Config struct {
	// Declared is the deployment's list of platform administrators.
	Declared Declared
	// OrganizationCreation is who may create organizations; empty means everyone.
	OrganizationCreation OrganizationCreation
}

// Service is the platform administrator: the one place the flag on the user row is interpreted.
type Service struct {
	users    Users
	callers  *auth.Service
	activity ActivityLog
	cfg      Config
}

// NewService returns the service. callers resolves the caller of a request from the database;
// it may be nil for a caller that never authorizes a request (startup reconciliation), and
// Require then refuses every request. It is the concrete auth service rather than an interface
// so the route inventory can follow what Require reads from the request.
func NewService(users Users, callers *auth.Service, activityLog ActivityLog, cfg Config) *Service {
	return &Service{users: users, callers: callers, activity: activityLog, cfg: cfg}
}

// Status reports whether u is a platform administrator and whether the deployment declared them.
func Status(u *models.User) (admin, declared bool) {
	if u == nil {
		return false, false
	}
	return u.PlatformAdmin, u.PlatformAdmin && u.PlatformAdminDeclared
}

// Require authorizes a request to an install-wide route. It accepts a signed-in person (a JWT)
// and a user token that carries the platform:admin scope, in both cases only while the row of
// the person behind it carries the flag, and refuses every other identity before the row is
// read, so an identity kind added later fails closed here until someone decides otherwise. It never consults
// team memberships, RBAC or the org wall, and the row is read on every call, so a revocation is
// effective on the next request. A refused request gets 404, as TFE answers a non-administrator,
// and Require returns false.
func (s *Service) Require(c *gin.Context) (*models.User, bool) {
	deny := func(userID any, reason string) (*models.User, bool) {
		logger.Warnf("platform admin: refused %s %s for user %v: %s", c.Request.Method, c.FullPath(), userID, reason)
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Not Found")
		return nil, false
	}
	userID, _ := c.Get("user_id")
	switch method := c.GetString("auth_method"); method {
	case "jwt":
	case "api_key":
		// Only a user token that carries platform:admin; an organization-bound key is refused
		// by its kind before its scopes or its owner are looked at.
		if kind := c.GetString("token_kind"); kind != models.APIKeyKindUser {
			return deny(userID, fmt.Sprintf("a %q token cannot act as a platform administrator", kind))
		}
		raw, _ := c.Get("api_key_scopes")
		scopes, _ := raw.([]string)
		checker, err := apikey.NewScopeChecker(scopes)
		if err != nil || !checker.HasPlatformAdmin() {
			return deny(userID, "the token does not carry the platform:admin scope")
		}
	default:
		return deny(userID, fmt.Sprintf("identity %q cannot act as a platform administrator", method))
	}
	if s.callers == nil {
		return deny(userID, "no caller resolver")
	}
	user, err := s.callers.GetUserFromContext(c)
	if err != nil || user == nil {
		return deny(userID, "caller not found")
	}
	if admin, _ := Status(user); !admin {
		return deny(user.ID, "not a platform administrator")
	}
	return user, true
}

// IsPlatformAdmin reports whether the user is a platform administrator, for callers that shape a
// response rather than gate one.
func (s *Service) IsPlatformAdmin(_ context.Context, userID uuid.UUID) (bool, error) {
	u, err := s.users.GetByID(userID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading user %s: %w", userID, err)
	}
	admin, _ := Status(u)
	return admin, nil
}

// ApplyDeclared applies the declared list to a user at sign-in (auth.PlatformAdminSeeder). It
// acts only on an address the identity provider verified for this request: a listed address is
// flagged declared (promoting a granted administrator), and a declared administrator whose
// address is off the list loses both columns. A request without a verified email, such as the
// identity-provider outage fallback or a machine user, changes nothing. user is updated in place.
func (s *Service) ApplyDeclared(ctx context.Context, user *models.User, info *auth.UserInfo) error {
	if user == nil || info == nil || !info.EmailVerified || info.Email == "" {
		return nil
	}
	onList := s.cfg.Declared.Contains(info.Email)
	switch {
	case onList && (!user.PlatformAdmin || !user.PlatformAdminDeclared):
		if err := s.transition(ctx, user, true, true, ActionDeclared, "sign-in"); err != nil {
			return err
		}
	case !onList && user.PlatformAdminDeclared:
		if err := s.transition(ctx, user, false, false, ActionUndeclared, "sign-in"); err != nil {
			return err
		}
	}
	return nil
}

// transition writes the system-caused change and its audit row; a repeat that changes nothing
// (a concurrent request won) writes no row.
func (s *Service) transition(ctx context.Context, user *models.User, admin, declared bool, action, source string) error {
	changed, err := s.users.SetPlatformAdmin(user.ID, admin, declared)
	if err != nil {
		return err
	}
	user.PlatformAdmin, user.PlatformAdminDeclared = admin, declared
	if changed {
		s.audit(ctx, action, user.ID, user.Email, nil, source)
	}
	return nil
}

// Reconcile is the startup half of the declared list: every declared administrator whose stored
// address is no longer on it loses both columns, so a removal takes effect at the restart that
// loads the new list rather than at that person's next sign-in. It never grants: flags follow the
// identity provider's verified address, which only a sign-in carries.
func (s *Service) Reconcile(ctx context.Context) error {
	if s.cfg.Declared.Empty() {
		logger.Warn("no platform administrators declared; set STACKWEAVER_PLATFORM_ADMINS")
	}
	ids, err := s.users.ClearDeclaredNotIn(s.cfg.Declared.Emails())
	if err != nil {
		return err
	}
	for _, id := range ids {
		email := ""
		if u, err := s.users.GetByID(id); err == nil {
			email = u.Email
		}
		logger.Infof("platform admin: %s (%s) is no longer declared by the deployment", id, email)
		s.audit(ctx, ActionUndeclared, id, email, nil, "startup")
	}
	return nil
}

// Grant makes the target a platform administrator. A declared administrator is left as it is.
func (s *Service) Grant(ctx context.Context, actor *models.User, targetID uuid.UUID) (*models.User, error) {
	target, err := s.target(targetID)
	if err != nil {
		return nil, err
	}
	admin, declared := Status(target)
	switch {
	case declared:
		return target, nil
	case admin:
		return nil, ErrAlreadyAdmin
	}
	changed, err := s.users.SetPlatformAdmin(target.ID, true, false)
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, ErrAlreadyAdmin
	}
	target.PlatformAdmin, target.PlatformAdminDeclared = true, false
	s.audit(ctx, ActionGranted, target.ID, target.Email, actor, "api")
	return target, nil
}

// Revoke removes a granted platform administrator. A declared administrator cannot be revoked
// here; revoking oneself is allowed, because the declared administrators always remain.
func (s *Service) Revoke(ctx context.Context, actor *models.User, targetID uuid.UUID) (*models.User, error) {
	target, err := s.target(targetID)
	if err != nil {
		return nil, err
	}
	admin, declared := Status(target)
	switch {
	case declared:
		return nil, ErrDeclaredAdmin
	case !admin:
		return nil, ErrNotAdmin
	}
	changed, err := s.users.SetPlatformAdmin(target.ID, false, false)
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, ErrNotAdmin
	}
	target.PlatformAdmin, target.PlatformAdminDeclared = false, false
	s.audit(ctx, ActionRevoked, target.ID, target.Email, actor, "api")
	return target, nil
}

func (s *Service) target(id uuid.UUID) (*models.User, error) {
	u, err := s.users.GetByID(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reading user %s: %w", id, err)
	}
	return u, nil
}

// audit writes one activity row with no organization. A failure is logged and does not undo the
// change, as elsewhere in the API.
func (s *Service) audit(ctx context.Context, action string, targetID uuid.UUID, targetEmail string, actor *models.User, source string) {
	if s.activity == nil {
		return
	}
	details := map[string]any{"actor": "system", "target_user_id": targetID.String(), "target_email": targetEmail, "source": source}
	var ac activity.ActivityContext
	if actor != nil {
		details["actor"] = actor.ID.String()
		ac.UserID = &actor.ID
	}
	if err := s.activity.LogActivity(ctx, action, "user", &targetID, details, ac); err != nil {
		logger.Errorf("platform admin: recording %s for user %s: %v", action, targetID, err)
	}
}
