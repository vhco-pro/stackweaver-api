// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// AdminUsersHandlerV2 serves the TFE admin users API for the platform administrator (#132, D4):
// `GET /api/v2/admin/users` as a lookup and the grant_admin and revoke_admin actions. Every route
// is reserved to a platform administrator and answers 404 to everyone else.
//
// The listing keeps TFE's route, parameters and attributes but is a lookup rather than a
// directory (decision 8): a call carries filter[admin]=true or q set to one full email address,
// so no call enumerates the installation's accounts. Suspension, the site auditor, impersonation
// and the organizations relationship are not part of Stackweaver.
// TFE API docs: https://developer.hashicorp.com/terraform/enterprise/api-docs/admin/users
type AdminUsersHandlerV2 struct {
	users  *repository.UserRepository
	admins *platformadmin.Service
}

// NewAdminUsersHandlerV2 creates the handler.
func NewAdminUsersHandlerV2(users *repository.UserRepository, admins *platformadmin.Service) *AdminUsersHandlerV2 {
	return &AdminUsersHandlerV2{users: users, admins: admins}
}

// AdminUserAttributes is the TFE admin users resource, with platform-admin-declared and name as
// Stackweaver extensions.
type AdminUserAttributes struct {
	Username             string `json:"username"`
	Email                string `json:"email"`
	Name                 string `json:"name"`
	AvatarURL            string `json:"avatar-url"`
	IsAdmin              bool   `json:"is-admin"`
	IsSuspended          bool   `json:"is-suspended"`
	IsSiteAuditor        bool   `json:"is-site-auditor"`
	IsServiceAccount     bool   `json:"is-service-account"`
	DeclaredByDeployment bool   `json:"platform-admin-declared"`
}

// adminLookupRequired is the detail of the 400 a call without a lookup parameter gets.
const adminLookupRequired = "set filter[admin]=true or q to one full email address"

func adminUserResource(u *models.User) jsonapi.Resource[AdminUserAttributes] {
	admin, declared := platformadmin.Status(u)
	username := u.Username
	if username == "" {
		username = u.Email
	}
	return jsonapi.Resource[AdminUserAttributes]{
		ID:   u.ID.String(),
		Type: "users",
		Attributes: AdminUserAttributes{
			Username:             username,
			Email:                u.Email,
			Name:                 u.Name,
			IsAdmin:              admin,
			DeclaredByDeployment: declared,
		},
	}
}

// isFullEmail reports whether q is one complete email address and nothing else.
func isFullEmail(q string) bool {
	addr, err := mail.ParseAddress(q)
	return err == nil && addr.Name == "" && strings.EqualFold(addr.Address, q)
}

// List looks users up.
// GET /api/v2/admin/users?filter[admin]=true | ?q=<email>
func (h *AdminUsersHandlerV2) List(c *gin.Context) {
	if _, ok := h.admins.Require(c); !ok {
		return
	}
	filterAdmin, hasFilterAdmin := c.GetQuery("filter[admin]")
	q := strings.TrimSpace(c.Query("q"))
	_, hasSuspended := c.GetQuery("filter[suspended]")
	adminsOnly := hasFilterAdmin && filterAdmin == "true"
	byEmail := q != ""
	if hasSuspended || (hasFilterAdmin && !adminsOnly) || (byEmail && !isFullEmail(q)) || (!adminsOnly && !byEmail) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", adminLookupRequired)
		return
	}
	page, pageSize := jsonapi.PageParams(c, 20, 100)

	var found []models.User
	var total int64
	if byEmail {
		u, err := h.users.GetByEmailCaseInsensitive(q)
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
		case err != nil:
			logger.Errorf("admin users: looking up %q: %v", q, err)
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to look up the user")
			return
		default:
			if admin, _ := platformadmin.Status(u); admin || !adminsOnly {
				total = 1
				if page == 1 {
					found = []models.User{*u}
				}
			}
		}
	} else {
		var err error
		found, total, err = h.users.ListPlatformAdminsPage(pageSize, jsonapi.Offset(page, pageSize))
		if err != nil {
			logger.Errorf("admin users: %v", err)
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to list platform administrators")
			return
		}
	}

	data := make([]jsonapi.Resource[AdminUserAttributes], 0, len(found))
	for i := range found {
		data = append(data, adminUserResource(&found[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, pageSize, total))
}

// GrantAdmin makes a user a platform administrator.
// POST /api/v2/admin/users/:id/actions/grant_admin
func (h *AdminUsersHandlerV2) GrantAdmin(c *gin.Context) {
	h.action(c, h.admins.Grant)
}

// RevokeAdmin removes a granted platform administrator.
// POST /api/v2/admin/users/:id/actions/revoke_admin
func (h *AdminUsersHandlerV2) RevokeAdmin(c *gin.Context) {
	h.action(c, h.admins.Revoke)
}

func (h *AdminUsersHandlerV2) action(c *gin.Context, do func(context.Context, *models.User, uuid.UUID) (*models.User, error)) {
	actor, ok := h.admins.Require(c)
	if !ok {
		return
	}
	targetID, err := uuid.Parse(c.Param("id"))
	if err != nil || targetID == uuid.Nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "User not found, or client is not an administrator.")
		return
	}
	target, err := do(c.Request.Context(), actor, targetID)
	switch {
	case errors.Is(err, platformadmin.ErrUserNotFound):
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "User not found, or client is not an administrator.")
	case errors.Is(err, platformadmin.ErrAlreadyAdmin):
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "User is already an administrator.")
	case errors.Is(err, platformadmin.ErrNotAdmin):
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "User is not an administrator.")
	case errors.Is(err, platformadmin.ErrDeclaredAdmin):
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
	case err != nil:
		logger.Errorf("admin users: %s on %s: %v", c.FullPath(), targetID, err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to change the platform administrator")
	default:
		jsonapi.WriteDocument(c, http.StatusOK, adminUserResource(target))
	}
}
