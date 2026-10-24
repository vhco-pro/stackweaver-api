// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/backend/internal/services/profile"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// AccountHandlerV2 serves the signed-in person's own account as the TFE `users` resource:
// `GET /api/v2/account/details`, the target of go-tfe's Users.ReadCurrent and the
// tfe_current_user data source, and `PATCH /api/v2/account/update`, go-tfe's Users.Update. The
// profile the settings pages edit is part of the same resource (#858, D8): name, bio, company and
// location extend `users` the way description extends organizations. It is account-level (no
// target organization), so the org wall classifies both routes as agnostic.
type AccountHandlerV2 struct {
	authService *auth.Service
	userRepo    *repository.UserRepository
	// profiles is the identity provider's copy of the name and email, kept in step with the
	// account; nil when the identity provider's profile API is not configured.
	profiles accountProfileSource
	// admins reports the caller's platform administrator status and the installation's
	// organization-creation setting; nil reports neither.
	admins *platformadmin.Service
}

// SetPlatformAdmin gives the account resource the caller's platform status (#132, D4).
func (h *AccountHandlerV2) SetPlatformAdmin(admins *platformadmin.Service) {
	h.admins = admins
}

// accountProfileSource is the part of profile.Service the account calls, declared where it is
// used.
type accountProfileSource interface {
	GetUserProfile(userID string) (*profile.UserProfile, error)
	UpdateUserProfile(userID string, req *profile.UpdateProfileRequest) error
}

func NewAccountHandlerV2(authService *auth.Service, userRepo *repository.UserRepository, profiles *profile.Service) *AccountHandlerV2 {
	h := &AccountHandlerV2{authService: authService, userRepo: userRepo}
	if profiles != nil {
		h.profiles = profiles
	}
	return h
}

// Details returns the authenticated user's account (tfe_current_user).
// GET /api/v2/account/details
func (h *AccountHandlerV2) Details(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, h.accountResource(c, user))
}

// UpdateAccountRequest is the users document go-tfe marshals for UserUpdateOptions (username,
// email), with the profile attributes beside them. Every attribute is a pointer: an omitted one is
// left as it is, and an empty string clears it.
type UpdateAccountRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Username *string `json:"username"`
			Email    *string `json:"email"`
			Name     *string `json:"name"`
			Bio      *string `json:"bio"`
			Company  *string `json:"company"`
			Location *string `json:"location"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *UpdateAccountRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// Update changes the signed-in person's account and answers the users resource. It is mounted
// behind InteractiveOnly: it acts on the signed-in person, and a token acting on its owner's
// account is refused, as the settings surface refuses it.
// PATCH /api/v2/account/update
func (h *AccountHandlerV2) Update(c *gin.Context) {
	var req UpdateAccountRequest
	if !jsonapi.BindDocument(c, &req, "users") {
		return
	}
	attrs := req.Data.Attributes

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonAPIError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	// The stored email is written only by the sign-in sync, from an address the identity provider
	// has verified. A requested change goes to the identity provider and stays unconfirmed until
	// the person verifies it there, so without one there is nowhere to send it.
	if attrs.Email != nil && *attrs.Email != "" && !strings.EqualFold(*attrs.Email, user.Email) && h.profiles == nil {
		jsonAPIError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "the email address is managed by the identity provider")
		return
	}

	// The identity provider holds the name and email too; a non-empty new value goes there first,
	// so the two copies cannot disagree after a failure.
	if h.profiles != nil {
		if subject, err := h.authService.GetUserSubject(c); err == nil {
			update := &profile.UpdateProfileRequest{}
			changed := false
			if attrs.Name != nil && *attrs.Name != "" {
				update.Name, changed = *attrs.Name, true
			}
			// Only a different address is a change; resending the stored one must not ask the
			// identity provider to set, and possibly re-verify, the address it already holds.
			if attrs.Email != nil && *attrs.Email != "" && !strings.EqualFold(*attrs.Email, user.Email) {
				update.Email, changed = *attrs.Email, true
			}
			if changed {
				if err := h.profiles.UpdateUserProfile(subject, update); err != nil {
					jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "failed to update the profile at the identity provider: "+err.Error())
					return
				}
			}
		}
	}

	for _, field := range []struct {
		value *string
		into  *string
	}{
		{attrs.Username, &user.Username},
		{attrs.Name, &user.Name},
		{attrs.Bio, &user.Bio},
		{attrs.Company, &user.Company},
		{attrs.Location, &user.Location},
	} {
		if field.value != nil {
			*field.into = *field.value
		}
	}
	if err := h.userRepo.Update(user); err != nil {
		jsonAPIError(c, http.StatusInternalServerError, "Internal Server Error", "failed to update the account: "+err.Error())
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, h.accountResource(c, user))
}

// accountResource is the caller's users resource: the stored account, with the identity
// provider's name and email where it has them and the avatar from the caller's sign-in.
func (h *AccountHandlerV2) accountResource(c *gin.Context, user *models.User) jsonapi.Resource[AccountAttributes] {
	attrs := AccountAttributes{
		Username:  user.Username,
		Email:     user.Email,
		Name:      user.Name,
		Bio:       user.Bio,
		Company:   user.Company,
		Location:  user.Location,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		V2Only:    true,
	}
	if h.profiles != nil {
		if subject, err := h.authService.GetUserSubject(c); err == nil {
			if p, err := h.profiles.GetUserProfile(subject); err == nil && p != nil {
				switch {
				case p.Email == "":
				case user.Email != "" && !strings.EqualFold(p.Email, user.Email):
					// The identity provider holds an address the sign-in sync has not stored yet,
					// because it is not verified: TFE reports that as the unconfirmed email.
					attrs.UnconfirmedEmail = p.Email
				default:
					attrs.Email = p.Email
				}
				if p.Name != "" {
					attrs.Name = p.Name
				}
			}
		}
	}
	// TFE requires a username; fall back to the email when the profile has none.
	if attrs.Username == "" {
		attrs.Username = attrs.Email
	}
	attrs.AvatarURL = h.authService.FetchUserInfoPicture(c.Request.Context(), c)
	// TFE's site-admin attribute and permissions object: the platform administrator, and whether
	// the installation lets this caller create organizations.
	attrs.IsSiteAdmin, attrs.DeclaredByDeployment = platformadmin.Status(user)
	attrs.Permissions.CanCreateOrganizations = h.admins == nil || h.admins.CanCreateOrganizations(c.Request.Context(), user)
	return jsonapi.Resource[AccountAttributes]{ID: user.ID.String(), Type: "users", Attributes: attrs}
}
