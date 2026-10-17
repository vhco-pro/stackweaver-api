// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/totp"
)

type TOTPHandler struct {
	totpService twoFactorBackend
	authService *auth.Service
}

// twoFactorBackend is the identity provider's side of two-factor and password changes: the
// methods of totp.Service these handlers call, declared where they are used so a test can stand
// in for the identity provider.
type twoFactorBackend interface {
	StartTOTPRegistration(userID string) (*totp.TOTPRegistrationResponse, error)
	VerifyTOTP(userID, code string) error
	RemoveTOTP(userID string) error
	CheckTOTPStatus(userID string) (bool, error)
	ChangePassword(userID, currentPassword, newPassword string) error
	ListMFADevices(userID string) ([]*totp.MFADevice, error)
}

func NewTOTPHandler(totpService *totp.Service, authService *auth.Service) *TOTPHandler {
	h := &TOTPHandler{authService: authService}
	if totpService != nil {
		h.totpService = totpService
	}
	return h
}

// StartTOTPRegistration starts TOTP registration
// POST /api/v2/settings/2fa/start
func (h *TOTPHandler) StartTOTPRegistration(c *gin.Context) {
	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// Start TOTP registration
	resp, err := h.totpService.StartTOTPRegistration(userSubject)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to start TOTP registration"+": "+err.Error())
		return
	}

	// An enrolment in progress has no identity of its own, so it is meta alone (#858, D8).
	jsonapi.WriteMeta(c, http.StatusOK, TOTPEnrolmentMeta{Secret: resp.Secret, URL: resp.URL})
}

// VerifyTOTPRequest is the two-factor document that confirms an enrolment with a code.
type VerifyTOTPRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Code string `json:"code" binding:"required"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *VerifyTOTPRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// VerifyTOTP verifies a TOTP code and answers the caller's two-factor resource.
// POST /api/v2/settings/2fa/verify
func (h *TOTPHandler) VerifyTOTP(c *gin.Context) {
	var req VerifyTOTPRequest
	if !jsonapi.BindDocument(c, &req, twoFactorType) {
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// Verify TOTP code
	if err := h.totpService.VerifyTOTP(userSubject, req.Data.Attributes.Code); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "invalid TOTP code"+": "+err.Error())
		return
	}

	// The verification is what enables two-factor, so the answer says so rather than re-reading
	// the identity provider, whose status read can trail the write for a moment.
	h.writeTwoFactor(c, true)
}

// GetTOTPStatus gets the TOTP status for the current user
// GET /api/v2/settings/2fa/status
func (h *TOTPHandler) GetTOTPStatus(c *gin.Context) {
	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	enabled, err := h.totpService.CheckTOTPStatus(userSubject)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to check TOTP status"+": "+err.Error())
		return
	}
	h.writeTwoFactor(c, enabled)
}

// writeTwoFactor answers the caller's two-factor resource, keyed by the caller's user id.
func (h *TOTPHandler) writeTwoFactor(c *gin.Context, enabled bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, jsonapi.Resource[TwoFactorAttributes]{
		ID:         user.ID.String(),
		Type:       twoFactorType,
		Attributes: TwoFactorAttributes{Enabled: enabled},
	})
}

// RemoveTOTP removes TOTP from the user
// DELETE /api/v2/settings/2fa
func (h *TOTPHandler) RemoveTOTP(c *gin.Context) {
	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// Remove TOTP
	if err := h.totpService.RemoveTOTP(userSubject); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to remove TOTP"+": "+err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// ChangePasswordRequest is the users document a password change is made from (#858, D8). The
// current password is required: it is what proves the change is the person's own.
type ChangePasswordRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			CurrentPassword string `json:"current-password" binding:"required"`
			NewPassword     string `json:"new-password" binding:"required"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *ChangePasswordRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// ChangePassword changes the user's password and answers 204.
// POST /api/v2/settings/password
func (h *TOTPHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if !jsonapi.BindDocument(c, &req, "users") {
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// Change password
	if err := h.totpService.ChangePassword(userSubject, req.Data.Attributes.CurrentPassword, req.Data.Attributes.NewPassword); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "failed to change password"+": "+err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// ListMFADevices lists all MFA devices for the current user
// GET /api/v1/settings/mfa-devices
func (h *TOTPHandler) ListMFADevices(c *gin.Context) {
	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// List MFA devices
	devices, err := h.totpService.ListMFADevices(userSubject)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to list MFA devices"+": "+err.Error())
		return
	}

	data := make([]jsonapi.Resource[MFADeviceAttributes], 0, len(devices))
	for _, d := range devices {
		data = append(data, jsonapi.Resource[MFADeviceAttributes]{
			ID:         d.ID,
			Type:       "mfa-devices",
			Attributes: MFADeviceAttributes{DeviceType: d.Type, Name: d.Name, State: d.State},
		})
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
}

// twoFactorType is the resource type of the caller's two-factor state.
const twoFactorType = "two-factor"

// TOTPEnrolmentMeta carries the shared secret and otpauth URL for a new TOTP device.
type TOTPEnrolmentMeta struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

// TwoFactorAttributes report whether TOTP is enabled for the caller.
type TwoFactorAttributes struct {
	Enabled bool `json:"enabled"`
}

// MFADeviceAttributes describe one registered second factor.
type MFADeviceAttributes struct {
	DeviceType string `json:"device-type"`
	Name       string `json:"name"`
	State      string `json:"state"`
}
