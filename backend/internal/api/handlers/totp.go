// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/totp"
)

type TOTPHandler struct {
	totpService *totp.Service
	authService *auth.Service
}

func NewTOTPHandler(totpService *totp.Service, authService *auth.Service) *TOTPHandler {
	return &TOTPHandler{
		totpService: totpService,
		authService: authService,
	}
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

	c.JSON(http.StatusOK, TOTPEnrolmentResponse{Secret: resp.Secret, URL: resp.URL})
}

// VerifyTOTP verifies a TOTP code
// POST /api/v2/settings/2fa/verify
type VerifyTOTPRequest struct {
	Code string `json:"code" binding:"required"`
}

func (h *TOTPHandler) VerifyTOTP(c *gin.Context) {
	var req VerifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// Verify TOTP code
	if err := h.totpService.VerifyTOTP(userSubject, req.Code); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "invalid TOTP code"+": "+err.Error())
		return
	}

	response.Message(c, http.StatusOK, "TOTP verified successfully")
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

	// Check TOTP status
	enabled, err := h.totpService.CheckTOTPStatus(userSubject)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to check TOTP status"+": "+err.Error())
		return
	}

	c.JSON(http.StatusOK, TOTPStatusResponse{Enabled: enabled})
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

	response.Message(c, http.StatusOK, "TOTP removed successfully")
}

// ChangePassword changes the user's password
// POST /api/v1/settings/password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (h *TOTPHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized")
		return
	}

	// Change password
	if err := h.totpService.ChangePassword(userSubject, req.CurrentPassword, req.NewPassword); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "failed to change password"+": "+err.Error())
		return
	}

	response.Message(c, http.StatusOK, "Password changed successfully")
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

	c.JSON(http.StatusOK, TOTPDeviceListResponse{Devices: devices})
}

// TOTPEnrolmentResponse carries the shared secret and otpauth URL for a new TOTP device.
type TOTPEnrolmentResponse struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

// TOTPStatusResponse reports whether TOTP is enabled for the caller.
type TOTPStatusResponse struct {
	Enabled bool `json:"enabled"`
}

// TOTPDeviceListResponse lists the caller's registered MFA devices.
type TOTPDeviceListResponse struct {
	Devices []*totp.MFADevice `json:"devices"`
}
