// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
)

type SessionsHandler struct {
	sessionsService *sessions.Service
	authService     *auth.Service
}

func NewSessionsHandler(sessionsService *sessions.Service, authService *auth.Service) *SessionsHandler {
	return &SessionsHandler{
		sessionsService: sessionsService,
		authService:     authService,
	}
}

// ListSessions lists all active sessions for the current user
// GET /api/v2/settings/sessions
func (h *SessionsHandler) ListSessions(c *gin.Context) {
	if h.sessionsService == nil {
		response.LegacyError(c, http.StatusServiceUnavailable, "sessions service is not available")
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		response.LegacyErrorDetails(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	if userSubject == "" {
		response.LegacyError(c, http.StatusBadRequest, "user subject is missing")
		return
	}

	// List sessions
	sessionList, err := h.sessionsService.ListUserSessions(userSubject)
	if err != nil {
		response.LegacyErrorDetails(c, http.StatusInternalServerError, "failed to list sessions", err.Error())
		return
	}

	// Identify current session by comparing request metadata
	// Get current request's IP address
	currentIP := c.ClientIP()

	// Find the session that best matches the current request
	sessionsWithCurrent := make([]SessionWithCurrent, len(sessionList))

	// First, try to match by IP address (most reliable)
	matchedByIP := false
	for i, session := range sessionList {
		isCurrent := false

		// Match by IP address if available
		if currentIP != "" && session.IPAddress != "" && session.IPAddress == currentIP {
			isCurrent = true
			matchedByIP = true
		}

		sessionsWithCurrent[i] = SessionWithCurrent{
			Session:   session,
			IsCurrent: isCurrent,
		}
	}

	// If no match by IP, mark the most recent session as current (fallback)
	if !matchedByIP && len(sessionsWithCurrent) > 0 {
		sessionsWithCurrent[0].IsCurrent = true
	}

	c.JSON(http.StatusOK, SessionListResponse{Sessions: sessionsWithCurrent})
}

// RevokeSession revokes a session
// DELETE /api/v2/settings/sessions/:sessionId
func (h *SessionsHandler) RevokeSession(c *gin.Context) {
	if h.sessionsService == nil {
		response.LegacyError(c, http.StatusServiceUnavailable, "sessions service is not available")
		return
	}

	sessionID := c.Param("sessionId")
	if sessionID == "" {
		response.LegacyError(c, http.StatusBadRequest, "session ID is required")
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		response.LegacyErrorDetails(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	if userSubject == "" {
		response.LegacyError(c, http.StatusBadRequest, "user subject is missing")
		return
	}

	// Optional: Verify the session belongs to the user before revoking
	// This adds an extra security layer - we can list the user's sessions and check if the session ID exists
	sessions, err := h.sessionsService.ListUserSessions(userSubject)
	if err == nil {
		sessionExists := false
		for _, session := range sessions {
			if session.ID == sessionID {
				sessionExists = true
				break
			}
		}
		if !sessionExists {
			response.LegacyError(c, http.StatusForbidden, "session does not belong to user")
			return
		}
	}

	// Revoke session
	if err := h.sessionsService.RevokeSession(sessionID); err != nil {
		response.LegacyErrorDetails(c, http.StatusInternalServerError, "failed to revoke session", err.Error())
		return
	}

	response.Message(c, http.StatusOK, "Session revoked successfully")
}

// SessionWithCurrent is a session annotated with whether it is the caller's own.
//
// Hoisted to package scope so SessionListResponse can name it. It was declared inside
// ListSessions, which made the response body impossible to give a type.
type SessionWithCurrent struct {
	*sessions.Session
	IsCurrent bool `json:"is_current"`
}

// SessionListResponse is the body of GET /api/v2/settings/sessions.
type SessionListResponse struct {
	Sessions []SessionWithCurrent `json:"sessions"`
}
