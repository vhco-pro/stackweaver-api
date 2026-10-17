// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
)

type SessionsHandler struct {
	sessionsService sessionsBackend
	authService     *auth.Service
}

// sessionsBackend is the identity provider's side of the session list: the methods of
// sessions.Service these handlers call, declared where they are used so a test can stand in for
// the identity provider.
type sessionsBackend interface {
	ListUserSessions(userID string) ([]*sessions.Session, error)
	RevokeSession(sessionID string) error
}

func NewSessionsHandler(sessionsService *sessions.Service, authService *auth.Service) *SessionsHandler {
	h := &SessionsHandler{authService: authService}
	if sessionsService != nil {
		h.sessionsService = sessionsService
	}
	return h
}

// ListSessions lists all active sessions for the current user
// GET /api/v2/settings/sessions
func (h *SessionsHandler) ListSessions(c *gin.Context) {
	if h.sessionsService == nil {
		jsonapi.WriteError(c, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable), "sessions service is not available")
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized"+": "+err.Error())
		return
	}

	if userSubject == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "user subject is missing")
		return
	}

	// List sessions
	sessionList, err := h.sessionsService.ListUserSessions(userSubject)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to list sessions"+": "+err.Error())
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

	data := make([]jsonapi.Resource[SessionAttributes], 0, len(sessionsWithCurrent))
	for _, s := range sessionsWithCurrent {
		data = append(data, jsonapi.Resource[SessionAttributes]{
			ID:   s.ID,
			Type: "sessions",
			Attributes: SessionAttributes{
				UserAgent: s.UserAgent, IPAddress: s.IPAddress, CreationDate: s.CreationDate,
				ExpirationDate: s.ExpirationDate, Factors: s.Factors, IsCurrent: s.IsCurrent,
			},
		})
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
}

// RevokeSession revokes a session
// DELETE /api/v2/settings/sessions/:sessionId
func (h *SessionsHandler) RevokeSession(c *gin.Context) {
	if h.sessionsService == nil {
		jsonapi.WriteError(c, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable), "sessions service is not available")
		return
	}

	sessionID := c.Param("sessionId")
	if sessionID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "session ID is required")
		return
	}

	// Get user's Zitadel subject from context
	userSubject, err := h.authService.GetUserSubject(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "unauthorized"+": "+err.Error())
		return
	}

	if userSubject == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "user subject is missing")
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
			jsonapi.WriteError(c, http.StatusForbidden, jsonapi.TitleForbidden, "session does not belong to user")
			return
		}
	}

	// Revoke session
	if err := h.sessionsService.RevokeSession(sessionID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to revoke session"+": "+err.Error())
		return
	}

	c.Status(http.StatusNoContent)
}

// SessionWithCurrent is a session annotated with whether it is the caller's own.
type SessionWithCurrent struct {
	*sessions.Session
	IsCurrent bool
}

// SessionAttributes describe one of the caller's sessions at the identity provider.
type SessionAttributes struct {
	UserAgent      string    `json:"user-agent"`
	IPAddress      string    `json:"ip-address,omitempty"`
	CreationDate   time.Time `json:"creation-date"`
	ExpirationDate time.Time `json:"expiration-date"`
	Factors        []string  `json:"factors"`
	IsCurrent      bool      `json:"is-current"`
}
