// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
	"github.com/michielvha/stackweaver/core/models"
)

type SessionsHandler struct {
	sessionsService sessionsBackend
	authService     *auth.Service
	browserSessions browserSessionEnder
}

// browserSessionEnder ends the Stackweaver browser sessions signed in through a Zitadel session.
type browserSessionEnder interface {
	DeleteByZitadelSID(sid string) (int64, error)
}

// sessionsBackend is the identity provider's side of the session list: the methods of
// sessions.Service these handlers call, declared where they are used so a test can stand in for
// the identity provider.
type sessionsBackend interface {
	ListUserSessions(userID string) ([]*sessions.Session, error)
	RevokeSession(sessionID string) error
}

func NewSessionsHandler(sessionsService *sessions.Service, authService *auth.Service, browserSessions browserSessionEnder) *SessionsHandler {
	h := &SessionsHandler{authService: authService, browserSessions: browserSessions}
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

	// The current session is the Zitadel session the caller's browser session was signed in
	// through (the sid of its ID token).
	currentSID := ""
	if v, ok := c.Get(auth.BrowserSessionContextKey); ok {
		if bs, ok := v.(*models.BrowserSession); ok {
			currentSID = bs.ZitadelSID
		}
	}
	sessionsWithCurrent := make([]SessionWithCurrent, len(sessionList))
	for i, session := range sessionList {
		sessionsWithCurrent[i] = SessionWithCurrent{Session: session, IsCurrent: currentSID != "" && session.ID == currentSID}
	}

	data := make([]jsonapi.Resource[SessionAttributes], 0, len(sessionsWithCurrent))
	for _, s := range sessionsWithCurrent {
		data = append(data, jsonapi.Resource[SessionAttributes]{
			ID:         s.ID,
			Type:       "sessions",
			Attributes: sessionAttributes(s),
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

	// The session must be one of the caller's: the service account could revoke anyone's. When the
	// list cannot be read, ownership is unknown, so nothing is revoked.
	sessions, err := h.sessionsService.ListUserSessions(userSubject)
	if err != nil {
		jsonapi.WriteError(c, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable), "could not confirm the session belongs to you; try again")
		return
	}
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

	// Revoke session
	if err := h.sessionsService.RevokeSession(sessionID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "failed to revoke session"+": "+err.Error())
		return
	}

	// The browsers signed in through that Zitadel session are refused from their next request.
	if h.browserSessions != nil {
		if _, err := h.browserSessions.DeleteByZitadelSID(sessionID); err != nil {
			logger.Errorf("sessions: revoked Zitadel session %s but could not delete its browser sessions: %v", sessionID, err)
			jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "revoked the session but failed to sign its browsers out")
			return
		}
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
	UserAgent      string     `json:"user-agent"`
	IPAddress      string     `json:"ip-address,omitempty"`
	CreationDate   time.Time  `json:"creation-date"`
	ExpirationDate *time.Time `json:"expiration-date,omitempty"`
	Factors        []string   `json:"factors"`
	IsCurrent      bool       `json:"is-current"`
}

// sessionAttributes describes s. A Zitadel session created without a lifetime has no expiration,
// which the attribute leaves out rather than reporting Go's zero time.
func sessionAttributes(s SessionWithCurrent) SessionAttributes {
	attrs := SessionAttributes{
		UserAgent: s.UserAgent, IPAddress: s.IPAddress, CreationDate: s.CreationDate,
		Factors: s.Factors, IsCurrent: s.IsCurrent,
	}
	if !s.ExpirationDate.IsZero() {
		exp := s.ExpirationDate
		attrs.ExpirationDate = &exp
	}
	return attrs
}
