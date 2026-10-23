// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// sessionCheckTimeout bounds the session read made after a refresh. A slow read takes the same
// path as a failed one (the refresh goes through) rather than holding the browser's refresh for the
// proxy client's full timeout.
const sessionCheckTimeout = 5 * time.Second

// refreshAnswer is the part of Zitadel's token response the session check reads.
type refreshAnswer struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// sessionVerdict is what the session check concluded about a refreshed token set.
type sessionVerdict int

const (
	sessionAlive   sessionVerdict = iota // the session exists, or the check could not tell
	sessionEnded                         // Zitadel answered 404 for the session
	sessionUnnamed                       // the answer names no session, so it is not the SPA's
)

// checkRefreshedSession reads the session a successful refresh belongs to. Zitadel keeps honouring a
// refresh token after the session it was issued for has been deleted, so the proxy asks: a session
// that no longer exists must stop yielding tokens. It returns the verdict and the refresh token
// Zitadel just issued, which the caller revokes when the session has ended. Any outcome other than a
// definite 404 counts as alive and is logged: the refresh has just succeeded at Zitadel, so a failed
// read is a blip between two calls to the same service, and the next refresh checks again.
func (p *AuthProxy) checkRefreshedSession(ctx context.Context, body []byte) (sessionVerdict, string) {
	var answer refreshAnswer
	if err := json.Unmarshal(body, &answer); err != nil {
		return sessionUnnamed, ""
	}
	sid, ok := sessionIDFromIDToken(answer.IDToken)
	if !ok {
		return sessionUnnamed, answer.RefreshToken
	}

	ctx, cancel := context.WithTimeout(ctx, sessionCheckTimeout)
	defer cancel()
	_, status, err := p.proxyJSON(ctx, http.MethodGet, "/v2/sessions/"+url.PathEscape(sid), nil)
	switch {
	case err != nil:
		p.warnf("auth proxy: refresh let through, session check failed: %v", err)
		return sessionAlive, answer.RefreshToken
	case status == http.StatusNotFound:
		return sessionEnded, answer.RefreshToken
	case status != http.StatusOK:
		p.warnf("auth proxy: refresh let through, session check answered %d", status)
	}
	return sessionAlive, answer.RefreshToken
}

// sessionIDFromIDToken reads the sid claim from an ID token's payload. The token comes straight from
// Zitadel over the internal URL, so decoding is enough; its signature is not checked a second time.
func sessionIDFromIDToken(idToken string) (string, bool) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.SID == "" {
		return "", false
	}
	return claims.SID, true
}

// revokeRefreshToken asks Zitadel to revoke a refresh token. The SPA is a public client, so the
// request carries only the token and the client_id, never the proxy's own credential.
func (p *AuthProxy) revokeRefreshToken(ctx context.Context, refreshToken, clientID string) error {
	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {clientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.zitadelURL("/oauth/v2/revoke"), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("building the revocation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range p.parsedHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("revoking the refresh token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoking the refresh token: Zitadel answered %d", resp.StatusCode)
	}
	return nil
}
