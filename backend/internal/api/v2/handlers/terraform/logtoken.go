// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"fmt"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/logtoken"
	"github.com/michielvha/stackweaver/core/models"
)

// buildLogReadURL builds the absolute log-read-url of a run's plan or apply phase. It carries a
// run-bound log token (AUD-045) minted for the request's credential, its API key or its browser
// session, in its path: /api/v2/runs/:id/logs/:phase/:token. The token re-establishes that
// credential on every read, so it reads only while the credential may (see package logtoken).
//
// The token is in the path because that is the only part of the URL a client keeps: go-tfe's log
// reader, which the Terraform CLI streams plan and apply logs with, replaces the query string with
// its own limit and offset and sends no Authorization header. A TFE log-read-url is likewise a
// pre-authorized URL. When no token can be minted, the URL names the phase's log route and the
// client authenticates with its Authorization header.
func buildLogReadURL(c *gin.Context, scheme, host, runID, phase string) string {
	base := fmt.Sprintf("%s://%s/api/v2/runs/%s/logs/%s", scheme, host, runID, phase)
	if tok := logtoken.Mint(runID, requestCredential(c)); tok != "" {
		return base + "/" + url.PathEscape(tok)
	}
	return base
}

// requestCredential is the credential the request was authenticated with.
func requestCredential(c *gin.Context) logtoken.Credential {
	if v, ok := c.Get("api_key_id"); ok {
		if id, ok := v.(uuid.UUID); ok {
			return logtoken.Credential{APIKeyID: id}
		}
	}
	if v, ok := c.Get(auth.BrowserSessionContextKey); ok {
		if s, ok := v.(*models.BrowserSession); ok && s != nil {
			return logtoken.Credential{BrowserSessionID: s.ID}
		}
	}
	return logtoken.Credential{}
}
