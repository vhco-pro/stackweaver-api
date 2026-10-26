// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/logtoken"
	"github.com/michielvha/stackweaver/core/models"
)

// buildLogReadURL builds the absolute log-read-url for a run, appending extraQuery (e.g.
// "phase=apply") and a run-bound log token (AUD-045) minted for the request's credential: its API
// key, or its browser session. The token re-establishes that credential on every read, so it
// reads only while the credential may (see package logtoken). When no token can be minted, the URL
// is returned without one and the client authenticates with its Authorization header.
func buildLogReadURL(c *gin.Context, scheme, host, runID, extraQuery string) string {
	base := fmt.Sprintf("%s://%s/api/v2/runs/%s/logs", scheme, host, runID)
	var params []string
	if extraQuery != "" {
		params = append(params, extraQuery)
	}
	if tok := logtoken.Mint(runID, requestCredential(c)); tok != "" {
		params = append(params, "token="+tok)
	}
	if len(params) > 0 {
		return base + "?" + strings.Join(params, "&")
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
