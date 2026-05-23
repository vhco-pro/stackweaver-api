// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build !e2e

// Production build: the testing/reset endpoint does not exist. This file is
// the stub that lets setupAuthProxyRoutes call registerTestingRoutes without
// knowing whether the binary was built with the e2e build tag.

package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	v2handlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
)

func registerTestingRoutes(_ *gin.RouterGroup, _ *middleware.IPRateLimiter, _ *v2handlers.AuthProxy) {
	// no-op: /auth/testing/reset is intentionally absent from production builds.
}
