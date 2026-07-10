// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// AUD-123: the Terraform registry-protocol endpoints (`/v1/providers`, `/v1/modules`) are
// registered on the root engine with NO auth middleware, because genuinely-public providers
// must stay anonymously reachable for `terraform init`. That left every PRIVATE provider and
// (all) module readable and downloadable — binaries included — by any unauthenticated caller.
// These helpers gate the private artifacts per-resource: parse the optional Bearer token the
// Terraform CLI sends for a private registry, and require org membership.

// registryBearerToken returns the Bearer token from the Authorization header, or "" if absent
// or malformed. The `/v1` groups have no AuthMiddleware, so tokens are resolved here.
func registryBearerToken(c *gin.Context) string {
	parts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// registryCaller resolves the (optional) authenticated user, or nil for an anonymous request.
// It prefers a user already established on the context (if some upstream middleware ran), then
// falls back to the Bearer token — the `/v1` groups have no AuthMiddleware, so the token path
// is the norm. It never writes a response.
func registryCaller(c *gin.Context, authService *auth.Service) *models.User {
	if user, err := authService.GetUserFromContext(c); err == nil && user != nil {
		return user
	}
	token := registryBearerToken(c)
	if token == "" {
		return nil
	}
	user, err := authService.GetUserFromToken(token)
	if err != nil || user == nil {
		return nil
	}
	return user
}

// authorizeRegistryRead gates a registry-protocol read/download of an org-owned artifact.
// A public artifact is always allowed. A private one requires a valid Bearer token whose user
// belongs to the owning org: a missing/invalid token yields 401, and a valid token for a
// non-member yields 404 — a non-member must not be able to confirm a private artifact exists.
// On denial it writes the response and returns false; otherwise it returns true.
func authorizeRegistryRead(c *gin.Context, authService *auth.Service, orgRepo *repository.OrganizationRepository, orgID uuid.UUID, public bool) bool {
	if public {
		return true
	}
	user := registryCaller(c, authService)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []string{"authentication required for private registry"}})
		return false
	}
	inOrg, err := orgRepo.UserInOrg(user.ID, orgID)
	if err != nil || !inOrg {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Not found"}})
		return false
	}
	return true
}

// registryAccessibleOrgs returns the subset of orgIDs the (optional) caller may see private
// artifacts for — the orgs they are a member of. Used to filter list/search results so private
// entries never leak to callers who are not members. An anonymous caller gets an empty set.
// Membership is checked once per distinct org.
func registryAccessibleOrgs(c *gin.Context, authService *auth.Service, orgRepo *repository.OrganizationRepository, orgIDs []uuid.UUID) map[uuid.UUID]bool {
	accessible := make(map[uuid.UUID]bool)
	user := registryCaller(c, authService)
	if user == nil {
		return accessible
	}
	checked := make(map[uuid.UUID]bool)
	for _, id := range orgIDs {
		if checked[id] {
			continue
		}
		checked[id] = true
		if inOrg, err := orgRepo.UserInOrg(user.ID, id); err == nil && inOrg {
			accessible[id] = true
		}
	}
	return accessible
}
