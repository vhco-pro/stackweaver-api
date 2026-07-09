// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
)

// authorizeInventoryResource gates a caller against an inventory's RBAC. It is the
// shared authorization check for the inventory sub-resource handlers (hosts,
// groups, inventory sources), which own no organization of their own and inherit
// their parent inventory's project/org scope. When the inventory is project-scoped
// it defers to CheckAnsibleResourcePermission; otherwise it falls back to the
// org-level manage/read check — mirroring inventories.go exactly. write=true
// requires inventory-write / manage-ansible, else inventory-read / read-ansible.
//
// It writes the JSON:API error response and returns false when the caller is
// unauthorized: 401 (no auth), 403 (no permission), 500 (permission lookup error).
// AUD-100: these sub-resource handlers previously performed no authorization, so
// any authenticated JWT identity (which bypasses the org wall) could read, mutate
// or delete any tenant's hosts/groups/sources — and read plaintext connection
// secrets in host/group variables — by UUID.
func authorizeInventoryResource(
	c *gin.Context,
	authService *auth.Service,
	rbacService *rbac.Service,
	inventory *models.AnsibleInventory,
	write bool,
) bool {
	user, err := authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}},
		})
		return false
	}

	perm := rbac.PermissionAnsibleInventoryRead
	if write {
		perm = rbac.PermissionAnsibleInventoryWrite
	}

	var hasPermission bool
	switch {
	case inventory.ProjectID != nil:
		hasPermission, err = rbacService.CheckAnsibleResourcePermission(
			c.Request.Context(),
			user.ID,
			rbac.ResourceTypeAnsibleInventory,
			inventory.ID.String(),
			perm,
			inventory.ProjectID,
		)
	case write:
		hasPermission, err = rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	default:
		hasPermission, err = rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, inventory.OrganizationID)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}},
		})
		return false
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to access this inventory"}},
		})
		return false
	}
	return true
}
