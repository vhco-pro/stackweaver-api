// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

// CollectionInfo represents an installed Ansible Galaxy collection
type CollectionInfo struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"` // "pre-installed", "requirements.yml", "manual"
}

// CollectionsHandler handles Galaxy collection-related endpoints
type CollectionsHandler struct {
	jobService  *ansible.JobService
	authService *auth.Service
	rbacService *rbac.Service
}

// NewCollectionsHandler creates a new CollectionsHandler
func NewCollectionsHandler(jobService *ansible.JobService, authService *auth.Service, rbacService *rbac.Service) *CollectionsHandler {
	return &CollectionsHandler{
		jobService:  jobService,
		authService: authService,
		rbacService: rbacService,
	}
}

// ListPreInstalledCollections returns the list of pre-installed collections in the runner
// GET /ansible/collections/pre-installed
func (h *CollectionsHandler) ListPreInstalledCollections(c *gin.Context) {
	// These are the collections pre-installed in runner-images/ansible/Dockerfile
	collections := []CollectionInfo{
		{
			Name:        "amazon.aws",
			Namespace:   "amazon",
			Version:     "latest",
			Description: "AWS cloud modules and dynamic inventory plugins",
			Source:      "pre-installed",
		},
		{
			Name:        "azure.azcollection",
			Namespace:   "azure",
			Version:     "latest",
			Description: "Azure cloud modules and dynamic inventory plugins",
			Source:      "pre-installed",
		},
		{
			Name:        "google.cloud",
			Namespace:   "google",
			Version:     "latest",
			Description: "GCP cloud modules and dynamic inventory plugins",
			Source:      "pre-installed",
		},
		{
			Name:        "community.vmware",
			Namespace:   "community",
			Version:     "latest",
			Description: "VMware vSphere modules",
			Source:      "pre-installed",
		},
		{
			Name:        "community.general",
			Namespace:   "community",
			Version:     "latest",
			Description: "General-purpose modules (1000+ modules)",
			Source:      "pre-installed",
		},
		{
			Name:        "ansible.posix",
			Namespace:   "ansible",
			Version:     "latest",
			Description: "POSIX system modules and JSONL callback",
			Source:      "pre-installed",
		},
		{
			Name:        "ansible.netcommon",
			Namespace:   "ansible",
			Version:     "latest",
			Description: "Network automation base modules",
			Source:      "pre-installed",
		},
	}

	// Convert to JSON:API format
	data := make([]map[string]interface{}, len(collections))
	for i, col := range collections {
		data[i] = map[string]interface{}{
			"type": "ansible-collections",
			"id":   col.Name,
			"attributes": map[string]interface{}{
				"name":        col.Name,
				"namespace":   col.Namespace,
				"version":     col.Version,
				"description": col.Description,
				"source":      col.Source,
			},
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// ListJobCollections returns collections installed for a specific job
// GET /ansible/jobs/:id/collections
func (h *CollectionsHandler) ListJobCollections(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []map[string]string{{"status": "400", "detail": "Invalid job ID"}},
		})
		return
	}

	// AUD-128: gate on the job's read permission (mirrors jobs.go Get). The listing is
	// static today, but the endpoint is keyed by job ID and will track per-job
	// installations — so authorize the caller against the job now, before real data
	// is wired in.
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []map[string]string{{"status": "401", "detail": "Authentication required"}},
		})
		return
	}
	job, err := h.jobService.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []map[string]string{{"status": "404", "detail": "Job not found"}},
		})
		return
	}
	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleJob, job.ID.String(), rbac.PermissionAnsibleJobRead, &job.ProjectID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []map[string]string{{"status": "500", "detail": "Failed to check permissions"}},
		})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []map[string]string{{"status": "403", "detail": "You don't have permission to view this job"}},
		})
		return
	}

	// For now, return the pre-installed collections
	// In the future, we'll track per-job installations from requirements.yml
	h.ListPreInstalledCollections(c)
}

// SearchGalaxyCollections searches for collections on Galaxy Hub
// GET /ansible/collections/search?q=keyword
func (h *CollectionsHandler) SearchGalaxyCollections(c *gin.Context) {
	// This would call the Galaxy API in a real implementation
	// For now, return a placeholder response
	c.JSON(http.StatusOK, gin.H{
		"data": []interface{}{},
		"meta": map[string]interface{}{
			"message": "Galaxy search not yet implemented. Browse collections at https://galaxy.ansible.com",
		},
	})
}
