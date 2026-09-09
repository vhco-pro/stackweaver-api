// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
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

// CollectionAttributes is the wire shape of an ansible-collections resource.
//
// Deliberately not CollectionInfo, whose Description carries `omitempty`. This block was built
// as an untyped map that always wrote "description", so reusing that tag would drop the member
// for every collection without one - a silent wire change of exactly the kind #760 typed these
// blocks to prevent. The member is emitted unconditionally here because it always was.
type CollectionAttributes struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

// collectionResource renders one collection in the shape the handlers previously hand-rolled.
func collectionResource(col CollectionInfo) jsonapi.Resource[CollectionAttributes] {
	// A plain conversion: the layouts are identical and Go ignores struct tags here, which is
	// the point - the two types exist precisely so the wire tags can differ.
	return jsonapi.Resource[CollectionAttributes]{
		ID:         col.Name,
		Type:       "ansible-collections",
		Attributes: CollectionAttributes(col),
	}
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
	data := make([]jsonapi.Resource[CollectionAttributes], len(collections))
	for i, col := range collections {
		data[i] = collectionResource(col)
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
}

// ListJobCollections returns collections installed for a specific job
// GET /ansible/jobs/:id/collections
func (h *CollectionsHandler) ListJobCollections(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid job ID")
		return
	}

	// AUD-128: gate on the job's read permission (mirrors jobs.go Get). The listing is
	// static today, but the endpoint is keyed by job ID and will track per-job
	// installations - so authorize the caller against the job now, before real data
	// is wired in.
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, jsonapi.TitleUnauthorized, "Authentication required")
		return
	}
	job, err := h.jobService.GetJob(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Job not found")
		return
	}
	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(), user.ID, rbac.ResourceTypeAnsibleJob, job.ID.String(), rbac.PermissionAnsibleJobRead, &job.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, jsonapi.TitleForbidden, "You don't have permission to view this job")
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
	// For now, return a placeholder response. It still carries the pagination block: a client
	// cannot tell a stub from a genuinely empty result, so "zero rows, one page" is both true
	// and the answer that stops it guessing.
	data := []jsonapi.Resource[CollectionAttributes]{}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, galaxySearchMeta{
		PaginationMeta: jsonapi.NewFullPageMeta(len(data)),
		Message:        "Galaxy search not yet implemented. Browse collections at https://galaxy.ansible.com",
	})
}

// galaxySearchMeta carries the standard pagination block alongside the stub's explanatory
// message. Typed rather than a map so the wire shape is visible to the compiler and the
// OpenAPI generator (#760).
type galaxySearchMeta struct {
	jsonapi.PaginationMeta
	Message string `json:"message"`
}
