// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/storage"
)

type StateVersionHandlerV2 struct {
	stateVersionRepo  *repository.StateVersionRepository
	workspaceRepo     *repository.WorkspaceRepository
	projectRepo       *repository.ProjectRepository
	authService       *auth.Service
	rbacService       *rbac.Service
	stateService      *state.Service
	storageClient     storage.Client
	stateOutputRepo   *repository.StateVersionOutputRepository
	stateResourceRepo *repository.StateVersionResourceRepository
}

func NewStateVersionHandlerV2(
	stateVersionRepo *repository.StateVersionRepository,
	workspaceRepo *repository.WorkspaceRepository,
	projectRepo *repository.ProjectRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	stateService *state.Service,
	storageClient storage.Client,
	stateOutputRepo *repository.StateVersionOutputRepository,
	stateResourceRepo *repository.StateVersionResourceRepository,
) *StateVersionHandlerV2 {
	return &StateVersionHandlerV2{
		stateVersionRepo:  stateVersionRepo,
		workspaceRepo:     workspaceRepo,
		projectRepo:       projectRepo,
		authService:       authService,
		rbacService:       rbacService,
		stateService:      stateService,
		storageClient:     storageClient,
		stateOutputRepo:   stateOutputRepo,
		stateResourceRepo: stateResourceRepo,
	}
}

// outputCrypto returns the encryption-at-rest service used to decrypt sensitive
// materialized output values, or nil when encryption is disabled.
func (h *StateVersionHandlerV2) outputCrypto() *crypto.CryptoService {
	if h.stateService == nil {
		return nil
	}
	return h.stateService.Crypto()
}

type CreateStateVersionRequestV2 struct {
	StateData map[string]interface{} `json:"state_data" binding:"required"`
	Serial    *int                   `json:"serial,omitempty"`
	Lineage   string                 `json:"lineage,omitempty"`
}

// hostedStateDownloadURL returns the API URL for downloading state (TFE hosted-state-download-url).
// Terraform fetches state from this URL; it must be reachable (use API URL, not internal MinIO).
func (h *StateVersionHandlerV2) hostedStateDownloadURL(c *gin.Context, v *models.StateVersion) string {
	host := c.GetHeader("Host")
	if host == "" {
		host = c.Request.Host
	}
	scheme := "https"
	if c.GetHeader("X-Forwarded-Proto") == "http" || c.Request.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/api/v2/state-versions/%s/download", scheme, host, v.ID)
}

// ListByWorkspace lists state versions for a workspace (TFE-compatible)
// GET /api/v2/workspaces/:id/state-versions
func (h *StateVersionHandlerV2) ListByWorkspace(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid workspace ID",
				},
			},
		})
		return
	}

	// Verify workspace exists and get project ID
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Workspace not found",
				},
			},
		})
		return
	}

	// Check permission: state versions read
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "read")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "Insufficient permissions to view state versions",
				},
			},
		})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	if perPage > 100 {
		perPage = 100
	}
	offset := (page - 1) * perPage

	versions, total, err := h.stateVersionRepo.ListByWorkspace(workspaceID, perPage, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to list state versions",
				},
			},
		})
		return
	}

	// TFE-compatible response format
	c.JSON(http.StatusOK, gin.H{
		"data": versions,
		"meta": gin.H{
			"pagination": gin.H{
				"page":     page,
				"per_page": perPage,
				"total":    total,
			},
		},
	})
}

// CurrentStateVersion returns the latest state version for a workspace (TFE-compatible).
// GET /api/v2/workspaces/:id/current-state-version
// Terraform remote backend uses this plus hosted-state-download-url to pull state; missing URL caused tfe_* drift.
func (h *StateVersionHandlerV2) CurrentStateVersion(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{"status": "400", "title": "Bad Request", "detail": "Invalid workspace ID"},
			},
		})
		return
	}

	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{"status": "404", "title": "Not Found", "detail": "Workspace not found"},
			},
		})
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{"status": "401", "title": "Unauthorized", "detail": "Authentication required"},
			},
		})
		return
	}

	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "read")
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{"status": "403", "title": "Forbidden", "detail": "Insufficient permissions to view state version"},
			},
		})
		return
	}

	version, err := h.stateVersionRepo.GetLatest(workspaceID)
	if err != nil || version == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{"status": "404", "title": "Not Found", "detail": "No state version for this workspace"},
			},
		})
		return
	}

	attrs := buildStateVersionAttributes(version)
	attrs["hosted-state-download-url"] = h.hostedStateDownloadURL(c, version)

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":         version.ID,
			"type":       "state-versions",
			"attributes": attrs,
			"relationships": gin.H{
				"workspace": gin.H{
					"data": gin.H{"id": version.WorkspaceID, "type": "workspaces"},
				},
			},
		},
	})
}

// Get returns a single state version by ID (TFE-compatible)
// GET /api/v2/state-versions/:id
func (h *StateVersionHandlerV2) Get(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid state version ID",
				},
			},
		})
		return
	}

	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "State version not found",
				},
			},
		})
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Workspace not found",
				},
			},
		})
		return
	}

	// Check permission: state versions read
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "read")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "Insufficient permissions to view state version",
				},
			},
		})
		return
	}

	attrs := buildStateVersionAttributes(version)
	attrs["hosted-state-download-url"] = h.hostedStateDownloadURL(c, version)

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":         version.ID,
			"type":       "state-versions",
			"attributes": attrs,
			"relationships": gin.H{
				"workspace": gin.H{
					"data": gin.H{
						"id":   version.WorkspaceID,
						"type": "workspaces",
					},
				},
			},
		},
	})
}

// buildStateVersionAttributes returns attributes map for state version (JSON:API).
func buildStateVersionAttributes(v *models.StateVersion) map[string]interface{} {
	var m map[string]interface{}
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]interface{}{}
	}
	_ = json.Unmarshal(b, &m)
	if m == nil {
		m = make(map[string]interface{})
	}
	return m
}

// Download streams the raw state JSON for a state version (TFE hosted-state-download-url target).
// GET /api/v2/state-versions/:id/download
func (h *StateVersionHandlerV2) Download(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{"status": "400", "title": "Bad Request", "detail": "Invalid state version ID"},
			},
		})
		return
	}

	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{"status": "404", "title": "Not Found", "detail": "State version not found"},
			},
		})
		return
	}

	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{"status": "404", "title": "Not Found", "detail": "Workspace not found"},
			},
		})
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{"status": "401", "title": "Unauthorized", "detail": "Authentication required"},
			},
		})
		return
	}

	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "read")
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{"status": "403", "title": "Forbidden", "detail": "Insufficient permissions to download state"},
			},
		})
		return
	}

	var stateJSON []byte
	if h.stateService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{"status": "500", "title": "Internal Server Error", "detail": "State storage unavailable"},
			},
		})
		return
	}
	// Route through the state service so encrypted-at-rest state is decrypted to plain
	// JSON for Terraform (legacy plain JSON is tolerated transparently).
	stateJSON, err = h.stateService.GetStateObject(c.Request.Context(), version.WorkspaceID, version.Version)
	if err != nil {
		logger.Warnf("State version %s download: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{"status": "500", "title": "Internal Server Error", "detail": "Failed to load state"},
			},
		})
		return
	}

	c.Header("Content-Type", "application/json")
	c.Data(http.StatusOK, "application/json", stateJSON)
}

// GetOutputs returns outputs for a state version (TFE-compatible)
// GET /api/v2/state-versions/:id/outputs
func (h *StateVersionHandlerV2) GetOutputs(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid state version ID",
				},
			},
		})
		return
	}

	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "State version not found",
				},
			},
		})
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Workspace not found",
				},
			},
		})
		return
	}

	// Check permission: state versions read-outputs (allows reading outputs even if full state is restricted)
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "read-outputs")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "Insufficient permissions to view state version outputs",
				},
			},
		})
		return
	}

	// TFE-compatible: mask sensitive values (return nil); see current-state-version-outputs.
	outputs := materializedOutputs(h.stateOutputRepo, version, true, h.outputCrypto())

	c.JSON(http.StatusOK, gin.H{
		"data": outputs,
	})
}

// CurrentStateVersionOutputs serves the outputs of a workspace's current (latest) state
// version from the materialized table (TFE current-state-version-outputs parity). Gated by
// the lower "read-outputs" permission so output values can be read without state-read access.
// GET /api/v2/workspaces/:id/current-state-version-outputs
func (h *StateVersionHandlerV2) CurrentStateVersionOutputs(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid workspace ID"}}})
		return
	}
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workspace not found"}}})
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}
	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspace.ID, workspace.ProjectID, "read-outputs")
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "Insufficient permissions to view outputs"}}})
		return
	}
	version, err := h.stateVersionRepo.GetLatest(workspace.ID)
	if err != nil || version == nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "No state version for this workspace"}}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": materializedOutputs(h.stateOutputRepo, version, true, h.outputCrypto())})
}

// CurrentStateVersionResources serves the resources of a workspace's current (latest) state
// version from the materialized table. Optional ?mode=managed|data filters; default all.
// Backs the workspace Resources and Data Sources tabs without parsing the raw state blob.
// GET /api/v2/workspaces/:id/current-state-version-resources
func (h *StateVersionHandlerV2) CurrentStateVersionResources(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid workspace ID"}}})
		return
	}
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Workspace not found"}}})
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return
	}
	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspace.ID, workspace.ProjectID, "read")
	if err != nil || !ok {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "Insufficient permissions to view resources"}}})
		return
	}
	version, err := h.stateVersionRepo.GetLatest(workspace.ID)
	if err != nil || version == nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "No state version for this workspace"}}})
		return
	}
	mode := c.Query("mode")
	resources := []gin.H{}
	if h.stateResourceRepo != nil {
		rows, listErr := h.stateResourceRepo.ListByStateVersion(version.ID, mode)
		if listErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to list resources"}}})
			return
		}
		resources = buildMaterializedResources(rows)
	}
	c.JSON(http.StatusOK, gin.H{"data": resources})
}

// buildMaterializedResources renders state-version-resources JSON:API objects from rows.
func buildMaterializedResources(rows []models.StateVersionResource) []gin.H {
	result := []gin.H{}
	for _, r := range rows {
		result = append(result, gin.H{
			"id":   r.ID,
			"type": "state-version-resources",
			"attributes": gin.H{
				"address":        r.Address,
				"mode":           r.Mode,
				"type":           r.Type,
				"name":           r.Name,
				"provider":       r.Provider,
				"module":         r.Module,
				"instance-count": r.InstanceCount,
			},
		})
	}
	return result
}

// materializedOutputs returns TFE-compatible outputs for a state version, read from the
// materialized state_version_outputs table (State Storage Rework — the single source of truth).
// cryptoSvc decrypts sensitive output values stored encrypted at rest (#95); pass nil when
// encryption is disabled.
func materializedOutputs(repo *repository.StateVersionOutputRepository, version *models.StateVersion, maskSensitive bool, cryptoSvc *crypto.CryptoService) []gin.H {
	if repo == nil || version == nil {
		return []gin.H{}
	}
	outs, err := repo.ListByStateVersion(version.ID)
	if err != nil {
		return []gin.H{}
	}
	return buildMaterializedOutputs(outs, maskSensitive, cryptoSvc)
}

// buildMaterializedOutputs renders TFE state-version-outputs JSON:API objects from the
// materialized rows. Value/Type are stored JSON-encoded, so they are decoded back into
// real JSON values for the response. Values encrypted at rest (#95, sensitive outputs)
// are decrypted with cryptoSvc first; if a value is encrypted and cannot be decrypted
// (no key) it is nulled so ciphertext never leaks. Sensitive values are nulled when
// maskSensitive.
func buildMaterializedOutputs(outs []models.StateVersionOutput, maskSensitive bool, cryptoSvc *crypto.CryptoService) []gin.H {
	result := []gin.H{}
	for _, o := range outs {
		raw := o.Value
		if o.ValueEncrypted {
			if cryptoSvc == nil {
				raw = ""
			} else if dec, err := cryptoSvc.Decrypt(o.Value); err == nil {
				raw = dec
			} else {
				raw = "" // never emit ciphertext
			}
		}
		var value any
		if raw != "" {
			_ = json.Unmarshal([]byte(raw), &value)
		}
		if maskSensitive && o.Sensitive {
			value = nil
		}
		attrs := gin.H{"name": o.Name, "value": value, "sensitive": o.Sensitive}
		if o.Type != "" {
			var t any
			if err := json.Unmarshal([]byte(o.Type), &t); err == nil {
				attrs["type"] = t
			}
		}
		result = append(result, gin.H{
			"id":         o.ID,
			"type":       "state-version-outputs",
			"attributes": attrs,
		})
	}
	return result
}

// Create creates a new state version for a workspace (TFE-compatible)
// POST /api/v2/workspaces/:id/state-versions
func (h *StateVersionHandlerV2) Create(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid workspace ID",
				},
			},
		})
		return
	}

	// Verify workspace exists
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Workspace not found",
				},
			},
		})
		return
	}

	// Check permission: state versions write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "write")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "Insufficient permissions to create state versions",
				},
			},
		})
		return
	}

	// Check if workspace is manually locked (TFE-compatible)
	if workspace.Locked {
		detail := "Workspace is locked. Unlock the workspace to create state versions."
		if workspace.LockedReason != "" {
			detail = fmt.Sprintf("Workspace is locked: %s", workspace.LockedReason)
		}
		c.JSON(http.StatusConflict, gin.H{
			"errors": []gin.H{
				{
					"status": "409",
					"title":  "Conflict",
					"detail": detail,
				},
			},
		})
		return
	}

	// Check if state is locked by an active run (TFE-compatible)
	if h.stateService != nil {
		existingLock, lockErr := h.stateService.GetStateLock(c.Request.Context(), workspaceID)
		if lockErr == nil && existingLock != nil && !existingLock.IsExpired() {
			c.JSON(http.StatusConflict, gin.H{
				"errors": []gin.H{
					{
						"status": "409",
						"title":  "Conflict",
						"detail": fmt.Sprintf("State is locked by run %v (lock ID: %s)", existingLock.LockedBy, existingLock.LockID),
					},
				},
			})
			return
		}
	}

	var req CreateStateVersionRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	// Marshal the state for storage first (validation), then reserve the version + write the object.
	stateJSON, err := json.Marshal(req.StateData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Failed to marshal state data",
				},
			},
		})
		return
	}

	// AUD-018: atomically reserve the next version through the shared path (retry on the
	// unique-violation, reject a serial regression with 409), row-first then object storage.
	stateVersion := &models.StateVersion{
		WorkspaceID: workspaceID,
		Serial:      req.Serial,
		Lineage:     req.Lineage,
	}
	nextVersion, err := h.stateVersionRepo.CreateNextVersion(stateVersion)
	if err != nil {
		if errors.Is(err, repository.ErrStateSerialRegression) {
			c.JSON(http.StatusConflict, gin.H{
				"errors": []gin.H{{"status": "409", "title": "Conflict", "detail": "incoming state serial is older than the current state version"}},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to create state version",
				},
			},
		})
		return
	}

	// Store the state object (encrypted at rest via the state service), keyed on the reserved
	// version. On failure roll back the reserved row so no dangling version remains.
	if h.stateService != nil {
		if err := h.stateService.PutStateObject(c.Request.Context(), workspaceID, nextVersion, stateJSON); err != nil {
			_ = h.stateVersionRepo.Delete(stateVersion.ID)
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{
					{
						"status": "500",
						"title":  "Internal Server Error",
						"detail": fmt.Sprintf("Failed to store state in object storage: %v", err),
					},
				},
			})
			return
		}
	}

	// Materialize outputs/resources from the pushed state (State Storage Rework).
	// Best-effort: the raw state is already persisted in object storage authoritatively.
	if h.stateService != nil {
		if err := h.stateService.Materialize(stateVersion.ID, req.StateData); err != nil {
			logger.Warnf("Failed to materialize outputs/resources for state version %s: %v", stateVersion.ID, err)
		}
	}

	// TFE-compatible response format
	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"id":         stateVersion.ID,
			"type":       "state-versions",
			"attributes": stateVersion,
			"relationships": gin.H{
				"workspace": gin.H{
					"data": gin.H{
						"id":   workspaceID,
						"type": "workspaces",
					},
				},
			},
		},
	})
}

// RemoveResource removes a resource from the latest state version by address
// POST /api/v2/workspaces/:id/state-versions/remove-resource
func (h *StateVersionHandlerV2) RemoveResource(c *gin.Context) {
	logger.Debugf("StateVersionHandlerV2 RemoveResource - Request received for workspace: %s", c.Param("id"))
	workspaceID := c.Param("id")
	if workspaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid workspace ID",
				},
			},
		})
		return
	}

	// Verify workspace exists and get project ID
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Workspace not found",
				},
			},
		})
		return
	}

	// Check permission: state versions write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "write")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "Insufficient permissions to modify state",
				},
			},
		})
		return
	}

	// Parse request body
	var req struct {
		Address string `json:"address" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": fmt.Sprintf("Invalid request: %v", err),
				},
			},
		})
		return
	}

	// Remove resource from state
	if h.stateService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "State service not initialized",
				},
			},
		})
		return
	}

	if err := h.stateService.RemoveResourceFromState(c.Request.Context(), workspaceID, req.Address); err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []gin.H{
					{
						"status": "404",
						"title":  "Not Found",
						"detail": err.Error(),
					},
				},
			})
			return
		}

		// Check if it's a "locked" error
		if strings.Contains(err.Error(), "locked") {
			c.JSON(http.StatusConflict, gin.H{
				"errors": []gin.H{
					{
						"status": "409",
						"title":  "Conflict",
						"detail": err.Error(),
					},
				},
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	// Return success
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": fmt.Sprintf("Resource %s removed from state", req.Address),
		},
	})
}

// Delete deletes a state version (StackWeaver-specific feature)
// DELETE /api/v2/state-versions/:id
func (h *StateVersionHandlerV2) Delete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid state version ID",
				},
			},
		})
		return
	}

	// Get state version
	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "State version not found",
				},
			},
		})
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []gin.H{
				{
					"status": "404",
					"title":  "Not Found",
					"detail": "Workspace not found",
				},
			},
		})
		return
	}

	// Check permission: state versions write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "write")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to check permissions",
				},
			},
		})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "Insufficient permissions to delete state version",
				},
			},
		})
		return
	}

	// Delete state version
	if h.stateService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "State service not initialized",
				},
			},
		})
		return
	}

	if err := h.stateService.DeleteStateVersion(c.Request.Context(), id); err != nil {
		// Check if it's a "locked" error
		if strings.Contains(err.Error(), "locked") {
			c.JSON(http.StatusConflict, gin.H{
				"errors": []gin.H{
					{
						"status": "409",
						"title":  "Conflict",
						"detail": err.Error(),
					},
				},
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	// Return success (204 No Content)
	c.Status(http.StatusNoContent)
}
