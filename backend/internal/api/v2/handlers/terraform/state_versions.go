// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"crypto/md5" //nolint:gosec // TFE's integrity check of a pushed state is an MD5, not a security boundary
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/pagination"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/apierror"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
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

// CreateStateVersionRequestV2 is the document go-tfe marshals for StateVersionCreateOptions
// (#858, D7): md5 and serial are required, the state travels base64-encoded, and a run
// relationship names the run the state belongs to. The two-step upload flow
// (hosted-state-upload-url) is not served, so the state is required here.
type CreateStateVersionRequestV2 struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Lineage          *string `json:"lineage"`
			MD5              *string `json:"md5" binding:"required"`
			Serial           *int64  `json:"serial" binding:"required"`
			State            *string `json:"state"`
			Force            *bool   `json:"force"`
			JSONState        *string `json:"json-state"`
			JSONStateOutputs *string `json:"json-state-outputs"`
		} `json:"attributes"`
		Relationships struct {
			Run *jsonapi.Relationship `json:"run"`
		} `json:"relationships"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *CreateStateVersionRequestV2) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

// RemoveResourceRequest is the state-versions document that removes one resource from the
// latest state, which writes a new state version.
type RemoveResourceRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Address string `json:"address" binding:"required"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *RemoveResourceRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}

const stateVersionsType = "state-versions"

// stateVersionResource is the one projection of a state version every endpoint answers with
// (#858, D7): TFE's attributes, which go-tfe decodes into a StateVersion, plus the committer
// Stackweaver records beside them, and the workspace, run and outputs relationships.
func (h *StateVersionHandlerV2) stateVersionResource(c *gin.Context, v *models.StateVersion) jsonapi.Resource[StateVersionAttributes] {
	status := v.Status
	if status == "" {
		status = "finalized"
	}
	rels := StateVersionRelationships{
		Workspace: jsonapi.ToOne(v.WorkspaceID, "workspaces"),
		Outputs:   jsonapi.ManyRelationship{Data: []jsonapi.ResourceID{}},
	}
	if v.RunID != nil && *v.RunID != "" {
		r := jsonapi.ToOne(*v.RunID, "runs")
		rels.Run = &r
	}
	for _, o := range materializedOutputs(h.stateOutputRepo, v, true, h.outputCrypto()) {
		rels.Outputs.Data = append(rels.Outputs.Data, jsonapi.ResourceID{ID: o.ID, Type: o.Type})
	}
	return jsonapi.Resource[StateVersionAttributes]{
		ID:   v.ID,
		Type: stateVersionsType,
		Attributes: StateVersionAttributes{
			HostedStateDownloadURL: h.hostedStateDownloadURL(c, v),
			Serial:                 v.Serial,
			Lineage:                v.Lineage,
			CreatedAt:              v.CreatedAt,
			Status:                 status,
			Size:                   v.Size,
			ResourcesProcessed:     v.ResourcesProcessed == nil || *v.ResourcesProcessed,
			StateVersion:           v.Version,
			VCSCommitSHA:           v.CommitHash,
			Committer:              v.Committer,
		},
		Relationships: rels,
	}
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
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	// Verify workspace exists and get project ID
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: state versions read
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "read")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view state versions")
		return
	}

	page, perPage := pagination.Parse(c, 20)
	if perPage > 100 {
		perPage = 100
	}
	offset := (page - 1) * perPage

	versions, total, err := h.stateVersionRepo.ListByWorkspace(workspaceID, perPage, offset)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list state versions")
		return
	}

	data := make([]jsonapi.Resource[StateVersionAttributes], 0, len(versions))
	for i := range versions {
		data = append(data, h.stateVersionResource(c, &versions[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, perPage, total))
}

// CurrentStateVersion returns the latest state version for a workspace (TFE-compatible).
// GET /api/v2/workspaces/:id/current-state-version
// Terraform remote backend uses this plus hosted-state-download-url to pull state; missing URL caused tfe_* drift.
func (h *StateVersionHandlerV2) CurrentStateVersion(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "read")
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view state version")
		return
	}

	version, err := h.stateVersionRepo.GetLatest(workspaceID)
	if err != nil || version == nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "No state version for this workspace")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, h.stateVersionResource(c, version))
}

// Get returns a single state version by ID (TFE-compatible)
// GET /api/v2/state-versions/:id
func (h *StateVersionHandlerV2) Get(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid state version ID")
		return
	}

	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "State version not found")
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: state versions read
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "read")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view state version")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, h.stateVersionResource(c, version))
}

// Download streams the raw state JSON for a state version (TFE hosted-state-download-url target).
// GET /api/v2/state-versions/:id/download
func (h *StateVersionHandlerV2) Download(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid state version ID")
		return
	}

	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "State version not found")
		return
	}

	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "read")
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to download state")
		return
	}

	var stateJSON []byte
	if h.stateService == nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "State storage unavailable")
		return
	}
	// Route through the state service so encrypted-at-rest state is decrypted to plain
	// JSON for Terraform (legacy plain JSON is tolerated transparently).
	stateJSON, err = h.stateService.GetStateObject(c.Request.Context(), version.WorkspaceID, version.Version)
	if err != nil {
		logger.Warnf("State version %s download: %v", id, err)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to load state")
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
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid state version ID")
		return
	}

	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "State version not found")
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: state versions read-outputs (allows reading outputs even if full state is restricted)
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "read-outputs")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view state version outputs")
		return
	}

	// TFE-compatible: mask sensitive values (return nil); see current-state-version-outputs.
	outputs := materializedOutputs(h.stateOutputRepo, version, true, h.outputCrypto())

	jsonapi.WriteDocument(c, http.StatusOK, outputs)
}

// CurrentStateVersionOutputs serves the outputs of a workspace's current (latest) state
// version from the materialized table (TFE current-state-version-outputs parity). Gated by
// the lower "read-outputs" permission so output values can be read without state-read access.
// GET /api/v2/workspaces/:id/current-state-version-outputs
func (h *StateVersionHandlerV2) CurrentStateVersionOutputs(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspace.ID, workspace.ProjectID, "read-outputs")
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view outputs")
		return
	}
	version, err := h.stateVersionRepo.GetLatest(workspace.ID)
	if err != nil || version == nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "No state version for this workspace")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, materializedOutputs(h.stateOutputRepo, version, true, h.outputCrypto()))
}

// CurrentStateVersionResources serves the resources of a workspace's current (latest) state
// version from the materialized table. Optional ?mode=managed|data filters; default all.
// Backs the workspace Resources and Data Sources tabs without parsing the raw state blob.
// GET /api/v2/workspaces/:id/current-state-version-resources
func (h *StateVersionHandlerV2) CurrentStateVersionResources(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	ok, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspace.ID, workspace.ProjectID, "read")
	if err != nil || !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view resources")
		return
	}
	version, err := h.stateVersionRepo.GetLatest(workspace.ID)
	if err != nil || version == nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "No state version for this workspace")
		return
	}
	mode := c.Query("mode")
	resources := []jsonapi.Resource[StateVersionResourceAttributes]{}
	if h.stateResourceRepo != nil {
		rows, listErr := h.stateResourceRepo.ListByStateVersion(version.ID, mode)
		if listErr != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list resources")
			return
		}
		resources = buildMaterializedResources(rows)
	}
	jsonapi.WriteDocument(c, http.StatusOK, resources)
}

// buildMaterializedResources renders state-version-resources JSON:API objects from rows.
func buildMaterializedResources(rows []models.StateVersionResource) []jsonapi.Resource[StateVersionResourceAttributes] {
	result := []jsonapi.Resource[StateVersionResourceAttributes]{}
	for _, r := range rows {
		result = append(result, jsonapi.Resource[StateVersionResourceAttributes]{
			ID:   r.ID,
			Type: "state-version-resources",
			Attributes: StateVersionResourceAttributes{
				Address:       r.Address,
				Mode:          r.Mode,
				Type:          r.Type,
				Name:          r.Name,
				Provider:      r.Provider,
				Module:        r.Module,
				InstanceCount: r.InstanceCount,
			},
		})
	}
	return result
}

// materializedOutputs returns TFE-compatible outputs for a state version, read from the
// materialized state_version_outputs table (State Storage Rework - the single source of truth).
// cryptoSvc decrypts sensitive output values stored encrypted at rest (#95); pass nil when
// encryption is disabled.
func materializedOutputs(repo *repository.StateVersionOutputRepository, version *models.StateVersion, maskSensitive bool, cryptoSvc *crypto.CryptoService) []jsonapi.Resource[StateVersionOutputAttributes] {
	if repo == nil || version == nil {
		return []jsonapi.Resource[StateVersionOutputAttributes]{}
	}
	outs, err := repo.ListByStateVersion(version.ID)
	if err != nil {
		return []jsonapi.Resource[StateVersionOutputAttributes]{}
	}
	return buildMaterializedOutputs(outs, maskSensitive, cryptoSvc)
}

// buildMaterializedOutputs renders TFE state-version-outputs JSON:API objects from the
// materialized rows. Value/Type are stored JSON-encoded, so they are decoded back into
// real JSON values for the response. Values encrypted at rest (#95, sensitive outputs)
// are decrypted with cryptoSvc first; if a value is encrypted and cannot be decrypted
// (no key) it is nulled so ciphertext never leaks. Sensitive values are nulled when
// maskSensitive.
func buildMaterializedOutputs(outs []models.StateVersionOutput, maskSensitive bool, cryptoSvc *crypto.CryptoService) []jsonapi.Resource[StateVersionOutputAttributes] {
	result := []jsonapi.Resource[StateVersionOutputAttributes]{}
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
		attrs := StateVersionOutputAttributes{Name: o.Name, Value: value, Sensitive: o.Sensitive}
		if o.Type != "" {
			var t any
			if err := json.Unmarshal([]byte(o.Type), &t); err == nil {
				attrs.Type = t
			}
		}
		result = append(result, jsonapi.Resource[StateVersionOutputAttributes]{
			ID:         o.ID,
			Type:       "state-version-outputs",
			Attributes: attrs,
		})
	}
	return result
}

// Create creates a new state version for a workspace (TFE-compatible)
// POST /api/v2/workspaces/:id/state-versions
func (h *StateVersionHandlerV2) Create(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	// Verify workspace exists
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: state versions write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "write")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to create state versions")
		return
	}

	var req CreateStateVersionRequestV2
	if !jsonapi.BindDocument(c, &req, stateVersionsType) {
		return
	}
	attrs := req.Data.Attributes
	runID, ok := jsonapi.RelationshipID(c, req.Data.Relationships.Run, "run", "runs")
	if !ok {
		return
	}
	if attrs.State == nil || *attrs.State == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "state is required: the state travels base64-encoded in the state attribute (the hosted-state-upload-url flow is not supported)")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(*attrs.State)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "state is not base64: "+err.Error())
		return
	}
	sum := md5.Sum(raw) //nolint:gosec // TFE's integrity check of the pushed state is an MD5, not a security boundary
	if !strings.EqualFold(hex.EncodeToString(sum[:]), *attrs.MD5) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "md5 does not match the state")
		return
	}
	var stateData map[string]interface{}
	if err := json.Unmarshal(raw, &stateData); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "state is not a JSON state document: "+err.Error())
		return
	}

	// TFE's rule (#858, D7): a state version is created only while the workspace is locked by the
	// caller, or its state is locked by the run the document names. That is why the CLI's remote
	// backend locks before it pushes. A lock held by anyone else, or no lock, refuses the push.
	var stateLock *models.StateLock
	if h.stateService != nil {
		if l, lockErr := h.stateService.GetStateLock(c.Request.Context(), workspaceID); lockErr == nil && l != nil && !l.IsExpired() {
			stateLock = l
		}
	}
	lockedByRun := runID != "" && stateLock != nil && stateLock.LockedBy != nil && *stateLock.LockedBy == runID
	lockedByCaller := workspace.Locked && workspace.LockedBy != nil && *workspace.LockedBy == user.ID
	switch {
	case stateLock != nil && !lockedByRun:
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", fmt.Sprintf("The state is locked by run %s; a state version is created only by the run that holds the lock", derefString(stateLock.LockedBy)))
		return
	case !lockedByCaller && !lockedByRun:
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Creating a state version requires the workspace to be locked by you, or its state to be locked by the run the document names. Lock the workspace first.")
		return
	}

	// AUD-018: atomically reserve the next version through the shared path (retry on the
	// unique-violation, reject a serial regression with 409), row-first then object storage.
	serial := int(*attrs.Serial)
	processed := true
	stateVersion := &models.StateVersion{
		WorkspaceID:        workspaceID,
		Serial:             &serial,
		MD5:                strings.ToLower(*attrs.MD5),
		Size:               int64(len(raw)),
		Status:             "finalized",
		ResourcesProcessed: &processed,
	}
	if attrs.Lineage != nil {
		stateVersion.Lineage = *attrs.Lineage
	}
	if runID != "" {
		stateVersion.RunID = &runID
	}
	nextVersion, err := h.stateVersionRepo.CreateNextVersion(stateVersion)
	if err != nil {
		if errors.Is(err, repository.ErrStateSerialRegression) {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "incoming state serial is older than the current state version")
			return
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create state version")
		return
	}

	// Store the state exactly as pushed (encrypted at rest by the state service), keyed on the
	// reserved version, so the md5 the client sent stays true of what is served back. On failure
	// roll back the reserved row so no dangling version remains.
	if h.stateService != nil {
		if err := h.stateService.PutStateObject(c.Request.Context(), workspaceID, nextVersion, raw); err != nil {
			_ = h.stateVersionRepo.Delete(stateVersion.ID)
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to store state in object storage: %v", err))
			return
		}
		// Materialize outputs/resources from the pushed state (State Storage Rework). The raw
		// state is already persisted authoritatively, so a failure is recorded, not returned.
		if err := h.stateService.Materialize(stateVersion.ID, stateData); err != nil {
			logger.Warnf("Failed to materialize outputs/resources for state version %s: %v", stateVersion.ID, err)
			processed = false
			_ = h.stateVersionRepo.SetResourcesProcessed(stateVersion.ID, false)
		}
	}

	stored, err := h.stateVersionRepo.GetByID(stateVersion.ID)
	if err != nil {
		stored = stateVersion
	}
	jsonapi.WriteDocument(c, http.StatusCreated, h.stateVersionResource(c, stored))
}

// derefString reads an optional identifier for a message.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// RemoveResource removes a resource from the latest state version by address
// POST /api/v2/workspaces/:id/state-versions/remove-resource
func (h *StateVersionHandlerV2) RemoveResource(c *gin.Context) {
	logger.Debugf("StateVersionHandlerV2 RemoveResource - Request received for workspace: %s", c.Param("id"))
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	// Verify workspace exists and get project ID
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: state versions write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "write")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to modify state")
		return
	}

	var body RemoveResourceRequest
	if !jsonapi.BindDocument(c, &body, stateVersionsType) {
		return
	}
	req := body.Data.Attributes

	// Remove resource from state
	if h.stateService == nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "State service not initialized")
		return
	}

	if err := h.stateService.RemoveResourceFromState(c.Request.Context(), workspaceID, req.Address); err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "not found") {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", err.Error())
			return
		}

		// Check if it's a "locked" error
		if strings.Contains(err.Error(), "locked") {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
			return
		}

		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	// Removing a resource writes a new state version; answer with it, read back as the latest
	// (RemoveResourceFromState saves it and returns only an error).
	latest, err := h.stateVersionRepo.GetLatest(workspaceID)
	if err != nil || latest == nil {
		apierror.Internal(c, "Failed to read the state version the removal wrote", err)
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, h.stateVersionResource(c, latest))
}

// Delete deletes a state version (StackWeaver-specific feature)
// DELETE /api/v2/state-versions/:id
func (h *StateVersionHandlerV2) Delete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid state version ID")
		return
	}

	// Get state version
	version, err := h.stateVersionRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "State version not found")
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(version.WorkspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: state versions write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckStateVersionPermission(c.Request.Context(), user.ID, version.WorkspaceID, workspace.ProjectID, "write")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to delete state version")
		return
	}

	// Delete state version
	if h.stateService == nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "State service not initialized")
		return
	}

	if err := h.stateService.DeleteStateVersion(c.Request.Context(), id); err != nil {
		// Check if it's a "locked" error
		if strings.Contains(err.Error(), "locked") {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
			return
		}

		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	// Return success (204 No Content)
	c.Status(http.StatusNoContent)
}
