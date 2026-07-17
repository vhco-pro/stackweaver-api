// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/runtask"
)

// isDuplicateKey detects a unique-constraint violation. gorm only translates to ErrDuplicatedKey
// when TranslateError is enabled (it is not here), so match the pg error text, like
// ansible/playbook_discovery.go does.
func isDuplicateKey(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLSTATE 23505") || strings.Contains(msg, "duplicate key value")
}

// RunTaskHandlerV2 serves organization run tasks (tfe_organization_run_task, JSON:API type "tasks"):
// external HTTP services that receive signed webhooks at run stage boundaries. The
// global-configuration attribute sub-object carries tfe_organization_run_task_global_settings,
// which has no endpoint of its own (the provider PATCHes /tasks/:id with only that object).
type RunTaskHandlerV2 struct {
	repo          *repository.RunTaskRepository
	wsTaskRepo    *repository.WorkspaceTaskRepository
	orgRepo       *repository.OrganizationRepository
	authService   *auth.Service
	rbacService   *rbac.Service
	cryptoService *crypto.CryptoService
	taskService   *runtask.Service
}

func NewRunTaskHandlerV2(
	repo *repository.RunTaskRepository,
	wsTaskRepo *repository.WorkspaceTaskRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	cryptoService *crypto.CryptoService,
	taskService *runtask.Service,
) *RunTaskHandlerV2 {
	return &RunTaskHandlerV2{
		repo:          repo,
		wsTaskRepo:    wsTaskRepo,
		orgRepo:       orgRepo,
		authService:   authService,
		rbacService:   rbacService,
		cryptoService: cryptoService,
		taskService:   taskService,
	}
}

func taskError(c *gin.Context, status int, title, detail string) {
	c.JSON(status, gin.H{"errors": []gin.H{{"status": strconv.Itoa(status), "title": title, "detail": detail}}})
}

// fullPaginationMeta is the complete TFE pagination meta block. go-tfe's Pagination struct reads all
// five fields, and the tfe_organization_run_task data source pages through List with them — the
// 3-field paginationMeta used elsewhere is not enough here (a nil next-page terminates its loop).
func fullPaginationMeta(page, pageSize int, total int64) gin.H {
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if totalPages < 1 {
		totalPages = 1
	}
	var prev, next interface{}
	if page > 1 {
		prev = page - 1
	}
	if page < totalPages {
		next = page + 1
	}
	return gin.H{"pagination": gin.H{
		"current-page": page,
		"page-size":    pageSize,
		"prev-page":    prev,
		"next-page":    next,
		"total-pages":  totalPages,
		"total-count":  total,
	}}
}

// runTaskAttributes is the JSON:API attribute set of a "tasks" document on write. Pointers
// distinguish absent from zero-valued: go-tfe's create serializes description even when null, and
// its update sends only changed fields.
type runTaskAttributes struct {
	Name        *string `json:"name"`
	URL         *string `json:"url"`
	Description *string `json:"description"`
	Category    *string `json:"category"`
	HMACKey     *string `json:"hmac-key"`
	Enabled     *bool   `json:"enabled"`
	Global      *struct {
		Enabled          *bool    `json:"enabled"`
		Stages           []string `json:"stages"`
		EnforcementLevel *string  `json:"enforcement-level"`
	} `json:"global-configuration"`
}

type runTaskRequest struct {
	Data struct {
		Type       string            `json:"type"`
		Attributes runTaskAttributes `json:"attributes"`
	} `json:"data"`
}

// formatRunTask renders a run task as JSON:API. hmac-key is write-only and never echoed;
// global-configuration is ALWAYS present with a boolean `enabled` — go-tfe only parses the
// sub-object when that key is a JSON bool, and tfe_organization_run_task_global_settings errors on
// a task without it.
func formatRunTask(t *models.RunTask, orgName string, workspaceTasks []models.WorkspaceTask) gin.H {
	stages := t.GlobalStages
	if stages == nil {
		stages = models.StringArray{}
	}
	wtRefs := make([]gin.H, 0, len(workspaceTasks))
	for i := range workspaceTasks {
		wtRefs = append(wtRefs, gin.H{"id": workspaceTasks[i].ID, "type": "workspace-tasks"})
	}
	return gin.H{
		"id":   t.ID,
		"type": "tasks",
		"attributes": gin.H{
			"name":        t.Name,
			"url":         t.URL,
			"description": t.Description,
			"category":    t.Category,
			"enabled":     t.Enabled,
			"global-configuration": gin.H{
				"enabled":           t.GlobalEnabled,
				"stages":            stages,
				"enforcement-level": t.GlobalEnforcementLevel,
			},
			"created-at": t.CreatedAt.Format(time.RFC3339),
			"updated-at": t.UpdatedAt.Format(time.RFC3339),
		},
		"relationships": gin.H{
			"organization":    gin.H{"data": gin.H{"id": orgName, "type": "organizations"}},
			"workspace-tasks": gin.H{"data": wtRefs},
		},
	}
}

func validTaskStages(stages []string) bool {
	seen := map[string]bool{}
	for _, s := range stages {
		switch s {
		case models.TaskStagePrePlan, models.TaskStagePostPlan, models.TaskStagePreApply, models.TaskStagePostApply:
		default:
			return false
		}
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func validEnforcementLevel(l string) bool {
	return l == models.TaskEnforcementAdvisory || l == models.TaskEnforcementMandatory
}

func validTaskURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// authOrg resolves an organization by name and checks run-task access: write requires the
// ManageRunTasks org bit or org:manage-workspaces (owners bypass via checkOrgPermission); read
// requires org membership.
func (h *RunTaskHandlerV2) authOrg(c *gin.Context, orgName string, write bool) (*models.Organization, bool) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		taskError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return nil, false
	}
	if write {
		if ok, err := h.rbacService.CheckOrgManageRunTasks(c.Request.Context(), user.ID, org.ID); err == nil && ok {
			return org, true
		}
		if ok, err := h.rbacService.CheckOrgManageWorkspaces(c.Request.Context(), user.ID, org.ID); err == nil && ok {
			return org, true
		}
		taskError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this organization's run tasks")
		return nil, false
	}
	inOrg, err := h.orgRepo.UserInOrg(user.ID, org.ID)
	if err != nil || !inOrg {
		taskError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return nil, false
	}
	return org, true
}

// loadForCaller loads a run task by id and authorizes the caller against its organization.
func (h *RunTaskHandlerV2) loadForCaller(c *gin.Context, write bool) (*models.RunTask, *models.Organization, bool) {
	t, err := h.repo.GetByID(c.Param("id"))
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Run task not found")
		return nil, nil, false
	}
	org, err := h.orgRepo.GetByID(t.OrganizationID)
	if err != nil {
		taskError(c, http.StatusNotFound, "Not Found", "Run task not found")
		return nil, nil, false
	}
	authedOrg, ok := h.authOrg(c, org.Name, write)
	if !ok {
		return nil, nil, false
	}
	return t, authedOrg, true
}

// Create handles POST /organizations/:name/tasks.
func (h *RunTaskHandlerV2) Create(c *gin.Context) {
	org, ok := h.authOrg(c, c.Param("name"), true)
	if !ok {
		return
	}
	var req runTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		taskError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	if a.Name == nil || *a.Name == "" {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "name is required")
		return
	}
	if a.URL == nil || !validTaskURL(*a.URL) {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "url is required and must be http(s)")
		return
	}
	if a.Category != nil && *a.Category != "task" {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "category must be \"task\"")
		return
	}

	t := &models.RunTask{
		OrganizationID: org.ID,
		Name:           *a.Name,
		URL:            *a.URL,
		Category:       "task",
		Enabled:        true,
	}
	if a.Description != nil {
		t.Description = *a.Description
	}
	if a.Enabled != nil {
		t.Enabled = *a.Enabled
	}
	plaintextKey := ""
	if a.HMACKey != nil {
		plaintextKey = *a.HMACKey
	}
	if g := a.Global; g != nil {
		if g.Enabled != nil {
			t.GlobalEnabled = *g.Enabled
		}
		if g.Stages != nil {
			if !validTaskStages(g.Stages) {
				taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "global-configuration stages must be unique values of pre_plan, post_plan, pre_apply, post_apply")
				return
			}
			t.GlobalStages = g.Stages
		}
		if g.EnforcementLevel != nil {
			if !validEnforcementLevel(*g.EnforcementLevel) {
				taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "global-configuration enforcement-level must be advisory or mandatory")
				return
			}
			t.GlobalEnforcementLevel = *g.EnforcementLevel
		}
	}

	// TFE validates the URL by POSTing a sentinel test-token payload and requiring a 2xx before the
	// task is created; we do the same (SSRF-guarded).
	if err := h.taskService.Handshake(c.Request.Context(), t.URL, plaintextKey, org.Name); err != nil {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute",
			"the run task URL did not respond successfully to the verification request: "+err.Error())
		return
	}

	if plaintextKey != "" {
		enc, err := h.cryptoService.Encrypt(plaintextKey)
		if err != nil {
			taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to store HMAC key")
			return
		}
		t.HMACKey = enc
	}

	if err := h.repo.Create(t); err != nil {
		if isDuplicateKey(err) {
			taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "a run task with this name already exists in the organization")
			return
		}
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create run task")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": formatRunTask(t, org.Name, nil)})
}

// List handles GET /organizations/:name/tasks.
func (h *RunTaskHandlerV2) List(c *gin.Context) {
	org, ok := h.authOrg(c, c.Param("name"), false)
	if !ok {
		return
	}
	page, pageSize, offset := paginate(c)
	tasks, total, err := h.repo.ListByOrganization(org.ID, pageSize, offset)
	if err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list run tasks")
		return
	}
	data := make([]gin.H, 0, len(tasks))
	for i := range tasks {
		wts, _ := h.wsTaskRepo.ListByTask(tasks[i].ID)
		data = append(data, formatRunTask(&tasks[i], org.Name, wts))
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": fullPaginationMeta(page, pageSize, total)})
}

// Read handles GET /tasks/:id (?include=workspace_tasks).
func (h *RunTaskHandlerV2) Read(c *gin.Context) {
	t, org, ok := h.loadForCaller(c, false)
	if !ok {
		return
	}
	wts, _ := h.wsTaskRepo.ListByTask(t.ID)
	resp := gin.H{"data": formatRunTask(t, org.Name, wts)}
	if c.Query("include") == "workspace_tasks" || c.Query("include") == "workspace_tasks.workspace" {
		included := make([]gin.H, 0, len(wts))
		for i := range wts {
			included = append(included, formatWorkspaceTask(&wts[i]))
		}
		resp["included"] = included
	}
	c.JSON(http.StatusOK, resp)
}

// Update handles PATCH /tasks/:id. All attributes are optional; hmac-key is written only when the
// request carries it (the provider sends it only when changed). A url or hmac-key change re-runs
// the verification handshake, as TFE does.
func (h *RunTaskHandlerV2) Update(c *gin.Context) {
	t, org, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	var req runTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		taskError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	if a.Category != nil && *a.Category != "task" {
		taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "category must be \"task\"")
		return
	}
	if a.Name != nil && *a.Name != "" {
		t.Name = *a.Name
	}
	urlChanged := a.URL != nil && *a.URL != t.URL
	if a.URL != nil {
		if !validTaskURL(*a.URL) {
			taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "url must be http(s)")
			return
		}
		t.URL = *a.URL
	}
	if a.Description != nil {
		t.Description = *a.Description
	}
	if a.Enabled != nil {
		t.Enabled = *a.Enabled
	}
	if g := a.Global; g != nil {
		if g.Enabled != nil {
			t.GlobalEnabled = *g.Enabled
		}
		if g.Stages != nil {
			if !validTaskStages(g.Stages) {
				taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "global-configuration stages must be unique values of pre_plan, post_plan, pre_apply, post_apply")
				return
			}
			t.GlobalStages = g.Stages
		}
		if g.EnforcementLevel != nil {
			if !validEnforcementLevel(*g.EnforcementLevel) {
				taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "global-configuration enforcement-level must be advisory or mandatory")
				return
			}
			t.GlobalEnforcementLevel = *g.EnforcementLevel
		}
	}

	// Resolve the plaintext key for the handshake: the new one when the request changes it, else
	// the stored one decrypted.
	keyChanged := a.HMACKey != nil
	plaintextKey := ""
	switch {
	case keyChanged:
		plaintextKey = *a.HMACKey
	case t.HMACKey != "":
		if dec, err := h.cryptoService.Decrypt(t.HMACKey); err == nil {
			plaintextKey = dec
		}
	}

	if urlChanged || keyChanged {
		if err := h.taskService.Handshake(c.Request.Context(), t.URL, plaintextKey, org.Name); err != nil {
			taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute",
				"the run task URL did not respond successfully to the verification request: "+err.Error())
			return
		}
	}
	if keyChanged {
		t.HMACKey = ""
		if plaintextKey != "" {
			enc, err := h.cryptoService.Encrypt(plaintextKey)
			if err != nil {
				taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to store HMAC key")
				return
			}
			t.HMACKey = enc
		}
	}

	if err := h.repo.Update(t); err != nil {
		if isDuplicateKey(err) {
			taskError(c, http.StatusUnprocessableEntity, "Invalid Attribute", "a run task with this name already exists in the organization")
			return
		}
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update run task")
		return
	}
	wts, _ := h.wsTaskRepo.ListByTask(t.ID)
	c.JSON(http.StatusOK, gin.H{"data": formatRunTask(t, org.Name, wts)})
}

// Delete handles DELETE /tasks/:id. Workspace attachments cascade; in-flight task results keep
// their snapshots (task pointer goes NULL).
func (h *RunTaskHandlerV2) Delete(c *gin.Context) {
	t, _, ok := h.loadForCaller(c, true)
	if !ok {
		return
	}
	if err := h.repo.Delete(t.ID); err != nil {
		taskError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete run task")
		return
	}
	c.Status(http.StatusNoContent)
}
