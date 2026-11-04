// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/wakeup"
	"gorm.io/gorm"
)

// The runner control plane of work items (#933, D2, decision 18): a sync is offered, claimed,
// given a job token, fed its artifacts, streams output and completes like a run or a job. Its id
// carries the wi- prefix, which is how every runner route tells it from a run and a job.

// SetWorkItems wires the work items' runtime; without it no work item is offered.
func (h *RunnerAgentHandler) SetWorkItems(rt *ansible.WorkItemRuntime) { h.workItems = rt }

// isWorkItem reports whether a runner route's job id names a work item.
func isWorkItem(id string) bool { return strings.HasPrefix(id, runnercontract.WorkItemPrefix) }

// loadWorkItem reads the work item a runner route names, answering the request when it cannot.
func (h *RunnerAgentHandler) loadWorkItem(c *gin.Context, id string) (*models.WorkItem, bool) {
	if h.workItems == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Work item not found")
		return nil, false
	}
	item, err := h.workItems.Items().GetByID(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Work item not found")
		return nil, false
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return item, true
}

// authorizeRunnerForWorkItem binds a work item to the calling runner as authorizeRunnerForRun
// binds a run: its organization and pool, its reservation, and a job token's job and attempt.
func (h *RunnerAgentHandler) authorizeRunnerForWorkItem(c *gin.Context, item *models.WorkItem, requireAssigned bool) bool {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "runner identity required")
		return false
	}
	if !h.authorizePool(c, runner, item.OrganizationID, item.AgentPoolID, item.RunnerID, "work item") {
		return false
	}
	if item.RunnerID != nil && *item.RunnerID != runner.ID {
		writeRunnerForbidden(c, "work item is reserved by a different runner")
		return false
	}
	if requireAssigned && (item.RunnerID == nil || *item.RunnerID != runner.ID) {
		writeRunnerForbidden(c, "work item is not reserved by this runner")
		return false
	}
	if p, ok := callingJob(c); ok {
		return authorizeJobPrincipal(c, p, models.JobTypeWorkItem, item.ID, item.RunnerID, item.Attempt, item.Finished())
	}
	return true
}

// workItemOffer is the offer of one work item.
func workItemOffer(item *models.WorkItem) PendingJob {
	return PendingJob{JobID: item.ID, JobType: runnercontract.JobTypeWorkItem, RunType: item.Kind}
}

// offersWorkItems reports whether a runner is offered work items: it declared it runs them.
func (h *RunnerAgentHandler) offersWorkItems(runner *models.Runner) bool {
	return h.workItems != nil && runner.HasCapability(runnercontract.CapabilityWorkItems)
}

// jobStartWorkItem claims a work item for the calling runner, a new attempt, and marks its target
// syncing.
func (h *RunnerAgentHandler) jobStartWorkItem(c *gin.Context, id string, placement *runnercontract.Placement) {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "runner identity required")
		return
	}
	item, ok := h.loadWorkItem(c, id)
	if !ok || !h.authorizeRunnerForWorkItem(c, item, false) {
		return
	}
	claimed, err := h.workItems.Items().ClaimForRunner(id, runner.ID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !claimed {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Work item already claimed by another runner")
		return
	}
	h.revokeJobTokens(models.JobTypeWorkItem, id)
	h.recordPlacement(models.JobTypeWorkItem, id, placement)
	if err := h.workItems.Started(item); err != nil {
		logger.Warnf("marking the target of work item %s syncing: %v", id, err)
	}
	response.Status(c, http.StatusOK, "started")
}

// workItemTokenFields is what the job token of a work item is minted from.
func (h *RunnerAgentHandler) workItemTokenFields(c *gin.Context, id string) (item *models.WorkItem, ok bool) {
	item, ok = h.loadWorkItem(c, id)
	if !ok || !h.authorizeRunnerForWorkItem(c, item, true) {
		return nil, false
	}
	if item.Finished() {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the work item has finished")
		return nil, false
	}
	return item, true
}

// getWorkItemArtifacts serves a work item's artifacts to the executor holding its job token.
func (h *RunnerAgentHandler) getWorkItemArtifacts(c *gin.Context, id string) {
	item, ok := h.loadWorkItem(c, id)
	if !ok || !h.authorizeRunnerForWorkItem(c, item, true) {
		return
	}
	if item.Finished() {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the work item has finished")
		return
	}
	art, err := h.workItemArtifacts(c.Request.Context(), item)
	if err != nil {
		// Nothing a later attempt could fix: the work item fails with the reason, and the runner
		// is told so.
		if _, finishErr := h.workItems.Finished(item, models.WorkItemStatusFailed, err.Error(), nil); finishErr != nil {
			logger.Warnf("failing work item %s: %v", item.ID, finishErr)
		}
		h.revokeJobTokens(models.JobTypeWorkItem, item.ID)
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
		return
	}
	c.JSON(http.StatusOK, art)
}

// workItemArtifacts builds what the sync executor needs for a work item.
func (h *RunnerAgentHandler) workItemArtifacts(ctx context.Context, item *models.WorkItem) (*runnercontract.WorkItemArtifacts, error) {
	art := &runnercontract.WorkItemArtifacts{
		ContractVersion: runnercontract.Version, JobID: item.ID, Kind: item.Kind, Mirror: h.mirror, TimeoutSeconds: item.TimeoutSeconds,
	}
	switch item.Kind {
	case models.WorkItemPlaybookSnapshot:
		playbook, err := h.playbookRepo.GetByID(*item.PlaybookID)
		if err != nil {
			return nil, fmt.Errorf("loading playbook: %w", err)
		}
		if playbook.VCSConnectionID == nil || playbook.VCSRepository == "" {
			return nil, errors.New("playbook has no VCS connection configured")
		}
		clone := h.cloneSourceFor(ctx, func(scope *repository.OrganizationScope) (*models.VCSConnection, error) {
			return ansible.PlaybookVCSConnection(scope, playbook.ProjectID, *playbook.VCSConnectionID)
		}, playbook.VCSRepository, playbook.VCSBranch)
		if clone == nil {
			return nil, errors.New("the playbook's VCS connection could not be resolved")
		}
		art.Clone, art.PlaybookPath = clone, playbook.PlaybookPath
	case models.WorkItemInventoryFileSync:
		inventory, err := h.inventoryRepo.GetByID(*item.InventoryID)
		if err != nil {
			return nil, fmt.Errorf("loading inventory: %w", err)
		}
		if inventory.VCSConnectionID == nil || inventory.VCSRepository == "" || inventory.InventoryPath == "" {
			return nil, errors.New("inventory has no VCS connection configured")
		}
		clone := h.cloneSourceFor(ctx, func(scope *repository.OrganizationScope) (*models.VCSConnection, error) {
			return ansible.InventoryVCSConnection(scope, inventory.OrganizationID, *inventory.VCSConnectionID)
		}, inventory.VCSRepository, inventory.VCSBranch)
		if clone == nil {
			return nil, errors.New("the inventory's VCS connection could not be resolved")
		}
		art.Clone, art.InventoryPath = clone, inventory.InventoryPath
		art.AzureSubscriptionID = h.orgAzureSubscription(item.OrganizationID)
	case models.WorkItemConfigurationSnapshot:
		if item.RunID == nil {
			return nil, errors.New("the work item names no run")
		}
		var run models.Run
		if err := h.db.Preload("Workspace").First(&run, "id = ?", *item.RunID).Error; err != nil {
			return nil, fmt.Errorf("loading run: %w", err)
		}
		ws := run.Workspace
		if ws.VCSConnectionID == nil || ws.VCSRepository == "" {
			return nil, errors.New("the run's workspace has no VCS connection configured")
		}
		clone := h.cloneSourceFor(ctx, func(scope *repository.OrganizationScope) (*models.VCSConnection, error) {
			return scope.VCSConnectionForProject(*ws.VCSConnectionID, ws.ProjectID)
		}, ws.VCSRepository, ws.VCSBranch)
		if clone == nil {
			return nil, errors.New("the workspace's VCS connection could not be resolved")
		}
		art.Clone = clone
	case models.WorkItemConstructedRebuild, models.WorkItemDynamicSourceSync:
		cmd, err := h.workItems.Command(item)
		if err != nil {
			return nil, err
		}
		art.Inventory = cmd
	default:
		return nil, fmt.Errorf("work item kind %q is not served by this API", item.Kind)
	}
	return art, nil
}

// cloneSourceFor resolves a repository's clone through the connection lookup names, within the
// target's organization: a target naming another organization's connection resolves to nothing.
// The minted token travels beside the URL, never inside it, so the executor can hand it to git
// without putting it in an argument or a file (decision 18).
func (h *RunnerAgentHandler) cloneSourceFor(ctx context.Context, lookup func(*repository.OrganizationScope) (*models.VCSConnection, error), repo, branch string) *runnercontract.CloneSource {
	if h.vcsRegistry == nil {
		return nil
	}
	conn, err := lookup(repository.NewOrganizationScope(h.db).WithContext(ctx))
	if err != nil {
		if !errors.Is(err, ansible.ErrInvalidInput) {
			logger.Warnf("loading the VCS connection for %s failed: %v", repo, err)
		}
		return nil
	}
	provider, err := h.vcsRegistry.GetProvider(conn)
	if err != nil {
		return nil
	}
	token, _ := provider.GetFreshToken(ctx, conn)
	if branch == "" {
		branch = "main"
	}
	return cloneSourceFromURL(provider.BuildCloneURL(conn, token, repo), branch)
}

// cloneSourceFromURL splits a credential-embedded clone URL into the bare URL and its credential.
func cloneSourceFromURL(raw, branch string) *runnercontract.CloneSource {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	src := &runnercontract.CloneSource{Branch: branch}
	if u.User != nil {
		src.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			src.Token = pw
		} else {
			// A bare token as the user part: git sends it as the password.
			src.Token, src.Username = src.Username, "x-access-token"
		}
		u.User = nil
	}
	src.URL = u.String()
	return src
}

// orgAzureSubscription is the organization's Azure subscription, the fallback of a VCS inventory
// file that names none.
func (h *RunnerAgentHandler) orgAzureSubscription(orgID uuid.UUID) string {
	if h.azureOIDCRepo == nil {
		return ""
	}
	configs, err := h.azureOIDCRepo.GetByOrganization(orgID)
	if err != nil || len(configs) == 0 {
		return ""
	}
	return strings.TrimSpace(configs[0].SubscriptionID)
}

// jobOutputWorkItem appends a chunk of a work item's output to its record and sync history.
func (h *RunnerAgentHandler) jobOutputWorkItem(c *gin.Context, id string, req JobOutputRequest) {
	item, ok := h.loadWorkItem(c, id)
	if !ok || !h.authorizeRunnerForWorkItem(c, item, true) {
		return
	}
	h.recordPlacement(models.JobTypeWorkItem, id, req.Placement)
	if req.Output != "" {
		if err := h.workItems.AppendOutput(item, req.Output); err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	response.Status(c, http.StatusOK, "ok")
}

// jobCompleteWorkItem ends a work item with what its executor reported.
func (h *RunnerAgentHandler) jobCompleteWorkItem(c *gin.Context, id string, req JobCompleteRequest) {
	item, ok := h.loadWorkItem(c, id)
	if !ok || !h.authorizeRunnerForWorkItem(c, item, true) {
		return
	}
	status := models.WorkItemStatusFailed
	switch req.Status {
	case "completed", "successful":
		status = models.WorkItemStatusCompleted
	case "canceled":
		status = models.WorkItemStatusCanceled
	}
	if _, err := h.workItems.Finished(item, status, req.ErrorMessage, req.WorkResult); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.revokeJobTokens(models.JobTypeWorkItem, id)
	h.wakeCallersPool(c)
	response.Status(c, http.StatusOK, "completed")
}

// workItemStatus answers a work item's status poll.
func (h *RunnerAgentHandler) workItemStatus(c *gin.Context, id string) {
	item, ok := h.loadWorkItem(c, id)
	if !ok || !h.authorizeRunnerForWorkItem(c, item, false) {
		return
	}
	response.Status(c, http.StatusOK, item.Status)
}

// maxSnapshotBytes bounds one snapshot upload.
const maxSnapshotBytes = 512 << 20

// UploadSnapshot stores the snapshot a playbook_snapshot work item captured (#933, D2, decision
// 18): the body is the tarball, the commit it was captured at is in HeaderSnapshotCommit, and the
// object is sealed at rest by the storage client.
// POST /api/v2/runner/jobs/:id/snapshot
func (h *RunnerAgentHandler) UploadSnapshot(c *gin.Context) {
	id := c.Param("id")
	if !isWorkItem(id) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "only a work item uploads a snapshot")
		return
	}
	item, ok := h.loadWorkItem(c, id)
	if !ok || !h.authorizeRunnerForWorkItem(c, item, true) {
		return
	}
	if item.Finished() {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the work item has finished")
		return
	}
	snapshotOfPlaybook := item.Kind == models.WorkItemPlaybookSnapshot && item.PlaybookID != nil
	snapshotOfRun := item.Kind == models.WorkItemConfigurationSnapshot && item.RunID != nil
	if !snapshotOfPlaybook && !snapshotOfRun {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "this work item captures no snapshot")
		return
	}
	if h.storageClient == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusServiceUnavailable, "Object storage is not configured")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxSnapshotBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jsonapi.WriteError(c, http.StatusRequestEntityTooLarge, "Request Entity Too Large", "the snapshot exceeds the size limit")
			return
		}
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "reading the snapshot failed")
		return
	}
	if len(data) == 0 {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "the snapshot is empty")
		return
	}
	commit := strings.TrimSpace(c.GetHeader(runnercontract.HeaderSnapshotCommit))
	if commit != "" {
		if err := h.workItems.Items().SetCommit(id, commit); err != nil {
			logger.Warnf("recording the snapshot commit of work item %s: %v", id, err)
		}
	}
	if snapshotOfRun {
		h.storeRunConfiguration(c, item, commit, data)
		return
	}
	// A playbook deleted while its snapshot was captured stays gone: its delete pruned this prefix.
	var kept int64
	if err := h.db.Model(&models.AnsiblePlaybook{}).Where("id = ?", *item.PlaybookID).Count(&kept).Error; err != nil {
		logger.Errorf("reading the playbook of work item %s: %v", id, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if kept == 0 {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Playbook not found")
		return
	}
	if err := h.storageClient.Put(c.Request.Context(), ansible.PlaybookSnapshotKey(*item.PlaybookID), data); err != nil {
		logger.Errorf("storing the snapshot of work item %s: %v", id, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.db.Model(&models.AnsiblePlaybook{}).Where("id = ?", *item.PlaybookID).Update("cached_size_bytes", len(data)).Error; err != nil {
		logger.Warnf("recording the snapshot size of playbook %s: %v", *item.PlaybookID, err)
	}
	response.Status(c, http.StatusOK, "stored")
}

// storeRunConfiguration makes a configuration_snapshot's upload the configuration version of its
// run (#933, decision 18): a version of the run's workspace, sourced from VCS at the commit, stored
// sealed where every configuration tarball is, and set on the run if it still has none; the run's
// pool is then woken, because the run is now offerable.
func (h *RunnerAgentHandler) storeRunConfiguration(c *gin.Context, item *models.WorkItem, commit string, data []byte) {
	var run models.Run
	if err := h.db.Select("id", "workspace_id", "agent_pool_id", "configuration_version_id").First(&run, "id = ?", *item.RunID).Error; err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
		return
	}
	cv := &models.ConfigurationVersion{WorkspaceID: run.WorkspaceID, Status: models.ConfigurationVersionStatusPending, Source: "tfe-vcs", CommitHash: commit}
	cvRepo := repository.NewConfigurationVersionRepository(h.db)
	if err := cvRepo.Create(cv); err != nil {
		logger.Errorf("creating the configuration version of run %s: %v", run.ID, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.storageClient.Put(c.Request.Context(), models.ConfigurationTarballKey(cv.ID), data); err != nil {
		logger.Errorf("storing the configuration of run %s: %v", run.ID, err)
		cv.Status, cv.ErrorMessage = models.ConfigurationVersionStatusErrored, "storing the snapshot failed"
		_ = cvRepo.Update(cv)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	cv.Status = models.ConfigurationVersionStatusUploaded
	if err := cvRepo.Update(cv); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.db.Model(&models.Run{}).Where("id = ? AND configuration_version_id IS NULL", run.ID).Update("configuration_version_id", cv.ID).Error; err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if run.AgentPoolID != nil {
		var pool models.AgentPool
		hosted := h.db.Select("id", "kind").First(&pool, "id = ?", *run.AgentPoolID).Error == nil && pool.IsHosted()
		wakeup.Publish(c.Request.Context(), h.wakeRedis, wakeup.KeyForPool(run.AgentPoolID.String(), hosted))
	}
	response.Status(c, http.StatusOK, "stored")
}
