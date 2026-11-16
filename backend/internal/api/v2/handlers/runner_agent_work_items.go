// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"bytes"
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
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/security/gitargs"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/wakeup"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
		writeRunnerForbidden(c, "launcher identity required")
		return false
	}
	if !h.authorizePool(c, runner, item.OrganizationID, item.AgentPoolID, item.RunnerID, "work item") {
		return false
	}
	if item.RunnerID != nil && *item.RunnerID != runner.ID {
		writeRunnerForbidden(c, "work item is reserved by a different launcher")
		return false
	}
	if requireAssigned && (item.RunnerID == nil || *item.RunnerID != runner.ID) {
		writeRunnerForbidden(c, "work item is not reserved by this launcher")
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
		writeRunnerForbidden(c, "launcher identity required")
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
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Work item already claimed by another launcher")
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
		finished, finishErr := h.workItems.FinishedContext(c.Request.Context(), item, models.WorkItemStatusFailed, err.Error(), nil)
		if finishErr != nil {
			logger.Warnf("failing work item %s: %v", item.ID, finishErr)
		}
		if finished {
			h.revokeWorkItemAttempt(item)
		}
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
		clone, err := h.cloneSourceFor(ctx, func(scope *repository.OrganizationScope) (*models.VCSConnection, error) {
			return ansible.PlaybookVCSConnection(scope, playbook.ProjectID, *playbook.VCSConnectionID)
		}, playbook.VCSRepository, playbook.VCSBranch)
		if errors.Is(err, errCloneUnresolved) {
			return nil, errors.New("the playbook's VCS connection could not be resolved")
		}
		if err != nil {
			return nil, err
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
		clone, err := h.cloneSourceFor(ctx, func(scope *repository.OrganizationScope) (*models.VCSConnection, error) {
			return ansible.InventoryVCSConnection(scope, inventory.OrganizationID, *inventory.VCSConnectionID)
		}, inventory.VCSRepository, inventory.VCSBranch)
		if errors.Is(err, errCloneUnresolved) {
			return nil, errors.New("the inventory's VCS connection could not be resolved")
		}
		if err != nil {
			return nil, err
		}
		art.Clone, art.InventoryPath = clone, inventory.InventoryPath
		art.AzureSubscriptionID = h.orgAzureSubscription(item.OrganizationID)
	case models.WorkItemConfigurationSnapshot:
		if item.RunID == nil {
			return nil, errors.New("the work item names no run")
		}
		var run models.Run
		if err := h.db.WithContext(ctx).Preload("Workspace").First(&run, "id = ?", *item.RunID).Error; err != nil {
			return nil, fmt.Errorf("loading run: %w", err)
		}
		ws := run.Workspace
		if ws.VCSConnectionID == nil || ws.VCSRepository == "" {
			return nil, errors.New("the run's workspace has no VCS connection configured")
		}
		clone, err := h.cloneSourceFor(ctx, func(scope *repository.OrganizationScope) (*models.VCSConnection, error) {
			return scope.VCSConnectionForProject(*ws.VCSConnectionID, ws.ProjectID)
		}, ws.VCSRepository, ws.VCSBranch)
		if errors.Is(err, errCloneUnresolved) {
			return nil, errors.New("the workspace's VCS connection could not be resolved")
		}
		if err != nil {
			return nil, err
		}
		// The run's fetching configuration version says which commit to capture (#938): a
		// delivery's commit, or the branch head when it names none.
		if run.ConfigurationVersionID != nil {
			var cv models.ConfigurationVersion
			// A version that cannot be read is an error: serving no commit would capture the
			// branch head instead of the requested revision.
			if err := h.db.WithContext(ctx).Select("id", "commit_hash", "fetch_ref").First(&cv, "id = ?", *run.ConfigurationVersionID).Error; err != nil {
				return nil, fmt.Errorf("loading the run's configuration version: %w", err)
			}
			clone.Commit, clone.FetchRef = cv.CommitHash, cv.FetchRef
		}
		art.Clone = clone
	case models.WorkItemModuleTagSnapshot:
		if item.ModuleID == nil || item.RequestedRef == "" {
			return nil, errors.New("the work item names no module tag")
		}
		var module models.Module
		if err := h.db.WithContext(ctx).First(&module, "id = ?", *item.ModuleID).Error; err != nil {
			return nil, fmt.Errorf("loading module: %w", err)
		}
		if module.VCSConnectionID == nil || module.VCSRepository == "" {
			return nil, errors.New("the module has no VCS connection configured")
		}
		// The module's own connection, resolved within its organization, at the tag (#938).
		clone, err := h.cloneSourceFor(ctx, func(scope *repository.OrganizationScope) (*models.VCSConnection, error) {
			return scope.VCSConnection(*module.VCSConnectionID, module.OrganizationID)
		}, module.VCSRepository, item.RequestedRef)
		if errors.Is(err, errCloneUnresolved) {
			return nil, errors.New("the module's VCS connection could not be resolved")
		}
		if err != nil {
			return nil, err
		}
		// No unauthenticated clone: a connection that cannot mint a token fails the capture, as
		// AUD-130 requires of every clone.
		if clone.Token == "" && clone.SSHPrivateKey == "" {
			return nil, errors.New("the module's VCS connection could not mint a token")
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
func (h *RunnerAgentHandler) cloneSourceFor(ctx context.Context, lookup func(*repository.OrganizationScope) (*models.VCSConnection, error), repo, branch string) (*runnercontract.CloneSource, error) {
	if h.vcsRegistry == nil {
		return nil, errCloneUnresolved
	}
	conn, err := lookup(repository.NewOrganizationScope(h.db).WithContext(ctx))
	if err != nil {
		if !errors.Is(err, ansible.ErrInvalidInput) {
			logger.Warnf("loading the VCS connection for %s failed: %v", repo, err)
		}
		return nil, errCloneUnresolved
	}
	provider, err := h.vcsRegistry.GetProvider(conn)
	if err != nil {
		return nil, errCloneUnresolved
	}
	// No unauthenticated clone of a connected repository (AUD-130, #938): a connection that
	// cannot mint its token fails the work item with the provider's reason.
	token, err := provider.GetFreshToken(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("the VCS connection could not mint a token: %w", err)
	}
	if branch == "" {
		branch = "main"
	}
	return cloneSourceFromURL(provider.BuildCloneURL(conn, token, repo), branch), nil
}

// errCloneUnresolved is cloneSourceFor's answer when the target's connection does not resolve
// within its organization; each work item kind reports it in its own words.
var errCloneUnresolved = errors.New("the VCS connection could not be resolved")

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
	if h.beforeWorkItemFinish != nil {
		h.beforeWorkItemFinish(item.ID)
	}
	finished, err := h.workItems.FinishedContext(c.Request.Context(), item, status, req.ErrorMessage, req.WorkResult)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !finished {
		// Finished already, or reclaimed since this request was authorized: the completion
		// changed nothing, and the current attempt's credentials are left alone.
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the work item was finished or reclaimed")
		return
	}
	h.revokeWorkItemAttempt(item)
	h.wakeCallersPool(c)
	response.Status(c, http.StatusOK, "completed")
}

// revokeWorkItemAttempt revokes the job tokens of the attempt of item the request was authorized
// for, never a later attempt's.
func (h *RunnerAgentHandler) revokeWorkItemAttempt(item *models.WorkItem) {
	if h.apiKeyService == nil {
		return
	}
	if err := h.apiKeyService.RevokeJobAttemptTokens(models.JobTypeWorkItem, item.ID, max(item.Attempt, 1)); err != nil {
		logger.Warnf("revoking the job tokens of work item %s attempt %d: %v", item.ID, item.Attempt, err)
	}
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
	if h.snapshotAuthorized != nil {
		h.snapshotAuthorized(item.ID)
	}
	snapshotOfPlaybook := item.Kind == models.WorkItemPlaybookSnapshot && item.PlaybookID != nil
	snapshotOfRun := item.Kind == models.WorkItemConfigurationSnapshot && item.RunID != nil
	snapshotOfModule := item.Kind == models.WorkItemModuleTagSnapshot && item.ModuleID != nil
	if !snapshotOfPlaybook && !snapshotOfRun && !snapshotOfModule {
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
	if snapshotOfModule {
		h.publishModuleSnapshot(c, item, commit, data)
		return
	}
	if snapshotOfRun {
		// The commit is recorded with the accepted upload, never by a refused one.
		h.storeRunConfiguration(c, item, commit, data)
		return
	}
	if commit != "" {
		if err := h.workItems.Items().SetCommit(id, commit); err != nil {
			logger.Warnf("recording the snapshot commit of work item %s: %v", id, err)
		}
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

// publishModuleSnapshot publishes the module version a module_tag_snapshot captured (#938). The
// commit is recorded on the work item only once the version is published, which is what its
// completion checks. A version that exists, whether an alias tag's capture or a manual upload
// published it first, answers 409 and publishes nothing.
func (h *RunnerAgentHandler) publishModuleSnapshot(c *gin.Context, item *models.WorkItem, commit string, data []byte) {
	if h.modulePublisher == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusServiceUnavailable, "Module publishing is not configured")
		return
	}
	if gitargs.CommitSHARe.FindString(commit) == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "the snapshot names no commit")
		return
	}
	// Publication holds the work item's row in its own transaction, before it writes storage, so a
	// cancellation or reclaim that lands while this request is in flight waits for it and one that
	// landed first is seen: a capture that lost its authority publishes neither a version nor an
	// archive. The commit, the completion's proof, is recorded in that transaction too, so a
	// version exists exactly when its proof does.
	conflict := ""
	version, err := h.modulePublisher.PublishCapturedVersion(c.Request.Context(), *item.ModuleID, item.RequestedRef, commit, bytes.NewReader(data),
		func(tx *gorm.DB) error {
			var locked models.WorkItem
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "status", "runner_id", "attempt").First(&locked, "id = ?", item.ID).Error; err != nil {
				return err
			}
			if conflict = heldConflict(&locked, item); conflict != "" {
				return errCaptureNotHeld
			}
			return tx.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("commit", commit).Error
		})
	switch {
	case conflict != "":
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", conflict)
		return
	case errors.Is(err, registry.ErrVersionExists):
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
		return
	case err != nil:
		logger.Errorf("publishing the capture of work item %s: %v", item.ID, err)
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	logger.Infof("Published version %s of module %s from capture %s", version.Version, *item.ModuleID, item.ID)
	response.Status(c, http.StatusOK, "published")
}

// errCaptureNotHeld ends a capture's write when its work item no longer belongs to the request.
var errCaptureNotHeld = errors.New("the capture no longer holds its work item")

// heldConflict says why a work item, read under its row lock, no longer belongs to the request
// authorized for it as authorized, or "" when it still does: it is running, held by the same
// runner in the same attempt (#938). The attempt can advance between authorization and the lock.
func heldConflict(locked, authorized *models.WorkItem) string {
	if locked.Status != models.WorkItemStatusRunning {
		return "the work item has finished"
	}
	sameRunner := (locked.RunnerID == nil) == (authorized.RunnerID == nil) &&
		(locked.RunnerID == nil || *locked.RunnerID == *authorized.RunnerID)
	if !sameRunner || max(locked.Attempt, 1) != max(authorized.Attempt, 1) {
		return "a later attempt of this work item exists"
	}
	return ""
}

// storeRunConfiguration makes a configuration_snapshot's upload the configuration of its run
// (#933, decision 18; #938). One transaction holds the work item, checked to be the running attempt
// the request was authorized for, and then the run's row, so the orchestrator's conversion of a run
// without a version, which attaches through that row, serializes with the upload. It fills the
// version the run holds at that moment: a fetching one, once, at its requested commit; for a run
// that still has none, a new version created and attached here. An uploaded version never changes
// again, and a capture canceled or reclaimed meanwhile changes nothing. The run's pool is woken
// once its configuration is uploaded.
func (h *RunnerAgentHandler) storeRunConfiguration(c *gin.Context, item *models.WorkItem, commit string, data []byte) {
	var run models.Run
	conflict, notFound := "", false
	// The transaction, its row-lock waits included, follows the request: an upload whose request
	// ends stops waiting and changes nothing.
	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		var locked models.WorkItem
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "status", "runner_id", "attempt").First(&locked, "id = ?", item.ID).Error; err != nil {
			return err
		}
		if conflict = heldConflict(&locked, item); conflict != "" {
			return nil
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "workspace_id", "agent_pool_id", "configuration_version_id", "operation").
			First(&run, "id = ?", *item.RunID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				notFound = true
				return nil
			}
			return err
		}
		var cvID string
		if run.ConfigurationVersionID == nil {
			// A run converted by no orchestrator yet, while an older one requested its capture
			// during a rolling deploy: the capture makes its version, as before #938, attached
			// under the run's lock.
			cv := &models.ConfigurationVersion{
				WorkspaceID: run.WorkspaceID, Status: models.ConfigurationVersionStatusFetching, Source: "tfe-vcs",
				Speculative: run.Operation == models.RunOperationPlanOnly,
			}
			if err := tx.Create(cv).Error; err != nil {
				return fmt.Errorf("creating the configuration version of run %s: %w", run.ID, err)
			}
			res := tx.Model(&models.Run{}).Where("id = ? AND configuration_version_id IS NULL", run.ID).Update("configuration_version_id", cv.ID)
			if res.Error != nil {
				return fmt.Errorf("attaching the configuration version of run %s: %w", run.ID, res.Error)
			}
			if res.RowsAffected != 1 {
				return fmt.Errorf("run %s was given a configuration version while its row was held", run.ID)
			}
			cvID = cv.ID
		} else {
			cvID = *run.ConfigurationVersionID
		}
		var cv models.ConfigurationVersion
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&cv, "id = ?", cvID).Error; err != nil {
			return err
		}
		switch {
		case cv.Status != models.ConfigurationVersionStatusFetching:
			conflict = "the configuration was already captured"
			return nil
		case cv.CommitHash != "" && commit != cv.CommitHash:
			conflict = "the snapshot is not of the requested commit"
			return nil
		}
		// Object storage is outside this transaction: a canceled write can still land after the
		// rollback. Each upload therefore writes its own object, recorded below with the status, so
		// a late write lands where nothing reads (R-48, R-49).
		key := models.ConfigurationCaptureKey(cv.ID, uuid.NewString())
		if err := h.storageClient.Put(c.Request.Context(), key, data); err != nil {
			return fmt.Errorf("storing the configuration of run %s: %w", run.ID, err)
		}
		updates := map[string]any{"status": models.ConfigurationVersionStatusUploaded, "archive_key": key}
		if cv.CommitHash == "" && commit != "" {
			updates["commit_hash"] = commit
		}
		res := tx.Model(&models.ConfigurationVersion{}).Where("id = ? AND status = ?", cv.ID, models.ConfigurationVersionStatusFetching).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return fmt.Errorf("configuration version %s left fetching while it was held", cv.ID)
		}
		if commit == "" {
			return nil
		}
		return tx.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("commit", commit).Error
	})
	switch {
	case err != nil:
		logger.Errorf("storing the configuration of run %s: %v", *item.RunID, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	case notFound:
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
		return
	case conflict != "":
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", conflict)
		return
	}
	h.wakeRunPool(c, &run)
	response.Status(c, http.StatusOK, "stored")
}

// wakeRunPool wakes the launchers of the run's pool, now that its configuration is uploaded.
func (h *RunnerAgentHandler) wakeRunPool(c *gin.Context, run *models.Run) {
	if run.AgentPoolID == nil {
		return
	}
	var pool models.AgentPool
	hosted := h.db.WithContext(c.Request.Context()).Select("id", "kind").First(&pool, "id = ?", *run.AgentPoolID).Error == nil && pool.IsHosted()
	wakeup.Publish(c.Request.Context(), h.wakeRedis, wakeup.KeyForPool(run.AgentPoolID.String(), hosted))
}
