// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// The per-organization cache (#933, D7): verified public content a launcher's populator uploads
// and jobs read. Organizations never share a prefix, a job token reads only its own organization's
// entries, and no job token writes any.

// maxCacheEntryBytes bounds one uploaded entry. A provider package or a tofu release is tens of
// megabytes; a gigabyte is far above anything legitimate and still bounds a runaway upload.
const maxCacheEntryBytes int64 = 1 << 30

var cacheSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// cacheKey validates the kind and digest a cache route names, answering the request when they are
// not valid.
func cacheKey(c *gin.Context, kind, sum string) bool {
	if !runnercontract.CacheKind(kind).Valid() {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "no such cache kind")
		return false
	}
	if !cacheSHA256.MatchString(sum) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "a cache entry is addressed by its lowercase hex sha256")
		return false
	}
	return true
}

// getJobCacheBlob serves one entry of the job's organization's cache to its job, as the blob
// GET /runner/jobs/:id/blob/cache/:kind/:sha256. An entry the organization does not hold is
// refused (403) whether or not another organization holds it, so a job learns nothing of another
// organization's cache.
func (h *RunnerAgentHandler) getJobCacheBlob(c *gin.Context, rest string) {
	kind, sum, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(sum, "/") {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "No such blob")
		return
	}
	if !cacheKey(c, kind, sum) {
		return
	}
	org, ok := h.jobOrganization(c)
	if !ok {
		return
	}
	var entry models.CacheEntry
	err := h.db.Where("organization_id = ? AND kind = ? AND sha256 = ?", org, kind, sum).First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeRunnerForbidden(c, "the job's organization holds no such cache entry")
		return
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.serveCacheEntry(c, &entry)
}

// jobOrganization authorizes the caller for the job its route names and returns the job's
// organization: a run, an Ansible job or a work item, by the job token's kind (or the id's shape for
// an agent that predates the job token).
func (h *RunnerAgentHandler) jobOrganization(c *gin.Context) (uuid.UUID, bool) {
	id := c.Param("id")
	kind := models.JobTypeTofuRun
	if p, isJob := callingJob(c); isJob {
		kind = p.Kind
	} else if isWorkItem(id) {
		kind = models.JobTypeWorkItem
	} else if _, err := uuid.Parse(id); err == nil {
		kind = models.JobTypeAnsibleJob
	}
	switch kind {
	case models.JobTypeWorkItem:
		item, ok := h.loadWorkItem(c, id)
		if !ok || !h.authorizeRunnerForWorkItem(c, item, true) {
			return uuid.Nil, false
		}
		return item.OrganizationID, true
	case models.JobTypeAnsibleJob:
		jobID, err := uuid.Parse(id)
		if err != nil || h.ansibleJobRepo == nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
			return uuid.Nil, false
		}
		job, err := h.ansibleJobRepo.GetByID(jobID)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
			return uuid.Nil, false
		}
		if !h.authorizeRunnerForAnsibleJob(c, job, true) {
			return uuid.Nil, false
		}
		org, _, err := h.ansibleJobOrgAndPool(job)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return uuid.Nil, false
		}
		return org, true
	case models.JobTypeTofuRun:
		run, ok := h.loadRunForJob(c)
		if !ok {
			return uuid.Nil, false
		}
		org, _, err := h.runOrgAndPool(run)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return uuid.Nil, false
		}
		return org, true
	}
	jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
	return uuid.Nil, false
}

// serveCacheEntry streams an entry and records its use.
func (h *RunnerAgentHandler) serveCacheEntry(c *gin.Context, entry *models.CacheEntry) {
	if h.storageClient == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotImplemented, "Object storage not configured")
		return
	}
	body, err := h.storageClient.GetStream(c.Request.Context(), models.CacheObjectKey(entry.OrganizationID, entry.Kind, entry.SHA256))
	if err != nil {
		// The row outlived its object (a janitor mid-sweep): the reader falls back to its source.
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Cache entry not found")
		return
	}
	defer func() { _ = body.Close() }()
	if err := h.db.Model(&models.CacheEntry{}).Where("id = ?", entry.ID).Update("last_used_at", time.Now()).Error; err != nil {
		logger.Warnf("Failed to record the use of cache entry %s: %v", entry.ID, err)
	}
	c.DataFromReader(http.StatusOK, entry.SizeBytes, "application/octet-stream", body, nil)
}

// cacheOrganization resolves the organization a launcher's cache request is for: a customer
// launcher's own pool's organization (naming another is refused), or for a hosted launcher the
// organization it names, which must be one whose work it holds right now. An upload may instead
// name (promotion) a pending promotion of that organization handed to this launcher: its populator
// verifies what a job reported after the job has finished, when the launcher holds no work of it.
func (h *RunnerAgentHandler) cacheOrganization(c *gin.Context, promotion string) (uuid.UUID, bool) {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return uuid.Nil, false
	}
	raw := strings.TrimSpace(c.Query("organization"))
	if !runner.IsHosted() {
		own := runner.OrgID()
		if raw != "" && raw != own.String() {
			writeRunnerForbidden(c, "a launcher of an agent pool reaches its own organization's cache only")
			return uuid.Nil, false
		}
		return own, true
	}
	if raw == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "a hosted launcher names the organization of the cache it reaches")
		return uuid.Nil, false
	}
	org, err := uuid.Parse(raw)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "organization must be an organization id")
		return uuid.Nil, false
	}
	holds, err := h.hostedRunnerHolds(runner.ID, org)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return uuid.Nil, false
	}
	if !holds && promotion != "" {
		holds, err = h.hostedRunnerPromotes(promotion, runner.ID, org)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return uuid.Nil, false
		}
	}
	if !holds {
		writeRunnerForbidden(c, "this hosted launcher holds no work of that organization")
		return uuid.Nil, false
	}
	return org, true
}

// hostedRunnerPromotes reports whether the upload names a pending promotion of the organization
// that was handed to the runner.
func (h *RunnerAgentHandler) hostedRunnerPromotes(promotion string, runnerID, org uuid.UUID) (bool, error) {
	id, err := uuid.Parse(strings.TrimSpace(promotion))
	if err != nil {
		return false, nil
	}
	var n int64
	err = h.db.Model(&models.CachePromotion{}).
		Where("id = ? AND runner_id = ? AND organization_id = ? AND status = ?", id, runnerID, org, models.CachePromotionPending).
		Count(&n).Error
	return n > 0, err
}

// hostedRunnerHolds reports whether a hosted runner holds an unfinished run, Ansible job or work
// item of the organization.
func (h *RunnerAgentHandler) hostedRunnerHolds(runnerID, org uuid.UUID) (bool, error) {
	var n int64
	err := h.db.Model(&models.Run{}).
		Joins("JOIN workspaces ON workspaces.id = runs.workspace_id").
		Joins("JOIN projects ON projects.id = workspaces.project_id").
		Where("runs.runner_id = ? AND projects.organization_id = ? AND runs.status NOT IN ?", runnerID, org, finishedRunStatuses).
		Count(&n).Error
	if err != nil || n > 0 {
		return n > 0, err
	}
	err = h.db.Model(&models.AnsibleJob{}).
		Joins("JOIN projects ON projects.id = ansible_jobs.project_id").
		Where("ansible_jobs.runner_id = ? AND projects.organization_id = ? AND ansible_jobs.status NOT IN ?", runnerID, org, finishedAnsibleJobStatuses).
		Count(&n).Error
	if err != nil || n > 0 {
		return n > 0, err
	}
	err = h.db.Model(&models.WorkItem{}).
		Where("runner_id = ? AND organization_id = ? AND status NOT IN ?", runnerID, org, []string{models.WorkItemStatusCompleted, models.WorkItemStatusFailed, models.WorkItemStatusCanceled}).
		Count(&n).Error
	return n > 0, err
}

// GetCacheEntry serves an entry of an organization's cache to a launcher, which places it in its
// node-local read-through copy after verifying its sha256 (decision 19). Entries are verified public
// content, not job artifacts, so the runner token reaches them.
//
// GET /api/v2/runner/cache/:kind/:sha256
func (h *RunnerAgentHandler) GetCacheEntry(c *gin.Context) {
	kind, sum := c.Param("kind"), c.Param("sha256")
	if !cacheKey(c, kind, sum) {
		return
	}
	org, ok := h.cacheOrganization(c, "")
	if !ok {
		return
	}
	var entry models.CacheEntry
	err := h.db.Where("organization_id = ? AND kind = ? AND sha256 = ?", org, kind, sum).First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Cache entry not found")
		return
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.serveCacheEntry(c, &entry)
}

// PutCacheEntry stores an entry the launcher's populator verified against its source (#933, D7,
// AC34). The API re-hashes the body and refuses one that does not hash to its key, so a populator
// can place nothing under a digest it does not have; a job token never reaches this route.
//
// PUT /api/v2/runner/cache/:kind/:sha256?organization=&name=&version=&platform=&source=&verification=
func (h *RunnerAgentHandler) PutCacheEntry(c *gin.Context) {
	kind, sum := c.Param("kind"), c.Param("sha256")
	if !cacheKey(c, kind, sum) {
		return
	}
	verification := c.DefaultQuery("verification", models.CacheVerified)
	if verification != models.CacheVerified && verification != models.CacheVerifiedOffline {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "verification is verified or offline")
		return
	}
	org, ok := h.cacheOrganization(c, c.Query("promotion"))
	if !ok {
		return
	}
	if h.storageClient == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotImplemented, "Object storage not configured")
		return
	}

	var existing models.CacheEntry
	err := h.db.Where("organization_id = ? AND kind = ? AND sha256 = ?", org, kind, sum).First(&existing).Error
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(c.Request.Body, maxCacheEntryBytes))
		h.settlePromotion(c, org)
		c.Status(http.StatusOK)
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Spool to disk while hashing, so a large entry never sits in memory and nothing reaches the
	// store before its digest is known.
	spool, err := os.CreateTemp("", "cache-entry-*")
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	defer func() { _ = spool.Close(); _ = os.Remove(spool.Name()) }()
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(spool, hasher), io.LimitReader(c.Request.Body, maxCacheEntryBytes+1))
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "reading the entry")
		return
	}
	if size > maxCacheEntryBytes {
		jsonapi.WriteError(c, http.StatusRequestEntityTooLarge, "Request Entity Too Large", "a cache entry is at most 1 GiB")
		return
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != sum {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "the body's sha256 is "+got+", not the key it was uploaded under")
		return
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.storageClient.PutStream(c.Request.Context(), models.CacheObjectKey(org, kind, sum), spool, size); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	entry := &models.CacheEntry{
		OrganizationID: org, Kind: kind, SHA256: sum, SizeBytes: size, Verification: verification,
		Name: truncate(c.Query("name"), 500), Version: truncate(c.Query("version"), 200),
		Platform: truncate(c.Query("platform"), 50), SourceURL: c.Query("source"),
	}
	res := h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(entry)
	if res.Error != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.settlePromotion(c, org)
	if res.RowsAffected == 0 {
		c.Status(http.StatusOK)
		return
	}
	c.Status(http.StatusCreated)
}

// truncate cuts s to at most n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
