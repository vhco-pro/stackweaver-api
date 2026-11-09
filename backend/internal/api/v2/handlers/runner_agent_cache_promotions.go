// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

// Cache promotion (#933, D7): what a successful job reports installing beyond its descriptor is
// handed to the runner that ran it, whose populator fetches each entry again from its source,
// verifies it and uploads it, or drops it. Nothing a job reports is stored as content.

// maxManifestEntries bounds what one job may report.
const maxManifestEntries = 200

// promotionsPerHeartbeat bounds how many promotions one heartbeat hands out.
const promotionsPerHeartbeat = 20

// promotionTTL is how long a promotion waits for its runner before it is no longer handed out.
const promotionTTL = 24 * time.Hour

// recordCachePromotions stores the manifest of a successful job as pending promotions for the
// runner that ran it, leaving out what the organization's cache already holds.
func (h *RunnerAgentHandler) recordCachePromotions(c *gin.Context, kind models.JobType, jobID string, org uuid.UUID, pool *uuid.UUID, m *runnercontract.CacheManifest) {
	runner, ok := callingRunner(c)
	if !ok || m == nil || len(m.Entries) == 0 {
		return
	}
	entries := m.Entries
	if len(entries) > maxManifestEntries {
		entries = entries[:maxManifestEntries]
	}
	for _, e := range entries {
		if !e.Kind.Valid() || e.Name == "" || len(e.Name) > 500 || len(e.Version) > 200 || len(e.Platform) > 50 {
			continue
		}
		var cached int64
		q := h.db.Model(&models.CacheEntry{}).Where("organization_id = ? AND kind = ? AND name = ?", org, e.Kind, e.Name)
		if e.Kind == runnercontract.CacheKindRole {
			q = q.Where("version LIKE ?", escapeLike(e.Version)+"@%")
		} else {
			q = q.Where("version = ? AND platform = ?", e.Version, e.Platform)
		}
		if err := q.Count(&cached).Error; err != nil || cached > 0 {
			continue
		}
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		var doc models.JSONB
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue
		}
		p := &models.CachePromotion{
			OrganizationID: org, AgentPoolID: pool, RunnerID: runner.ID, JobKind: string(kind), JobID: jobID,
			Entry: doc, Status: models.CachePromotionPending,
		}
		if err := h.db.Create(p).Error; err != nil {
			logger.Warnf("Recording a cache promotion of job %s: %v", jobID, err)
		}
	}
}

// pendingPromotions are the promotions waiting for runner, oldest first.
func (h *RunnerAgentHandler) pendingPromotions(runner *models.Runner) []runnercontract.CachePromotion {
	var rows []models.CachePromotion
	err := h.db.Where("runner_id = ? AND status = ? AND created_at > ?", runner.ID, models.CachePromotionPending, time.Now().Add(-promotionTTL)).
		Order("created_at").Limit(promotionsPerHeartbeat).Find(&rows).Error
	if err != nil || len(rows) == 0 {
		return nil
	}
	out := make([]runnercontract.CachePromotion, 0, len(rows))
	for _, r := range rows {
		var e runnercontract.CacheEntry
		raw, err := json.Marshal(r.Entry)
		if err != nil || json.Unmarshal(raw, &e) != nil {
			continue
		}
		out = append(out, runnercontract.CachePromotion{ID: r.ID.String(), OrganizationID: r.OrganizationID.String(), JobID: r.JobID, Entry: e})
	}
	return out
}

// settlePromotion marks the promotion the calling runner uploaded an entry under as promoted, when
// it is that runner's and the organization's.
func (h *RunnerAgentHandler) settlePromotion(c *gin.Context, org uuid.UUID) {
	raw := c.Query("promotion")
	if raw == "" {
		return
	}
	runner, ok := callingRunner(c)
	id, err := uuid.Parse(raw)
	if !ok || err != nil {
		return
	}
	h.db.Model(&models.CachePromotion{}).
		Where("id = ? AND runner_id = ? AND organization_id = ? AND status = ?", id, runner.ID, org, models.CachePromotionPending).
		Updates(map[string]any{"status": models.CachePromotionPromoted, "updated_at": time.Now()})
}

// DropCachePromotionRequest is the body of POST /runner/cache/promotions/:id/drop.
type DropCachePromotionRequest struct {
	Reason string `json:"reason"`
	// Poisoned says the source's artifact differed from what the job reported or from the
	// source's own published digest: an attempted poisoning.
	Poisoned bool `json:"poisoned"`
}

// DropCachePromotion settles a promotion the populator could not verify. A poisoning attempt leaves
// an event on the job, where its organization sees it, and an audit record on the job's pool.
//
// POST /api/v2/runner/cache/promotions/:id/drop
func (h *RunnerAgentHandler) DropCachePromotion(c *gin.Context) {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Cache promotion not found")
		return
	}
	var req DropCachePromotionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if len(req.Reason) > 4000 {
		req.Reason = req.Reason[:4000]
	}
	var p models.CachePromotion
	if err := h.db.First(&p, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Cache promotion not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}
	if p.RunnerID != runner.ID {
		writeRunnerForbidden(c, "the promotion belongs to another launcher")
		return
	}
	if p.Status != models.CachePromotionPending {
		c.JSON(http.StatusOK, map[string]string{"status": p.Status})
		return
	}
	if err := h.db.Model(&p).Updates(map[string]any{"status": models.CachePromotionDropped, "reason": req.Reason, "poisoned": req.Poisoned, "updated_at": time.Now()}).Error; err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if req.Poisoned {
		h.recordPoisoning(&p, req.Reason)
	}
	c.JSON(http.StatusOK, map[string]string{"status": models.CachePromotionDropped})
}

// recordPoisoning writes the event on the job and the audit record on its pool.
func (h *RunnerAgentHandler) recordPoisoning(p *models.CachePromotion, reason string) {
	name, _ := p.Entry["name"].(string)
	version, _ := p.Entry["version"].(string)
	kind, _ := p.Entry["kind"].(string)
	text := "The verified cache refused " + kind + " " + name + " " + version + ": " + reason + "\n"
	if p.JobKind == string(models.JobTypeAnsibleJob) && h.ansibleJobRepo != nil {
		if jobID, err := uuid.Parse(p.JobID); err == nil {
			ev := &models.AnsibleJobEvent{JobID: jobID, Event: "cache_entry_dropped", Task: "Cache entry refused", Stderr: text, Failed: true}
			if err := h.ansibleJobRepo.CreateEventNextCounter(ev); err != nil {
				logger.Warnf("Recording the refused cache entry on job %s: %v", p.JobID, err)
			}
		}
	}
	audit := &models.AuditLog{
		OrganizationID: &p.OrganizationID, Action: "cache.poisoning_refused", ResourceType: "agent_pool", ResourceID: p.AgentPoolID,
		Details: models.AuditDetails{"job_kind": p.JobKind, "job_id": p.JobID, "kind": kind, "name": name, "version": version, "reason": reason, "runner_id": p.RunnerID.String()},
	}
	if err := h.db.Create(audit).Error; err != nil {
		logger.Warnf("Recording the refused cache entry of job %s in the audit log: %v", p.JobID, err)
	}
}
