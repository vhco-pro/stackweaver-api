// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/settings"
	"gorm.io/gorm"
)

// SetAllowedRegistries sets images.allowed_registries, which a job's run image is checked against at
// job start as it is at save (#933, D6, AC29).
func (h *RunnerAgentHandler) SetAllowedRegistries(allowed []string) { h.allowedRegistries = allowed }

// errImageNotAllowed refuses a job whose run image's registry images.allowed_registries does not
// list (#933, D6, AC29).
var errImageNotAllowed = errors.New("not allowed")

// jobImage resolves the run image a job's level rule selects (#933, D0, D6) and records it on the
// job's placement record with the level it came from; nil runs the platform image. A sync other
// than a dynamic source's runs the platform image (D2). When the job's pool offers a pull Secret
// for the image's registry, the image names it (D8).
func (h *RunnerAgentHandler) jobImage(kind models.JobType, jobID string, pool *uuid.UUID) (*runnercontract.JobImage, error) {
	var resolved settings.Resolved[*uuid.UUID]
	var table any
	switch kind {
	case models.JobTypeTofuRun:
		var run models.Run
		if err := h.db.Preload("Workspace.Project.Organization").First(&run, "id = ?", jobID).Error; err != nil {
			return nil, err
		}
		resolved, table = settings.EffectiveWorkspaceRunImage(&run.Workspace), &models.Run{}
	case models.JobTypeAnsibleJob:
		var job models.AnsibleJob
		if err := h.db.Preload("Project.Organization").First(&job, "id = ?", jobID).Error; err != nil {
			return nil, err
		}
		var tmpl *models.AnsibleJobTemplate
		if job.TemplateID != nil {
			var t models.AnsibleJobTemplate
			if h.db.Select("id", "run_image_id").First(&t, "id = ?", *job.TemplateID).Error == nil {
				tmpl = &t
			}
		}
		resolved, table = settings.EffectiveTemplateRunImage(tmpl, &job.Project, &job.Project.Organization), &models.AnsibleJob{}
	case models.JobTypeWorkItem:
		var item models.WorkItem
		if err := h.db.First(&item, "id = ?", jobID).Error; err != nil {
			return nil, err
		}
		if item.Kind != models.WorkItemDynamicSourceSync || item.InventorySourceID == nil {
			return nil, nil //nolint:nilnil // the platform image
		}
		var src models.AnsibleInventorySource
		if err := h.db.First(&src, "id = ?", *item.InventorySourceID).Error; err != nil {
			return nil, err
		}
		project, org, err := ansible.SourceScope(h.db, &src)
		if err != nil {
			return nil, err
		}
		resolved, table = settings.EffectiveSourceRunImage(&src, project, org), &models.WorkItem{}
	}
	if resolved.Value == nil {
		return nil, nil //nolint:nilnil // the platform image
	}
	var img models.RunImage
	if err := h.db.First(&img, "id = ?", *resolved.Value).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil //nolint:nilnil // a deleted image defers to the platform image
		}
		return nil, err
	}
	if !settings.RegistryAllowed(img.Image, h.allowedRegistries) {
		return nil, fmt.Errorf("the run image %s (%s) comes from a registry images.allowed_registries does not list (%s): %w", img.Name, img.Image, strings.Join(h.allowedRegistries, ", "), errImageNotAllowed)
	}
	out := &runnercontract.JobImage{
		ID: img.ID.String(), Ref: img.Reference(), Digest: img.Digest, Level: string(resolved.Level),
		Kind: img.Kind, PullCredential: img.RegistryCredentialID != nil,
	}
	if pool != nil {
		ps, err := repository.NewPullSecretRepository(h.db).ForRegistry(*pool, imageRegistryHost(img.Image))
		if err != nil {
			return nil, err
		}
		if ps != nil {
			out.PullSecret = ps.SecretName
		}
	}
	if table != nil {
		if err := h.db.Model(table).Where("id = ?", jobID).Updates(map[string]any{
			"placement_image": out.Ref, "placement_image_digest": img.Digest, "placement_image_level": out.Level,
		}).Error; err != nil {
			logger.Warnf("recording the run image of %s: %v", jobID, err)
		}
	}
	return out, nil
}

// GetPullCredential serves a run image's registry credential to a launcher that serves the
// image's organization: a customer launcher of it, or a hosted launcher holding its work. It
// serves registry credentials only, never a job's.
//
// GET /api/v2/runner/images/:id/pull-credential
func (h *RunnerAgentHandler) GetPullCredential(c *gin.Context) {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run image not found")
		return
	}
	var img models.RunImage
	if err := h.db.First(&img, "id = ?", id).Error; err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run image not found")
		return
	}
	if runner.IsHosted() {
		holds, err := h.hostedRunnerHolds(runner.ID, img.OrganizationID)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !holds {
			writeRunnerForbidden(c, "this hosted launcher holds no work of the image's organization")
			return
		}
	} else if runner.OrgID() != img.OrganizationID {
		writeRunnerForbidden(c, "the run image belongs to a different organization")
		return
	}
	if img.RegistryCredentialID == nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the run image is pulled without a credential")
		return
	}
	var cred models.AnsibleCredential
	if err := h.db.First(&cred, "id = ? AND organization_id = ? AND type = ?", *img.RegistryCredentialID, img.OrganizationID, models.CredentialTypeRegistry).Error; err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the run image's registry credential is gone")
		return
	}
	password := ""
	if cred.Password != "" && h.cryptoService != nil {
		if p, err := h.cryptoService.Decrypt(cred.Password); err == nil {
			password = p
		}
	}
	c.JSON(http.StatusOK, runnercontract.PullCredential{Registry: imageRegistryHost(img.Image), Username: cred.Username, Password: password})
}

// imageRegistryHost is the registry an image reference names: its first component when it is a host,
// Docker Hub otherwise.
func imageRegistryHost(ref string) string {
	name := settings.NormalizedImageName(ref)
	host, _, _ := strings.Cut(name, "/")
	return host
}
