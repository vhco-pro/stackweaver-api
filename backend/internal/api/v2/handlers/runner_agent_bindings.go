// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/settings"
)

// jobIdentity resolves the identity binding a job runs with by the level rule and checks that its
// pool offers it (#933, D8, AC44), recording it on the job's placement. Nil is the platform
// identity; an error refuses the token, because a job must not run with an identity its pool does
// not offer.
func (h *RunnerAgentHandler) jobIdentity(kind models.JobType, jobID string, pool *uuid.UUID) (*runnercontract.Identity, error) {
	var resolved *uuid.UUID
	var table any
	switch kind {
	case models.JobTypeTofuRun:
		var run models.Run
		if err := h.db.Preload("Workspace.Project.Organization").First(&run, "id = ?", jobID).Error; err != nil {
			return nil, err
		}
		resolved, table = settings.EffectiveWorkspaceIdentity(&run.Workspace).Value, &models.Run{}
	case models.JobTypeAnsibleJob:
		var job models.AnsibleJob
		if err := h.db.Preload("Project.Organization").First(&job, "id = ?", jobID).Error; err != nil {
			return nil, err
		}
		var tmpl *models.AnsibleJobTemplate
		if job.TemplateID != nil {
			var t models.AnsibleJobTemplate
			if h.db.Select("id", "identity_binding_id").First(&t, "id = ?", *job.TemplateID).Error == nil {
				tmpl = &t
			}
		}
		resolved, table = settings.EffectiveTemplateIdentity(tmpl, &job.Project, &job.Project.Organization).Value, &models.AnsibleJob{}
	case models.JobTypeWorkItem:
		var item models.WorkItem
		if err := h.db.First(&item, "id = ?", jobID).Error; err != nil {
			return nil, err
		}
		// Only a dynamic-source sync runs with its source's identity; every other sync runs with
		// the platform identity (D2).
		if item.Kind != models.WorkItemDynamicSourceSync || item.InventorySourceID == nil {
			return nil, nil //nolint:nilnil // the platform identity
		}
		var src models.AnsibleInventorySource
		if err := h.db.First(&src, "id = ?", *item.InventorySourceID).Error; err != nil {
			return nil, err
		}
		project, org, err := ansible.SourceScope(h.db, &src)
		if err != nil {
			return nil, err
		}
		resolved, table = settings.EffectiveSourceIdentity(&src, project, org).Value, &models.WorkItem{}
	}
	b, err := repository.NewIdentityBindingRepository(h.db).Offered(resolved, pool)
	if err != nil || b == nil {
		return nil, err
	}
	if table != nil {
		if err := h.db.Model(table).Where("id = ?", jobID).Update("placement_identity_binding_id", b.ID).Error; err != nil {
			logger.Warnf("recording the identity binding of %s: %v", jobID, err)
		}
	}
	ann := map[string]string{}
	for k, v := range b.Annotations {
		if s, ok := v.(string); ok {
			ann[k] = s
		}
	}
	return &runnercontract.Identity{BindingID: b.ID.String(), Mechanism: b.Mechanism, ServiceAccount: b.ServiceAccount, Annotations: ann, PerJob: b.PerJobSA}, nil
}

// ingestInventory stores what a customer launcher placing pods reported from its job namespace
// and answers with the identity binding ServiceAccounts and registry pull Secrets its pool needs
// there (#933, D8).
func (h *RunnerAgentHandler) ingestInventory(runner *models.Runner, entries []runnercontract.InventoryEntry) []runnercontract.EnsureObject {
	if runner.IsHosted() || runner.AgentPoolID == nil || runner.Driver != "kubernetes" {
		return nil
	}
	bindings := repository.NewIdentityBindingRepository(h.db)
	if entries != nil {
		reports := make([]repository.ObjectReport, 0, len(entries))
		for _, e := range entries {
			reports = append(reports, repository.ObjectReport{Kind: e.Kind, Namespace: e.Namespace, Name: e.Name, Present: e.Present, ManagedBy: e.ManagedBy, ExternalManager: e.ExternalManager})
		}
		if err := bindings.ReportInventory(*runner.AgentPoolID, reports); err != nil {
			logger.Warnf("storing the inventory of runner %s: %v", runner.ID, err)
		}
	}
	toCreate, err := bindings.ToCreate(*runner.AgentPoolID)
	if err != nil {
		return nil
	}
	out := make([]runnercontract.EnsureObject, 0, len(toCreate))
	for _, b := range toCreate {
		ann := map[string]string{}
		for k, v := range b.Annotations {
			if s, ok := v.(string); ok {
				ann[k] = s
			}
		}
		out = append(out, runnercontract.EnsureObject{Kind: "ServiceAccount", Name: b.ServiceAccount, PoolID: b.AgentPoolID.String(), Annotations: ann})
	}
	return append(out, h.pullSecretsToCreate(*runner.AgentPoolID)...)
}

// pullSecretsToCreate are the create-mode registry pull Secrets of the pool, each with the
// credential of the organization registry credential it is built from (#933, D8). One whose
// credential is gone is left out: there is nothing to write it from.
func (h *RunnerAgentHandler) pullSecretsToCreate(poolID uuid.UUID) []runnercontract.EnsureObject {
	pulls, err := repository.NewPullSecretRepository(h.db).ToCreate(poolID)
	if err != nil {
		logger.Warnf("listing the pull Secrets of pool %s: %v", poolID, err)
		return nil
	}
	var out []runnercontract.EnsureObject
	for _, p := range pulls {
		if p.RegistryCredentialID == nil {
			continue
		}
		var cred models.AnsibleCredential
		if err := h.db.First(&cred, "id = ? AND organization_id = ? AND type = ?", *p.RegistryCredentialID, p.OrganizationID, models.CredentialTypeRegistry).Error; err != nil {
			logger.Warnf("pull Secret %s: its registry credential is gone", p.ID)
			continue
		}
		password := ""
		if cred.Password != "" && h.cryptoService != nil {
			pw, err := h.cryptoService.Decrypt(cred.Password)
			if err != nil {
				logger.Warnf("pull Secret %s: decrypting its registry credential failed", p.ID)
				continue
			}
			password = pw
		}
		out = append(out, runnercontract.EnsureObject{Kind: "Secret", Name: p.SecretName, PoolID: poolID.String(), Registry: p.Registry, Username: cred.Username, Password: password})
	}
	return out
}

// hostedDepth is the pending work across the hosted pools of a hosted runner's group, nil for a
// customer runner (#933, D11, AC78).
func (h *RunnerAgentHandler) hostedDepth(runner *models.Runner) *runnercontract.HostedDepth {
	if !runner.IsHosted() {
		return nil
	}
	group := runner.HostedGroup
	if group == "" {
		group = "default"
	}
	tofu, ansible, items, err := repository.HostedDepth(h.db, group)
	if err != nil {
		logger.Warnf("reading the hosted depth of group %s: %v", group, err)
		return nil
	}
	return &runnercontract.HostedDepth{Group: group, Tofu: tofu, Ansible: ansible, WorkItems: items}
}

// HostedQueueDepth answers a hosted launcher with the pending work of its group's hosted pools,
// for an operator scaling hosted capacity (#933, D11, AC78).
//
// GET /api/v2/runner/queue-depth
func (h *RunnerAgentHandler) HostedQueueDepth(c *gin.Context) {
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	if !runner.IsHosted() {
		writeRunnerForbidden(c, "the hosted queue depth is read by a hosted launcher; an agent pool's depth is GET /agent-pools/:id/queue-depth")
		return
	}
	depth := h.hostedDepth(runner)
	if depth == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	c.JSON(http.StatusOK, depth)
}
