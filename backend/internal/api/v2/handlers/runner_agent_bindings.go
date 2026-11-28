// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	"gorm.io/gorm"
)

// attemptIdentity is the identity a job token for this attempt carries (#1113, D3, owner decision
// Q10). It runs in the token's transaction, after the claim checks, with the job row locked:
//   - an attempt that holds a decision replays it unchanged, never re-resolving or refusing on
//     identity grounds, as a launcher recovering its claim needs;
//   - an attempt with no decision that already holds a job token started before decisions were
//     recorded: it gets no identity, no check and no recorded decision;
//   - otherwise this is the first token: it resolves the binding, which refuses one the pool does
//     not offer, and records the decision with the attempt, so both commit with the token or not
//     at all.
func (h *RunnerAgentHandler) attemptIdentity(runner *models.Runner, kind models.JobType, jobID string, pool *uuid.UUID, attempt int, placement models.JobPlacement, target any) (*runnercontract.Identity, error) {
	if placement.IdentityAttempt == attempt && placement.Identity != nil {
		return tokenIdentity(placement.Identity), nil
	}
	preFeature, err := h.apiKeyService.HasJobToken(kind, jobID, attempt)
	if err != nil {
		return nil, fmt.Errorf("checking for an earlier job token: %w", err)
	}
	if preFeature {
		return nil, nil //nolint:nilnil // a pre-feature attempt keeps the identity it was placed with
	}
	b, scope, err := h.jobBinding(kind, jobID, pool)
	if err != nil {
		return nil, err
	}
	if b != nil {
		if err := identityApplicable(runner, b); err != nil {
			return nil, err
		}
	}
	decision := &models.PlacementIdentity{Mechanism: models.PlacementMechanismPlatform}
	var bindingID *uuid.UUID
	if b != nil {
		decision, bindingID = bindingSnapshot(b), &b.ID
	}
	decision.Scope = scope
	raw, err := json.Marshal(decision)
	if err != nil {
		return nil, fmt.Errorf("encoding the identity decision: %w", err)
	}
	if err := h.db.Model(target).Updates(map[string]any{
		"placement_identity_attempt":    attempt,
		"placement_identity":            gorm.Expr("?::jsonb", string(raw)),
		"placement_identity_binding_id": bindingID,
	}).Error; err != nil {
		return nil, fmt.Errorf("recording the identity decision of %s: %w", jobID, err)
	}
	return tokenIdentity(decision), nil
}

// errIdentityNotApplicable refuses a job's first token because the claiming launcher cannot apply
// the binding it resolves (#1113, D3, owner decision Q9).
var errIdentityNotApplicable = errors.New("identity not applicable")

// identityApplicable checks that the claiming launcher can run a job with binding b: a strict hosted
// launcher runs every job with the platform identity, on any driver, and only the Kubernetes driver
// applies a ServiceAccount. The refusal holds whatever release the launcher runs, because the API
// decides it.
func identityApplicable(runner *models.Runner, b *models.IdentityBinding) error {
	if runner.HostedStrict {
		return fmt.Errorf("%w: strict hosted isolation runs every job with the platform identity; identity binding %q cannot be used here",
			errIdentityNotApplicable, b.Name)
	}
	if runner.Driver != "kubernetes" {
		driver := runner.Driver
		if driver == "" {
			driver = "unreported"
		}
		return fmt.Errorf("%w: identity binding %q (%s) needs the kubernetes driver; this pool's launcher uses the %s driver; run the job on a Kubernetes pool or select no binding",
			errIdentityNotApplicable, b.Name, b.Mechanism, driver)
	}
	return nil
}

// bindingSnapshot is a binding as a decision records it.
func bindingSnapshot(b *models.IdentityBinding) *models.PlacementIdentity {
	ann := map[string]string{}
	for k, v := range b.Annotations {
		if s, ok := v.(string); ok {
			ann[k] = s
		}
	}
	id := b.ID
	return &models.PlacementIdentity{BindingID: &id, Name: b.Name, Mechanism: b.Mechanism, ServiceAccount: b.ServiceAccount, Annotations: ann, PerJobSA: b.PerJobSA}
}

// tokenIdentity is the identity a job token carries for a decision: nil for the platform identity.
func tokenIdentity(p *models.PlacementIdentity) *runnercontract.Identity {
	if p == nil || p.BindingID == nil {
		return nil
	}
	ann := make(map[string]string, len(p.Annotations))
	maps.Copy(ann, p.Annotations)
	return &runnercontract.Identity{BindingID: p.BindingID.String(), Mechanism: p.Mechanism, ServiceAccount: p.ServiceAccount, Annotations: ann, PerJob: p.PerJobSA}
}

// jobBinding resolves the identity binding a job runs with by the level rule and checks that its
// pool offers it (#933, D8, AC44). Nil is the platform identity; an error refuses the token,
// because a job must not run with an identity its pool does not offer. For a VCS inventory file
// sync it reads the inventory row once, checks that the customer pool the sync is queued on still
// lets the inventory's current project use it, whatever the selection resolves to now, and returns
// that validated scope (#1113, D2, owner decision Q12).
func (h *RunnerAgentHandler) jobBinding(kind models.JobType, jobID string, pool *uuid.UUID) (*models.IdentityBinding, *models.PlacementScope, error) {
	var resolved *uuid.UUID
	var org uuid.UUID
	var scope *models.PlacementScope
	switch kind {
	case models.JobTypeTofuRun:
		var run models.Run
		if err := h.db.Preload("Workspace.Project.Organization").First(&run, "id = ?", jobID).Error; err != nil {
			return nil, nil, err
		}
		resolved, org = settings.EffectiveWorkspaceIdentity(&run.Workspace).Value, run.Workspace.Project.OrganizationID
	case models.JobTypeAnsibleJob:
		var job models.AnsibleJob
		if err := h.db.Preload("Project.Organization").First(&job, "id = ?", jobID).Error; err != nil {
			return nil, nil, err
		}
		var tmpl *models.AnsibleJobTemplate
		if job.TemplateID != nil {
			var t models.AnsibleJobTemplate
			if err := h.db.Select("id", "identity_binding_id").First(&t, "id = ?", *job.TemplateID).Error; err == nil {
				tmpl = &t
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, nil, fmt.Errorf("loading the job template: %w", err)
			}
		}
		resolved, org = settings.EffectiveTemplateIdentity(tmpl, &job.Project, &job.Project.Organization).Value, job.Project.OrganizationID
	case models.JobTypeWorkItem:
		var item models.WorkItem
		if err := h.db.First(&item, "id = ?", jobID).Error; err != nil {
			return nil, nil, err
		}
		org = item.OrganizationID
		// A dynamic-source sync runs with its source's identity and a VCS inventory file sync with
		// its inventory's, each resolved as it stands now (#1113, D2, Q5); every other sync runs
		// with the platform identity (#933, D2).
		switch {
		case item.Kind == models.WorkItemDynamicSourceSync && item.InventorySourceID != nil:
			var src models.AnsibleInventorySource
			if err := h.db.First(&src, "id = ?", *item.InventorySourceID).Error; err != nil {
				return nil, nil, err
			}
			project, org, err := ansible.SourceScope(h.db, &src)
			if err != nil {
				return nil, nil, err
			}
			resolved = settings.EffectiveSourceIdentity(&src, project, org).Value
		case item.Kind == models.WorkItemInventoryFileSync && item.InventoryID != nil:
			var inv models.AnsibleInventory
			if err := h.db.Select("id", "organization_id", "project_id", "identity_binding_id").First(&inv, "id = ?", *item.InventoryID).Error; err != nil {
				return nil, nil, err
			}
			scope = &models.PlacementScope{ProjectID: inv.ProjectID}
			if pool != nil {
				var queued models.AgentPool
				if err := h.db.Preload("AllowedProjects").First(&queued, "id = ?", *pool).Error; err != nil {
					return nil, nil, fmt.Errorf("loading the pool of %s: %w", jobID, err)
				}
				if !queued.IsHosted() && !queued.AllowsInventory(inv.ProjectID) {
					return nil, nil, fmt.Errorf("%w: agent pool %q no longer lets the inventory's project use it; request a sync again", repository.ErrBindingNotOffered, queued.Name)
				}
			}
			project, org, err := ansible.InventoryScope(h.db, &inv)
			if err != nil {
				return nil, nil, err
			}
			resolved = settings.EffectiveInventoryIdentity(&inv, project, org).Value
		default:
			return nil, nil, nil
		}
	}
	b, err := repository.NewIdentityBindingRepository(h.db).Offered(org, resolved, pool)
	if err != nil {
		return nil, nil, err
	}
	return b, scope, nil
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
