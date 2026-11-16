package handlers

import (
	"context"
	"fmt"

	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/security/gitargs"
)

// captureSpec is the commit a webhook delivery asks one workspace to run, and where to fetch it.
type captureSpec struct {
	commit       string
	fetchRef     string // the ref a commit outside the branches is fetched by, such as refs/pull/7/head
	committer    string
	sourceBranch string
	prNumber     int
	speculative  bool
}

// queueCapturedRun creates ws's run for a webhook delivery together with a configuration version
// in status fetching, pinned to the delivered commit (#938). The API clones nothing: the
// orchestrator requests the run's configuration_snapshot work item, and an executor fetches the
// commit with the workspace's own connection. supersede runs only when a pair is created. created
// is false when the commit already has one.
func (h *VCSAppInstallationHandlerV2) queueCapturedRun(ctx context.Context, ws *models.Workspace, s captureSpec, supersede func(*repository.RunRepository, *repository.ConfigurationVersionRepository)) (run *models.Run, created bool, err error) {
	if gitargs.CommitSHARe.FindString(s.commit) == "" {
		return nil, false, fmt.Errorf("delivered commit %q is not a commit id", s.commit)
	}
	if s.fetchRef != "" && gitargs.RefNameRe.FindString(s.fetchRef) == "" {
		return nil, false, fmt.Errorf("delivered ref %q is not a ref name", s.fetchRef)
	}
	cv := &models.ConfigurationVersion{
		WorkspaceID:   ws.ID,
		Status:        models.ConfigurationVersionStatusFetching,
		Source:        "tfe-vcs",
		AutoQueueRuns: true,
		Speculative:   s.speculative,
		CommitHash:    s.commit,
		FetchRef:      s.fetchRef,
		Committer:     s.committer,
		PRNumber:      s.prNumber,
		SourceBranch:  s.sourceBranch,
	}
	// TFE-compatible: a push runs plan and apply, applying when the workspace auto-applies; a pull
	// request runs a speculative plan only.
	run = &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanAndApply, AutoApplyAfterPlan: true}
	if s.speculative {
		run.Operation, run.AutoApplyAfterPlan = models.RunOperationPlanOnly, false
	}
	created, err = h.runRepo.CreateCapturedContext(ctx, cv, run, supersede)
	if err != nil {
		return nil, false, fmt.Errorf("queueing the run of workspace %s at %s: %w", ws.ID, s.commit, err)
	}
	return run, created, nil
}
