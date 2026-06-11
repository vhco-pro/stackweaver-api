// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"gorm.io/gorm"
)

// maxBulkImportEntries caps a single bulk-import request.
const maxBulkImportEntries = 200

// playbookExcludedDirs are conventional Ansible (and CI) directory names that
// never contain playbooks; a YAML file under any of these segments is hidden
// from playbook discovery.
var playbookExcludedDirs = map[string]struct{}{
	"roles": {}, "group_vars": {}, "host_vars": {}, "vars": {}, "tasks": {},
	"handlers": {}, "templates": {}, "files": {}, "defaults": {}, "meta": {},
	"collections": {}, "inventories": {}, "inventory": {}, "molecule": {},
	"library": {}, "filter_plugins": {}, "module_utils": {}, "plugins": {},
	"test": {}, "tests": {}, ".github": {}, ".gitlab": {}, ".git": {},
}

// playbookExcludedFiles are well-known YAML files that are never playbooks.
var playbookExcludedFiles = map[string]struct{}{
	"requirements.yml": {}, "requirements.yaml": {},
	"galaxy.yml": {}, "galaxy.yaml": {},
	".gitlab-ci.yml": {}, ".travis.yml": {}, "azure-pipelines.yml": {},
	"docker-compose.yml": {}, "docker-compose.yaml": {},
}

// filterPlaybookFiles narrows a repository file listing down to playbook
// candidates: YAML files under scopePath (when set), excluding conventional
// non-playbook directories, hidden files, and well-known non-playbook YAML.
// The result is sorted for stable output.
func filterPlaybookFiles(paths []string, scopePath string) []string {
	scopePath = strings.Trim(scopePath, "/")
	var out []string
	for _, p := range paths {
		p = strings.TrimPrefix(p, "/")
		if scopePath != "" && !strings.HasPrefix(p, scopePath+"/") && p != scopePath {
			continue
		}
		base := path.Base(p)
		lowerBase := strings.ToLower(base)
		if !strings.HasSuffix(lowerBase, ".yml") && !strings.HasSuffix(lowerBase, ".yaml") {
			continue
		}
		if strings.HasPrefix(base, ".") || strings.HasPrefix(lowerBase, "docker-compose.") {
			continue
		}
		if _, excluded := playbookExcludedFiles[lowerBase]; excluded {
			continue
		}
		dir := path.Dir(p)
		excluded := false
		if dir != "." {
			for _, seg := range strings.Split(dir, "/") {
				if _, ok := playbookExcludedDirs[strings.ToLower(seg)]; ok {
					excluded = true
					break
				}
			}
		}
		if excluded {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// playbookNameCandidates returns deterministic name candidates for a playbook
// derived from its file path: the filename stem, then disambiguated with the
// parent directory, the repository name, and finally numeric suffixes. Playbook
// names are unique per project, so collisions (e.g. several site.yml files in
// different directories) are resolved by walking this list. A requested name
// short-circuits derivation and is only disambiguated numerically.
func playbookNameCandidates(filePath, repository, requested string) []string {
	if requested != "" {
		candidates := []string{requested}
		for i := 2; i <= 9; i++ {
			candidates = append(candidates, fmt.Sprintf("%s-%d", requested, i))
		}
		return candidates
	}

	base := path.Base(filePath)
	stem := strings.TrimSuffix(base, path.Ext(base))
	candidates := []string{stem}
	if dir := path.Dir(filePath); dir != "." && dir != "/" {
		candidates = append(candidates, fmt.Sprintf("%s (%s)", stem, path.Base(dir)))
	}
	if repository != "" {
		repoName := repository
		if idx := strings.LastIndex(repository, "/"); idx >= 0 {
			repoName = repository[idx+1:]
		}
		candidates = append(candidates, fmt.Sprintf("%s (%s)", stem, repoName))
	}
	for i := 2; i <= 9; i++ {
		candidates = append(candidates, fmt.Sprintf("%s-%d", stem, i))
	}
	return candidates
}

// isDuplicateKeyErr reports whether err is a unique-constraint violation.
// gorm only translates to ErrDuplicatedKey when TranslateError is enabled, so
// the Postgres SQLSTATE is matched as a fallback.
func isDuplicateKeyErr(err error) bool {
	if err == nil {
		return false
	}
	if err == gorm.ErrDuplicatedKey {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLSTATE 23505") || strings.Contains(msg, "duplicate key value")
}

// enqueueInitialSync marks a VCS-backed playbook as syncing and enqueues its
// initial sync. Failures are recorded on the playbook rather than returned:
// creation already succeeded and the playbook stays usable (cached-mode runs
// auto-sync on cache miss).
func (h *PlaybookHandler) enqueueInitialSync(playbook *models.AnsiblePlaybook) {
	if playbook.VCSConnectionID == nil || playbook.VCSRepository == "" || h.queue == nil {
		return
	}
	playbook.LastSyncStatus = "syncing"
	if err := h.playbookRepo.Update(playbook); err != nil {
		logger.Warnf("Failed to update playbook sync status: %v", err)
	}
	syncMsg := h.buildPlaybookSyncMessage(context.Background(), playbook)
	if err := h.queue.Enqueue(context.Background(), "ansible_sync", syncMsg); err != nil {
		playbook.LastSyncStatus = "pending"
		playbook.LastSyncError = "Auto-sync failed to queue: " + err.Error()
		if updateErr := h.playbookRepo.Update(playbook); updateErr != nil {
			logger.Warnf("Failed to update playbook after sync queue error: %v", updateErr)
		}
	}
}

// resolveDiscoveryContext validates the org (from the :name path param), the
// caller's permission (manage when write, read otherwise), and the VCS
// connection's ownership. Writes the error response and returns nil on failure.
type discoveryContext struct {
	org  *models.Organization
	conn *models.VCSConnection
}

func (h *PlaybookHandler) resolveDiscoveryContext(c *gin.Context, connectionID string, write bool) *discoveryContext {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Organization not found"}}})
		return nil
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": []gin.H{{"status": "401", "title": "Unauthorized", "detail": "Authentication required"}}})
		return nil
	}
	var hasPermission bool
	if write {
		hasPermission, err = h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, org.ID)
	} else {
		hasPermission, err = h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to check permissions"}}})
		return nil
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"errors": []gin.H{{"status": "403", "title": "Forbidden", "detail": "You do not have permission to access playbooks in this organization"}}})
		return nil
	}

	connID, err := uuid.Parse(connectionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid VCS connection ID"}}})
		return nil
	}
	conn, err := h.vcsConnectionRepo.GetByID(connID)
	if err != nil || conn.OrganizationID != org.ID {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "VCS connection not found"}}})
		return nil
	}
	return &discoveryContext{org: org, conn: conn}
}

// findRegisteredPlaybooks returns the playbooks registered on the given
// connection, repository, and branch, keyed by playbook path. When projectID
// is non-nil, only that project's playbooks are returned (the dedupe scope for
// imports); with uuid.Nil the whole connection is covered (annotation scope —
// if the same path is registered in several projects an arbitrary one wins,
// which is fine for display purposes). The connection match implies the org
// boundary: connections are org-scoped and validated by the caller.
func (h *PlaybookHandler) findRegisteredPlaybooks(connID, projectID uuid.UUID, repository, branch string) (map[string]*models.AnsiblePlaybook, error) {
	playbooks, err := h.playbookRepo.ListByVCSRepositoryAndBranch(repository, branch)
	if err != nil {
		return nil, err
	}
	registered := make(map[string]*models.AnsiblePlaybook)
	for i := range playbooks {
		pb := &playbooks[i]
		if pb.VCSConnectionID == nil || *pb.VCSConnectionID != connID {
			continue
		}
		if projectID != uuid.Nil && pb.ProjectID != projectID {
			continue
		}
		registered[strings.TrimPrefix(pb.PlaybookPath, "/")] = pb
	}
	return registered, nil
}

// ListPlaybookFiles lists playbook candidate files in a connected repository,
// annotated with whether each is already registered as a playbook in the org.
// GET /api/v2/organizations/:name/ansible/vcs-playbook-files?vcs_connection_id=&repository=&branch=&path=
func (h *PlaybookHandler) ListPlaybookFiles(c *gin.Context) {
	repository := c.Query("repository")
	branch := c.Query("branch")
	scopePath := c.Query("path")
	if repository == "" || !strings.Contains(repository, "/") {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "repository must be in owner/repo format"}}})
		return
	}
	// Branch is required: the file listing, the registered-playbook annotation,
	// and any subsequent import must all refer to the same branch (a silent
	// default would diverge from repositories whose default branch is not it).
	if branch == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "branch is required"}}})
		return
	}

	dc := h.resolveDiscoveryContext(c, c.Query("vcs_connection_id"), false)
	if dc == nil {
		return
	}

	provider, err := h.vcsRegistry.GetProvider(dc.conn)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": fmt.Sprintf("Failed to resolve VCS provider: %v", err)}}})
		return
	}

	owner, repo, _ := strings.Cut(repository, "/")
	files, err := provider.ListFiles(c.Request.Context(), dc.conn, owner, repo, branch, []string{".yml", ".yaml"})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not implemented") {
			c.JSON(http.StatusNotImplemented, gin.H{"errors": []gin.H{{"status": "501", "title": "Not Implemented", "detail": fmt.Sprintf("File listing is not yet supported for %s", dc.conn.Provider)}}})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": fmt.Sprintf("Failed to list repository files: %v", err)}}})
		}
		return
	}

	candidates := filterPlaybookFiles(files, scopePath)

	registered, err := h.findRegisteredPlaybooks(dc.conn.ID, uuid.Nil, repository, branch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to load registered playbooks"}}})
		return
	}

	entries := make([]gin.H, 0, len(candidates))
	for _, filePath := range candidates {
		entry := gin.H{"path": filePath, "name": path.Base(filePath), "registered": false}
		if pb, ok := registered[filePath]; ok {
			entry["registered"] = true
			entry["playbook_id"] = pb.ID.String()
			entry["playbook_name"] = pb.Name
		}
		entries = append(entries, entry)
	}

	c.JSON(http.StatusOK, gin.H{"data": entries})
}

// BulkImportRequest is the body of the bulk-import action.
type BulkImportRequest struct {
	ProjectID       string `json:"project_id"`
	VCSConnectionID string `json:"vcs_connection_id"`
	Repository      string `json:"repository"`
	Branch          string `json:"branch"`
	SourceMode      string `json:"source_mode"`
	Playbooks       []struct {
		Path string `json:"path"`
		Name string `json:"name"`
	} `json:"playbooks"`
}

// importOnePlaybook finds or creates a single playbook for (project, connection,
// repository, branch, path). Returns the playbook, whether it was created, and
// an error. Name collisions (globally unique names) are resolved by walking the
// deterministic candidate list and retrying on unique-constraint violations.
func (h *PlaybookHandler) importOnePlaybook(
	registered map[string]*models.AnsiblePlaybook,
	projectID uuid.UUID, connID uuid.UUID,
	repository, branch, filePath, requestedName, sourceMode string,
) (*models.AnsiblePlaybook, bool, error) {
	filePath = strings.TrimPrefix(strings.TrimSpace(filePath), "/")
	if filePath == "" {
		return nil, false, fmt.Errorf("path is required")
	}
	if existing, ok := registered[filePath]; ok && existing.ProjectID == projectID {
		return existing, false, nil
	}

	var lastErr error
	for _, name := range playbookNameCandidates(filePath, repository, requestedName) {
		playbook := &models.AnsiblePlaybook{
			ProjectID:       projectID,
			Name:            name,
			VCSConnectionID: &connID,
			VCSRepository:   repository,
			VCSBranch:       branch,
			PlaybookPath:    filePath,
			SourceMode:      normalizeSourceMode(sourceMode),
		}
		err := h.playbookRepo.Create(playbook)
		if err == nil {
			registered[filePath] = playbook
			h.enqueueInitialSync(playbook)
			return playbook, true, nil
		}
		if !isDuplicateKeyErr(err) {
			return nil, false, err
		}
		lastErr = err
	}
	return nil, false, fmt.Errorf("could not find an available name: %w", lastErr)
}

// BulkImportPlaybooks registers many playbooks from one repository in one call.
// POST /api/v2/organizations/:name/ansible/playbooks/actions/bulk-import
func (h *PlaybookHandler) BulkImportPlaybooks(c *gin.Context) {
	var req BulkImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}
	if len(req.Playbooks) == 0 || len(req.Playbooks) > maxBulkImportEntries {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": fmt.Sprintf("playbooks must contain between 1 and %d entries", maxBulkImportEntries)}}})
		return
	}
	if req.Repository == "" || !strings.Contains(req.Repository, "/") || req.Branch == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "repository (owner/repo) and branch are required"}}})
		return
	}

	dc := h.resolveDiscoveryContext(c, req.VCSConnectionID, true)
	if dc == nil {
		return
	}

	projectID, ok := h.resolveProjectForOrg(c, dc.org, req.ProjectID)
	if !ok {
		return
	}

	registered, err := h.findRegisteredPlaybooks(dc.conn.ID, projectID, req.Repository, req.Branch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to load registered playbooks"}}})
		return
	}

	results := make([]gin.H, 0, len(req.Playbooks))
	created, skipped, failed := 0, 0, 0
	for _, entry := range req.Playbooks {
		playbook, wasCreated, err := h.importOnePlaybook(registered, projectID, dc.conn.ID, req.Repository, req.Branch, entry.Path, entry.Name, req.SourceMode)
		switch {
		case err != nil:
			failed++
			results = append(results, gin.H{"path": entry.Path, "status": "failed", "error": err.Error()})
		case wasCreated:
			created++
			results = append(results, gin.H{"path": entry.Path, "status": "created", "playbook_id": playbook.ID.String(), "name": playbook.Name})
		default:
			skipped++
			results = append(results, gin.H{"path": entry.Path, "status": "skipped", "playbook_id": playbook.ID.String(), "name": playbook.Name})
		}
	}

	if created > 0 {
		// Webhook registration is per-repository, not per-playbook: once per import.
		h.maybeRegisterADOWebhook(&dc.conn.ID, req.Repository)
	}

	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"results": results,
		"created": created,
		"skipped": skipped,
		"failed":  failed,
	}})
}

// FindOrCreateRequest is the body of the find-or-create action.
type FindOrCreateRequest struct {
	ProjectID       string `json:"project_id"`
	VCSConnectionID string `json:"vcs_connection_id"`
	Repository      string `json:"repository"`
	Branch          string `json:"branch"`
	Path            string `json:"path"`
	Name            string `json:"name"`
	SourceMode      string `json:"source_mode"`
}

// FindOrCreatePlaybook returns the playbook registered for (project, connection,
// repository, branch, path), creating it when absent. 200 with the existing
// playbook, 201 when created.
// POST /api/v2/organizations/:name/ansible/playbooks/actions/find-or-create
func (h *PlaybookHandler) FindOrCreatePlaybook(c *gin.Context) {
	var req FindOrCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}
	if req.Repository == "" || !strings.Contains(req.Repository, "/") || req.Path == "" || req.Branch == "" {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "repository (owner/repo), branch, and path are required"}}})
		return
	}

	dc := h.resolveDiscoveryContext(c, req.VCSConnectionID, true)
	if dc == nil {
		return
	}

	projectID, ok := h.resolveProjectForOrg(c, dc.org, req.ProjectID)
	if !ok {
		return
	}

	registered, err := h.findRegisteredPlaybooks(dc.conn.ID, projectID, req.Repository, req.Branch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to load registered playbooks"}}})
		return
	}

	playbook, wasCreated, err := h.importOnePlaybook(registered, projectID, dc.conn.ID, req.Repository, req.Branch, req.Path, req.Name, req.SourceMode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": fmt.Sprintf("Failed to register playbook: %v", err)}}})
		return
	}
	if wasCreated {
		// Webhook registration is per-repository: once per request, not per loop.
		h.maybeRegisterADOWebhook(&dc.conn.ID, req.Repository)
	}

	status := http.StatusOK
	if wasCreated {
		status = http.StatusCreated
	}
	c.JSON(status, gin.H{"data": formatPlaybookResponse(playbook), "meta": gin.H{"created": wasCreated}})
}

// resolveProjectForOrg parses and validates an optional project ID against the
// org, falling back to the org's first project (the same default the create
// endpoint uses). Writes the error response and returns false on failure.
func (h *PlaybookHandler) resolveProjectForOrg(c *gin.Context, org *models.Organization, projectIDStr string) (uuid.UUID, bool) {
	if projectIDStr != "" {
		pid, err := uuid.Parse(projectIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid project ID"}}})
			return uuid.Nil, false
		}
		project, err := h.projectRepo.GetByID(pid)
		if err != nil || project.OrganizationID != org.ID {
			c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Project not found or does not belong to this organization"}}})
			return uuid.Nil, false
		}
		return pid, true
	}
	projects, _, err := h.projectRepo.ListByOrganization(org.ID, 1, 0)
	if err != nil || len(projects) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Organization must have at least one project to create playbooks"}}})
		return uuid.Nil, false
	}
	return projects[0].ID, true
}
