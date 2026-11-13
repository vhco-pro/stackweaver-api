// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/executor/cachedesc"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/settings"
)

// The cache descriptor (#933, D7): the entries of a job's organization's cache that the job's
// configuration names, by digest. The launcher prepares its read-only node-local copy from it and
// the executor reads each entry, verified, from that copy or its blob route. Nothing of another
// organization's cache is ever named.

// maxDescriptorFileBytes bounds the lock or requirements file a descriptor is read from.
const maxDescriptorFileBytes = 1 << 20

// maxDescriptorSnapshotBytes bounds the playbook snapshot scanned for its requirements.
const maxDescriptorSnapshotBytes = 256 << 20

var gitCommitPin = regexp.MustCompile(`^[0-9a-f]{40}$`)

// gitCommitsPerSource bounds how many cached commits of one git source on a branch or tag a job
// is named: its ref most likely resolves to one of the newest.
const gitCommitsPerSource = 3

// descriptor builds the descriptor of entries for jobID; nil when there are none.
func descriptor(org uuid.UUID, jobID string, entries []models.CacheEntry) *runnercontract.CacheDescriptor {
	if len(entries) == 0 {
		return nil
	}
	d := &runnercontract.CacheDescriptor{OrganizationID: org.String()}
	seen := map[string]bool{}
	for _, e := range entries {
		key := e.Kind + "/" + e.SHA256
		if seen[key] {
			continue
		}
		seen[key] = true
		d.Entries = append(d.Entries, runnercontract.CacheEntryRef{
			CacheEntry: runnercontract.CacheEntry{
				Kind: runnercontract.CacheKind(e.Kind), Name: e.Name, Version: e.Version, Platform: e.Platform,
				SHA256: e.SHA256, SizeBytes: e.SizeBytes,
			},
			Path: "/api/v2/runner/jobs/" + jobID + "/blob/cache/" + e.Kind + "/" + e.SHA256,
		})
	}
	return d
}

// runCacheDescriptor resolves a run's entries: the tofu release of its version, and the provider
// packages its dependency lock file pins, matched by name, version and zh: digest.
func (h *RunnerAgentHandler) runCacheDescriptor(org uuid.UUID, run *models.Run, version string, tarball []byte) *runnercontract.CacheDescriptor {
	var entries []models.CacheEntry
	if version != "" {
		var tofu []models.CacheEntry
		if err := h.db.Where("organization_id = ? AND kind = ? AND name = ? AND version = ?", org, runnercontract.CacheKindTofu, "tofu", version).Find(&tofu).Error; err != nil {
			logger.Warnf("Reading the tofu cache entries of run %s: %v", run.ID, err)
		}
		entries = append(entries, tofu...)
	}
	if len(tarball) > 0 {
		dir := strings.Trim(run.Workspace.WorkingDirectory, "/")
		lockPath := path.Join(dir, cachedesc.LockFileName)
		data, _, err := cachedesc.FindInTarGz(bytes.NewReader(tarball), []string{lockPath}, maxDescriptorFileBytes)
		if err == nil && data != nil {
			providers, err := cachedesc.ParseLockFile(data)
			if err != nil {
				logger.Warnf("Run %s: %v", run.ID, err)
			}
			for _, p := range providers {
				zh := p.ZipHashes()
				if p.Version == "" || len(zh) == 0 {
					continue
				}
				var found []models.CacheEntry
				if err := h.db.Where("organization_id = ? AND kind = ? AND name = ? AND version = ? AND sha256 IN ?", org, runnercontract.CacheKindProvider, p.Source, p.Version, zh).Find(&found).Error; err != nil {
					logger.Warnf("Reading the provider cache entries of run %s: %v", run.ID, err)
				}
				entries = append(entries, found...)
			}
		}
	}
	return descriptor(org, run.ID, entries)
}

// runCacheDescriptorFor reads a run's version and configuration and resolves its descriptor, for
// the job token, which has neither at hand.
func (h *RunnerAgentHandler) runCacheDescriptorFor(ctx context.Context, run *models.Run) *runnercontract.CacheDescriptor {
	version := settings.EffectiveTofuVersion(&run.Workspace, repository.InstallationTofuVersion(h.db))
	var tarball []byte
	if run.ConfigurationVersionID != nil && h.storageClient != nil {
		if data, err := h.configTarball(ctx, run); err == nil {
			tarball = data
		}
	}
	return h.runCacheDescriptor(run.Workspace.Project.OrganizationID, run, version.Value, tarball)
}

// ansibleCacheDescriptor resolves an Ansible job's entries from the Galaxy requirements of its
// playbook's snapshot: a pinned collection or role at that version, an unpinned one at the newest
// version the organization caches, and a git source at its pinned commit or, on a branch or tag,
// at the repository's newest cached commits. A
// playbook cloned fresh for each job has no snapshot to read, so it gets no descriptor.
func (h *RunnerAgentHandler) ansibleCacheDescriptor(ctx context.Context, org uuid.UUID, job *models.AnsibleJob) *runnercontract.CacheDescriptor {
	if job.PlaybookID == nil || h.playbookRepo == nil || h.storageClient == nil {
		return nil
	}
	// An organization that caches no Ansible content has nothing to name: its snapshot is not read.
	var cached int64
	if err := h.db.Model(&models.CacheEntry{}).
		Where("organization_id = ? AND kind IN ?", org, []runnercontract.CacheKind{runnercontract.CacheKindCollection, runnercontract.CacheKindRole, runnercontract.CacheKindGit}).
		Limit(1).Count(&cached).Error; err != nil || cached == 0 {
		return nil
	}
	playbook, err := h.playbookRepo.GetByID(*job.PlaybookID)
	if err != nil || playbook.CachedAt == nil || playbookSourceMode(playbook) == models.PlaybookSourceModeFresh {
		return nil
	}
	stream, err := h.storageClient.GetStream(ctx, ansible.PlaybookSnapshotKey(playbook.ID))
	if err != nil {
		return nil
	}
	defer func() { _ = stream.Close() }()
	data, _, err := cachedesc.FindInTarGz(limitReader(stream, maxDescriptorSnapshotBytes), cachedesc.RequirementsFiles, maxDescriptorFileBytes)
	if err != nil || data == nil {
		return nil
	}
	reqs, err := cachedesc.ParseRequirements(data)
	if err != nil {
		logger.Warnf("Job %s: %v", job.ID, err)
		return nil
	}
	var entries []models.CacheEntry
	add := func(kind runnercontract.CacheKind, r cachedesc.Requirement) {
		q := h.db.Where("organization_id = ? AND kind = ?", org, kind)
		switch {
		case !r.Galaxy():
			if r.Type != "git" || kind != runnercontract.CacheKindCollection {
				return
			}
			// A git source is cached by its repository and commit. A pinned commit names that
			// entry; a branch, a tag or the default branch moves, so the repository's newest
			// cached commits are named and the executor takes the one the ref resolves to.
			repo, _ := cachedesc.GitSource(r.Name)
			git := h.db.Where("organization_id = ? AND kind = ? AND name = ?", org, runnercontract.CacheKindGit, repo)
			if gitCommitPin.MatchString(r.Version) {
				git = git.Where("version = ?", r.Version)
			}
			var found []models.CacheEntry
			if err := git.Order("created_at DESC").Limit(gitCommitsPerSource).Find(&found).Error; err == nil {
				entries = append(entries, found...)
			}
			return
		case kind == runnercontract.CacheKindRole && r.Version != "":
			// A role entry's version is the tag and the commit it resolved to.
			q = q.Where("name = ? AND version LIKE ?", r.Name, escapeLike(r.Version)+"@%")
		case r.Pinned():
			q = q.Where("name = ? AND version = ?", r.Name, strings.TrimPrefix(r.Version, "="))
		default:
			q = q.Where("name = ?", r.Name)
		}
		var e models.CacheEntry
		if err := q.Order("created_at DESC").First(&e).Error; err == nil {
			entries = append(entries, e)
		}
	}
	for _, r := range reqs.Collections {
		add(runnercontract.CacheKindCollection, r)
	}
	for _, r := range reqs.Roles {
		add(runnercontract.CacheKindRole, r)
	}
	return descriptor(org, job.ID.String(), entries)
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// limitReader cuts r after n bytes with an error, so a descriptor never reads an unbounded body.
func limitReader(r interface{ Read([]byte) (int, error) }, n int64) *boundedReader {
	return &boundedReader{r: r, left: n}
}

type boundedReader struct {
	r    interface{ Read([]byte) (int, error) }
	left int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, fmt.Errorf("the snapshot is larger than %d bytes", maxDescriptorSnapshotBytes)
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}
