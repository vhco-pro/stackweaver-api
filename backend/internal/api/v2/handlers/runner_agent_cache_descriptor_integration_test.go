// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the cache descriptor (#933, D7, AC33): the job token a launcher mints and
// the artifacts its executor fetches name the entries of the job's organization's cache that the
// run's OpenTofu version and dependency lock file, or the job's Galaxy requirements, resolve to, and
// nothing of another organization's cache.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestCacheDescriptor

//go:build integration

package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/tofu"
)

func gzTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// seedNamedCacheEntry stores an entry with its name and version.
func (f *agentPrepFixture) seedNamedCacheEntry(t *testing.T, store *snapshotStore, org uuid.UUID, kind, name, version, platform string, content []byte, created time.Time) *models.CacheEntry {
	t.Helper()
	e := f.seedCacheEntry(t, store, org, kind, content)
	if err := f.db.Model(&models.CacheEntry{}).Where("id = ?", e.ID).Updates(map[string]any{"name": name, "version": version, "platform": platform, "created_at": created}).Error; err != nil {
		t.Fatal(err)
	}
	e.Name, e.Version, e.Platform = name, version, platform
	return e
}

func descriptorShas(d *runnercontract.CacheDescriptor) []string {
	if d == nil {
		return nil
	}
	var out []string
	for _, e := range d.Entries {
		out = append(out, e.SHA256)
	}
	slices.Sort(out)
	return out
}

func TestCacheDescriptor_RunResolvesItsVersionAndLockFile(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.cacheRouter(store)
	orgB := *f.runnerB1.OrganizationID
	now := time.Now()

	nullZip := []byte("null 3.2.4 linux_amd64")
	tofuZip := f.seedNamedCacheEntry(t, store, f.orgA, "tofu", "tofu", "1.10.6", "linux_amd64", []byte("tofu 1.10.6 linux"), now)
	f.seedNamedCacheEntry(t, store, f.orgA, "tofu", "tofu", "1.9.0", "linux_amd64", []byte("tofu 1.9.0 linux"), now)
	locked := f.seedNamedCacheEntry(t, store, f.orgA, "provider", "registry.opentofu.org/hashicorp/null", "3.2.4", "linux_amd64", nullZip, now)
	// The same name and version, but a digest the lock file does not pin: never named.
	f.seedNamedCacheEntry(t, store, f.orgA, "provider", "registry.opentofu.org/hashicorp/null", "3.2.4", "darwin_arm64", []byte("unlocked"), now)
	// Organization B holds the run's exact entries; none of them is named.
	f.seedNamedCacheEntry(t, store, orgB, "tofu", "tofu", "1.10.6", "linux_amd64", []byte("tofu 1.10.6 linux, B"), now)

	lock := `provider "registry.opentofu.org/hashicorp/null" {
  version = "3.2.4"
  hashes = ["zh:` + sha256Hex(nullZip) + `"]
}
`
	run := f.seedRunWithConfig(t, store, gzTar(t, map[string]string{"main.tf": "", "envs/prod/.terraform.lock.hcl": lock}))
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", run.WorkspaceID).Updates(map[string]any{"tofu_version": "1.10.6", "working_directory": "envs/prod"}).Error; err != nil {
		t.Fatal(err)
	}
	code, tok := f.mintJobToken(t, r, svc, "a1", run.ID, "job")
	if code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	want := []string{tofuZip.SHA256, locked.SHA256}
	slices.Sort(want)
	if tok.Cache == nil || tok.Cache.OrganizationID != f.orgA.String() || !slices.Equal(descriptorShas(tok.Cache), want) {
		t.Fatalf("the job token's cache descriptor = %+v, want %v", tok.Cache, want)
	}
	for _, e := range tok.Cache.Entries {
		if e.Path != "/api/v2/runner/jobs/"+run.ID+"/blob/cache/"+string(e.Kind)+"/"+e.SHA256 {
			t.Errorf("entry path = %s", e.Path)
		}
	}

	rec := cacheDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("artifacts: %d %s", rec.Code, rec.Body.String())
	}
	var arts runnercontract.TofuArtifacts
	_ = json.Unmarshal(rec.Body.Bytes(), &arts)
	if !slices.Equal(descriptorShas(arts.Cache), want) {
		t.Errorf("the artifacts' cache descriptor = %+v, want %v", arts.Cache, want)
	}
}

// A run whose workspace, project and organization pin no OpenTofu version runs the installation
// default (the version the job image bakes when TOFU_DEFAULT_VERSION is unset), and its artifacts
// and descriptor name that version, whatever newer releases the organization caches (#1069, D2).
// Before #1069 such a run took the newest stable release the organization cached (#933, D7); that
// fallback is gone, because the deployment level always resolves.
func TestCacheDescriptor_UnpinnedRunTakesTheInstallationDefault(t *testing.T) {
	t.Setenv(settings.EnvTofuDefaultVersion, "")
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.cacheRouter(store)
	now := time.Now()
	f.seedNamedCacheEntry(t, store, f.orgA, "tofu", "tofu", "1.99.6", "linux_amd64", []byte("tofu 1.99.6, newest"), now.Add(-time.Hour))
	bundled := f.seedNamedCacheEntry(t, store, f.orgA, "tofu", "tofu", tofu.BundledVersion, "linux_amd64", []byte("tofu bundled"), now)

	run := f.seedRunWithConfig(t, store, gzTar(t, map[string]string{"main.tf": ""}))
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", run.WorkspaceID).Update("tofu_version", "").Error; err != nil {
		t.Fatal(err)
	}
	code, tok := f.mintJobToken(t, r, svc, "a1", run.ID, "job")
	if code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	if got := descriptorShas(tok.Cache); !slices.Equal(got, []string{bundled.SHA256}) {
		t.Fatalf("the job token's cache descriptor = %v, want the bundled release alone", got)
	}
	rec := cacheDo(t, r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/artifacts", nil)
	var arts runnercontract.TofuArtifacts
	_ = json.Unmarshal(rec.Body.Bytes(), &arts)
	if arts.TofuVersion != tofu.BundledVersion || !slices.Equal(descriptorShas(arts.Cache), []string{bundled.SHA256}) {
		t.Errorf("artifacts = version %q, cache %v; want %s and its entry", arts.TofuVersion, descriptorShas(arts.Cache), tofu.BundledVersion)
	}
}

func TestCacheDescriptor_AnsibleJobResolvesItsRequirements(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.cacheRouter(store)
	old, newer := time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)

	posix := f.seedNamedCacheEntry(t, store, f.orgA, "collection", "ansible.posix", "2.2.2", "", []byte("posix 2.2.2"), old)
	f.seedNamedCacheEntry(t, store, f.orgA, "collection", "ansible.posix", "2.2.1", "", []byte("posix 2.2.1"), newer)
	f.seedNamedCacheEntry(t, store, f.orgA, "collection", "community.general", "9.3.0", "", []byte("general 9.3.0"), old)
	general := f.seedNamedCacheEntry(t, store, f.orgA, "collection", "community.general", "9.4.0", "", []byte("general 9.4.0"), newer)
	role := f.seedNamedCacheEntry(t, store, f.orgA, "role", "geerlingguy.pip", "3.0.3@0123456789abcdef0123456789abcdef01234567", "", []byte("pip role"), old)
	f.seedNamedCacheEntry(t, store, f.orgA, "collection", "amazon.aws", "8.0.0", "", []byte("not required"), newer)

	now := time.Now()
	pb := f.seedPlaybook(t, playbookSpec{cachedAt: &now, commit: "abc"})
	reqs := "collections:\n  - name: ansible.posix\n    version: 2.2.2\n  - community.general\nroles:\n  - name: geerlingguy.pip\n    version: 3.0.3\n"
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), gzTar(t, map[string]string{"site.yml": "", "collections/requirements.yml": reqs})); err != nil {
		t.Fatal(err)
	}
	job := f.seedJob(t, &pb.ID, f.runnerA1)
	code, tok := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job")
	if code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	want := []string{posix.SHA256, general.SHA256, role.SHA256}
	slices.Sort(want)
	if got := descriptorShas(tok.Cache); !slices.Equal(got, want) {
		t.Errorf("the job's cache descriptor = %+v, want the pinned posix, the newest general and the pinned role", tok.Cache)
	}
}

// A git source names its repository's cached commits: a pinned one exactly, a branch or tag the
// newest few, for the executor to match against the commit the ref resolves to when the job runs
// (#933, D7: keyed by the resolved commit). The entry is the repository, whatever subdirectory the
// requirement installs from.
func TestCacheDescriptor_AnsibleGitSourcesNameTheirRepositoryCommits(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.cacheRouter(store)
	const repo = "https://github.com/example/c.git"
	const pinned = "0123456789abcdef0123456789abcdef01234567"
	base := time.Now().Add(-48 * time.Hour)
	var branchEntries []*models.CacheEntry
	for i, commit := range []string{"1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "3333333333333333333333333333333333333333", "4444444444444444444444444444444444444444"} {
		e := f.seedNamedCacheEntry(t, store, f.orgA, "git", "https://github.com/example/b.git", commit, "", []byte("b "+commit), base.Add(time.Duration(i)*time.Hour))
		branchEntries = append(branchEntries, e)
	}
	exact := f.seedNamedCacheEntry(t, store, f.orgA, "git", repo, pinned, "", []byte("c pinned"), base)
	f.seedNamedCacheEntry(t, store, f.orgA, "git", repo, "5555555555555555555555555555555555555555", "", []byte("c other"), base.Add(time.Hour))

	now := time.Now()
	pb := f.seedPlaybook(t, playbookSpec{cachedAt: &now, commit: "abc"})
	reqs := "collections:\n  - name: git+" + repo + "#/collections/c/\n    type: git\n    version: " + pinned + "\n  - name: https://github.com/example/b.git#/b/\n    type: git\n    version: main\n"
	if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), gzTar(t, map[string]string{"site.yml": "", "requirements.yml": reqs})); err != nil {
		t.Fatal(err)
	}
	job := f.seedJob(t, &pb.ID, f.runnerA1)
	code, tok := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job")
	if code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	// The pinned commit, and the branch's three newest cached commits.
	want := []string{exact.SHA256, branchEntries[1].SHA256, branchEntries[2].SHA256, branchEntries[3].SHA256}
	slices.Sort(want)
	if got := descriptorShas(tok.Cache); !slices.Equal(got, want) {
		t.Errorf("the job's cache descriptor = %+v, want the pinned commit of c and the three newest commits of b", tok.Cache)
	}
}

func TestCacheDescriptor_NoEntriesNoDescriptor(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.cacheRouter(store)
	run := f.seedRunWithConfig(t, store, gzTar(t, map[string]string{"main.tf": ""}))
	_, tok := f.mintJobToken(t, r, svc, "a1", run.ID, "job")
	if tok.Cache != nil && len(tok.Cache.Entries) > 0 {
		t.Errorf("a run whose organization caches nothing it needs got %+v", tok.Cache)
	}
}
