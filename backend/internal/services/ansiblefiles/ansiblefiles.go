// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package ansiblefiles classifies the files of an Ansible repository into
// playbook and inventory candidates, so the pickers that offer a repository
// file as a playbook or an inventory show only plausible choices.
//
// Classification is by path convention only (the listing APIs return paths,
// not content). Both filters share one exclusion base: directories that hold
// role internals, variable files, collection or plugin code, tests, and CI or
// editor configuration never hold a playbook or an inventory source. Each
// filter then excludes the other kind's conventional locations and names, so
// a repository that follows the Ansible layout (playbooks/ and inventories/,
// or site.yml next to hosts.yml) no longer offers every YAML file in both.
package ansiblefiles

import (
	"path"
	"sort"
	"strings"
)

// sharedExcludedDirs are directory names that never contain a playbook or an
// inventory source. group_vars and host_vars are loaded relative to an
// inventory (or playbook) but are variable files, never an inventory: Ansible
// itself skips them when an inventory directory is walked.
var sharedExcludedDirs = map[string]struct{}{
	"roles": {}, "group_vars": {}, "host_vars": {}, "vars": {}, "tasks": {},
	"handlers": {}, "templates": {}, "files": {}, "defaults": {}, "meta": {},
	"collections": {}, "molecule": {}, "library": {}, "filter_plugins": {},
	"module_utils": {}, "plugins": {}, "test": {}, "tests": {},
	"node_modules": {},
}

// playbookOnlyExcludedDirs hold inventories, so they are not playbook candidates.
var playbookOnlyExcludedDirs = map[string]struct{}{
	"inventories": {}, "inventory": {},
}

// inventoryOnlyExcludedDirs hold playbooks, so they are not inventory candidates.
var inventoryOnlyExcludedDirs = map[string]struct{}{
	"playbooks": {}, "playbook": {},
}

// sharedExcludedFiles are well-known YAML files that are neither a playbook
// nor an inventory (dependency manifests, CI, tooling configuration).
var sharedExcludedFiles = map[string]struct{}{
	"requirements.yml": {}, "requirements.yaml": {},
	"galaxy.yml": {}, "galaxy.yaml": {},
	"azure-pipelines.yml": {}, "azure-pipelines.yaml": {},
	"mkdocs.yml": {}, "mkdocs.yaml": {},
	"ansible-navigator.yml": {}, "ansible-navigator.yaml": {},
}

// inventoryStems are file names (without extension) that conventionally name
// an inventory, so a YAML file with one of them is not a playbook candidate.
var inventoryStems = map[string]struct{}{
	"hosts": {}, "inventory": {},
}

// inventoryPluginSuffixes are the file-name endings Ansible's cloud inventory
// plugins require of their configuration files (for example `prod.azure_rm.yml`
// or `aws_ec2.yml`). Such a file is an inventory source, never a playbook.
var inventoryPluginSuffixes = []string{"azure_rm", "aws_ec2", "gcp_compute"}

// playbookStems are file names (without extension) that conventionally name
// a top-level playbook, so a YAML file with one of them is not an inventory
// candidate.
var playbookStems = map[string]struct{}{
	"site": {}, "playbook": {},
}

// inventoryExcludedFiles are well-known JSON tooling files that match the
// inventory extensions but are never an inventory.
var inventoryExcludedFiles = map[string]struct{}{
	"package.json": {}, "package-lock.json": {}, "tsconfig.json": {},
	"renovate.json": {}, "composer.json": {},
}

// Playbooks narrows a repository file listing to playbook candidates: YAML
// files under scopePath (when set) outside every conventional non-playbook
// location. The result is sorted.
func Playbooks(paths []string, scopePath string) []string {
	return filter(paths, scopePath, func(p, _, stem, ext string) bool {
		if ext != ".yml" && ext != ".yaml" {
			return false
		}
		if _, ok := inventoryStems[stem]; ok {
			return false
		}
		if isInventoryPluginConfig(stem) {
			return false
		}
		return !inDir(p, playbookOnlyExcludedDirs)
	})
}

// Inventories narrows a repository file listing to inventory candidates:
// the file types `ansible-inventory -i <file>` parses through its ini and
// yaml plugins (.ini, .yml, .yaml, .json) under scopePath (when set), outside
// every conventional non-inventory location. The result is sorted.
func Inventories(paths []string, scopePath string) []string {
	return filter(paths, scopePath, func(p, base, stem, ext string) bool {
		switch ext {
		case ".ini", ".yml", ".yaml", ".json":
		default:
			return false
		}
		if _, ok := inventoryExcludedFiles[base]; ok {
			return false
		}
		if _, ok := playbookStems[stem]; ok {
			return false
		}
		return !inDir(p, inventoryOnlyExcludedDirs)
	})
}

// filter applies the scope, the shared exclusions, and keep to every path.
// keep receives the normalized path and its lower-cased base name, stem, and
// extension.
func filter(paths []string, scopePath string, keep func(p, base, stem, ext string) bool) []string {
	scopePath = strings.Trim(scopePath, "/")
	var out []string
	for _, p := range paths {
		p = strings.TrimPrefix(p, "/")
		if scopePath != "" && p != scopePath && !strings.HasPrefix(p, scopePath+"/") {
			continue
		}
		base := strings.ToLower(path.Base(p))
		if strings.HasPrefix(base, ".") || strings.HasPrefix(base, "docker-compose.") {
			continue
		}
		if _, ok := sharedExcludedFiles[base]; ok {
			continue
		}
		if inHiddenDir(p) || inDir(p, sharedExcludedDirs) {
			continue
		}
		ext := path.Ext(base)
		if !keep(p, base, strings.TrimSuffix(base, ext), ext) {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isInventoryPluginConfig reports whether a file stem names a cloud inventory
// plugin configuration (`azure_rm` or `<anything>.azure_rm`).
func isInventoryPluginConfig(stem string) bool {
	for _, suffix := range inventoryPluginSuffixes {
		if stem == suffix || strings.HasSuffix(stem, "."+suffix) {
			return true
		}
	}
	return false
}

// inDir reports whether any directory segment of p is in dirs.
func inDir(p string, dirs map[string]struct{}) bool {
	dir := path.Dir(p)
	if dir == "." {
		return false
	}
	for seg := range strings.SplitSeq(dir, "/") {
		if _, ok := dirs[strings.ToLower(seg)]; ok {
			return true
		}
	}
	return false
}

// inHiddenDir reports whether any directory segment of p is hidden (.github,
// .gitlab, .vscode, .devcontainer, ...). Hidden directories hold CI and editor
// configuration, never a playbook or an inventory.
func inHiddenDir(p string) bool {
	dir := path.Dir(p)
	if dir == "." {
		return false
	}
	for seg := range strings.SplitSeq(dir, "/") {
		if strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}
