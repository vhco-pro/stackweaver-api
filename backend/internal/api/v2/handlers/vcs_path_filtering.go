// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
)

// Path filtering decides which workspaces a VCS change queues runs for. Four workspace
// settings feed the decision, mirroring the TFE contract:
//
//   - file_triggers_enabled - when false, every change triggers a run and all of the
//     path settings below are ignored.
//   - trigger_patterns      - glob patterns, relative to the repository root. When set
//     they are the only thing consulted; the working directory is NOT monitored too.
//     Mutually exclusive with trigger_prefixes (rejected at the API boundary).
//   - trigger_prefixes      - directory paths relative to the repository root, monitored
//     alongside the working directory.
//   - working_directory     - the fallback when neither list is set. Empty (or "/") means
//     the repository root, which matches any change.
//
// Everything routes through isWorkspaceAffectedByFiles so a GitHub push, a GitHub pull
// request and an Azure DevOps delivery reach the same verdict for the same change - the
// two implementations used to disagree about root-level workspaces (#678).

// isWorkspaceAffected checks whether a workspace is affected by the files touched by a
// set of push commits. It flattens the commits and defers to isWorkspaceAffectedByFiles
// so the push path cannot drift from the pull-request and Azure DevOps paths.
func (h *VCSAppInstallationHandlerV2) isWorkspaceAffected(workspace models.Workspace, commits []struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Modified []string `json:"modified"`
},
) bool {
	allChangedFiles := make(map[string]bool)
	for _, commit := range commits {
		for _, file := range commit.Added {
			allChangedFiles[file] = true
		}
		for _, file := range commit.Modified {
			allChangedFiles[file] = true
		}
		for _, file := range commit.Removed {
			allChangedFiles[file] = true
		}
	}

	return h.isWorkspaceAffectedByFiles(workspace, getKeys(allChangedFiles))
}

// isWorkspaceAffectedByFiles checks whether a workspace is affected by a list of changed
// file paths, applying the trigger settings documented above.
func (h *VCSAppInstallationHandlerV2) isWorkspaceAffectedByFiles(workspace models.Workspace, changedFiles []string) bool {
	// "Always trigger runs": the working directory and both trigger lists are ignored.
	if !workspace.FileTriggersEnabled {
		logger.Infof("Workspace %s - file triggers disabled, matching all changes", workspace.ID)
		return true
	}

	if patterns := decodeTriggerList(workspace.TriggerPatterns); len(patterns) > 0 {
		return workspaceMatchesPatterns(workspace, changedFiles, patterns)
	}

	prefixes := decodeTriggerList(workspace.TriggerPrefixes)

	// Monitored directories: the working directory plus every configured prefix. A root
	// entry ("" or "/") in either position means the whole repository is monitored.
	monitored := make([]string, 0, len(prefixes)+1)
	workingDir := normalizeRepoPath(workspace.WorkingDirectory)
	if workingDir != "" {
		monitored = append(monitored, workingDir)
	} else if len(prefixes) == 0 {
		// Root-level workspace with no prefixes: any change in the repository counts.
		logger.Infof("Workspace %s - working directory is empty/root, matching all changes", workspace.ID)
		return len(changedFiles) > 0
	}
	for _, prefix := range prefixes {
		normalized := normalizeRepoPath(prefix)
		if normalized == "" {
			logger.Infof("Workspace %s - trigger prefix %q is the repository root, matching all changes", workspace.ID, prefix)
			return len(changedFiles) > 0
		}
		monitored = append(monitored, normalized)
	}

	// A file counts when it is one of the monitored paths or sits underneath one, so
	// "infra/prod" matches "infra/prod/main.tf" but not "infra/production/main.tf".
	for _, file := range changedFiles {
		normalizedFile := normalizeRepoPath(file)
		for _, dir := range monitored {
			if normalizedFile == dir || strings.HasPrefix(normalizedFile, dir+"/") {
				logger.Infof("Workspace %s - file %q matches monitored path %q", workspace.ID, file, dir)
				return true
			}
		}
	}

	logger.Infof("Workspace %s - no files match monitored paths %v", workspace.ID, monitored)
	return false
}

// workspaceMatchesPatterns reports whether any changed file matches any trigger pattern.
// Patterns are compiled once per call rather than once per file.
func workspaceMatchesPatterns(workspace models.Workspace, changedFiles []string, patterns []string) bool {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := compileTriggerPattern(pattern)
		if err != nil {
			// A pattern that cannot be compiled is skipped rather than treated as a
			// match-all, so a typo cannot silently queue runs for every change.
			logger.Warnf("Workspace %s - ignoring invalid trigger pattern %q: %v", workspace.ID, pattern, err)
			continue
		}
		compiled = append(compiled, re)
	}

	for _, file := range changedFiles {
		normalizedFile := normalizeRepoPath(file)
		for i, re := range compiled {
			if re.MatchString(normalizedFile) {
				logger.Infof("Workspace %s - file %q matches trigger pattern %q", workspace.ID, file, patterns[i])
				return true
			}
		}
	}

	logger.Infof("Workspace %s - no files match trigger patterns %v", workspace.ID, patterns)
	return false
}

// compileTriggerPattern translates a TFE-style glob into an anchored regular expression:
// "**" spans directory separators, "*" and "?" stay within a single path segment, and a
// trailing "/" means "everything under this directory". Go's regexp is RE2, so the result
// is linear-time no matter how many wildcards a pattern stacks.
func compileTriggerPattern(pattern string) (*regexp.Regexp, error) {
	raw := strings.TrimSpace(pattern)
	glob := normalizeRepoPath(raw)
	if glob != "" && strings.HasSuffix(raw, "/") {
		// A pattern written as a directory means everything underneath it.
		glob += "/**"
	}

	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				// "**/" also matches zero directories, so "**/*.tf" covers "main.tf".
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")

	return regexp.Compile(b.String())
}

// decodeTriggerList reads one of the JSON-array trigger columns, dropping blank entries.
// A column that is empty or malformed yields no entries, which leaves the workspace on
// its working-directory behaviour.
func decodeTriggerList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		logger.Warnf("Ignoring malformed trigger list %q: %v", raw, err)
		return nil
	}

	cleaned := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry) != "" {
			cleaned = append(cleaned, entry)
		}
	}
	return cleaned
}

// normalizeRepoPath strips surrounding whitespace and any leading or trailing slash so
// repository paths, working directories and trigger entries all compare on the same
// footing. The repository root - "", "/" or blank - normalizes to "".
func normalizeRepoPath(path string) string {
	trimmed := strings.TrimSpace(path)
	trimmed = strings.TrimPrefix(trimmed, "/")
	return strings.TrimSuffix(trimmed, "/")
}
