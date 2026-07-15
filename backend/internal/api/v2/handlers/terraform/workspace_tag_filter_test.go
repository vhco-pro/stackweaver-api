// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
)

// eff builds an effective-tag slice from key=value pairs for the matcher tests.
func eff(pairs ...[2]string) []models.TagBinding {
	out := make([]models.TagBinding, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, models.TagBinding{Key: p[0], Value: p[1]})
	}
	return out
}

// TestWsTagFilterMatches covers the data.tfe_workspace_ids filter semantics: include-by-key
// (search[tags]), include-by-key=value (filter[tagged]), and exclude-by-key (search[exclude-tags]),
// all AND-combined.
func TestWsTagFilterMatches(t *testing.T) {
	tests := []struct {
		name   string
		filter wsTagFilter
		tags   []models.TagBinding
		want   bool
	}{
		{"no filter matches anything", wsTagFilter{}, eff([2]string{"env", "prod"}), true},
		{"include key present", wsTagFilter{includeKeys: []string{"env"}}, eff([2]string{"env", "prod"}), true},
		{"include key absent", wsTagFilter{includeKeys: []string{"team"}}, eff([2]string{"env", "prod"}), false},
		{"include pair exact match", wsTagFilter{includePairs: eff([2]string{"env", "prod"})}, eff([2]string{"env", "prod"}), true},
		{"include pair value mismatch", wsTagFilter{includePairs: eff([2]string{"env", "prod"})}, eff([2]string{"env", "dev"}), false},
		{"exclude key present drops", wsTagFilter{excludeKeys: []string{"env"}}, eff([2]string{"env", "prod"}), false},
		{"exclude key absent keeps", wsTagFilter{excludeKeys: []string{"team"}}, eff([2]string{"env", "prod"}), true},
		{
			"include + exclude combined",
			wsTagFilter{includePairs: eff([2]string{"env", "prod"}), excludeKeys: []string{"secret"}},
			eff([2]string{"env", "prod"}, [2]string{"team", "platform"}),
			true,
		},
		{
			"all include pairs required (AND)",
			wsTagFilter{includePairs: eff([2]string{"env", "prod"}, [2]string{"team", "platform"})},
			eff([2]string{"env", "prod"}),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.matches(tt.tags); got != tt.want {
				t.Fatalf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWsParseTagFilter covers query-param parsing of the three filter forms.
func TestWsParseTagFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/?search[tags]=env,+team+&search[exclude-tags]=secret&filter[tagged][0][key]=env&filter[tagged][0][value]=prod&filter[tagged][1][key]=team&filter[tagged][1][value]=platform", nil)

	f := wsParseTagFilter(c)
	if len(f.includeKeys) != 2 || f.includeKeys[0] != "env" || f.includeKeys[1] != "team" {
		t.Fatalf("includeKeys = %v, want [env team] (trimmed)", f.includeKeys)
	}
	if len(f.excludeKeys) != 1 || f.excludeKeys[0] != "secret" {
		t.Fatalf("excludeKeys = %v, want [secret]", f.excludeKeys)
	}
	if len(f.includePairs) != 2 || f.includePairs[0].Key != "env" || f.includePairs[0].Value != "prod" || f.includePairs[1].Key != "team" {
		t.Fatalf("includePairs = %+v, want env=prod, team=platform", f.includePairs)
	}
	if !f.active() {
		t.Fatal("active() = false, want true")
	}
}
