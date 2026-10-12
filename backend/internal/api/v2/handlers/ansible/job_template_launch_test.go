// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Launching a job template takes an optional JSON:API document whose attributes replace the
// template's own values for that one launch: `extra-vars` (merged over the template's, key by
// key), `limit`, `tags` and `skip-tags`. No body, or a body that carries nothing, launches with
// the template's values. A body that cannot be read as that document is a 400 and launches
// nothing.
//
// The defect this test was written against (#890): the launch dialog sent a flat
// {extra_vars, limit, tags, skip_tags} body, the handler bound a document and threw the bind
// error away, and the request struct carried `extra-vars` only. Every override the dialog offered
// was dropped and the job ran with the template's values, with a 201 either way.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestLaunchFromTemplate

//go:build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
)

func TestLaunchFromTemplate_OverridesReachTheJob(t *testing.T) {
	// Org A with an owner and a job template (playbook plus inventory); cleans up after itself.
	f := setupAnsibleSubResourceAuthz(t)
	db := f.db
	if err := db.AutoMigrate(&models.AnsibleJob{}); err != nil {
		t.Fatalf("migrating ansible jobs: %v", err)
	}
	templateID := uuid.MustParse(f.templateID)

	// The template's own values, which a launch without overrides must carry. Simultaneous runs
	// are allowed so that one case's pending job does not hold the next one's.
	if err := db.Model(&models.AnsibleJobTemplate{}).Where("id = ?", templateID).Updates(map[string]any{
		"limit":              "template-limit",
		"tags":               "template-tag",
		"skip_tags":          "template-skip",
		"extra_vars":         models.InventoryVariables{"from_template": "yes", "shared": "template"},
		"allow_simultaneous": true,
	}).Error; err != nil {
		t.Fatalf("setting the template's values: %v", err)
	}
	// Registered after the fixture's cleanup, so it runs before it: the jobs go before the
	// template they point at.
	t.Cleanup(func() {
		db.Where("template_id = ?", templateID).Delete(&models.AnsibleJob{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	templateRepo := repository.NewAnsibleJobTemplateRepository(db)
	// No queue: a launch stores the job and dispatches nothing.
	jobService := ansiblesvc.NewJobService(
		repository.NewAnsibleJobRepository(db),
		repository.NewAnsiblePlaybookRepository(db),
		f.inventoryRepo,
		templateRepo,
		projectRepo,
		nil,
	)
	h := NewJobHandler(
		jobService, projectRepo, orgRepo, templateRepo,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo),
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/ansible/job-templates/:id/launch", h.LaunchFromTemplate)
	router.GET("/api/v2/ansible/jobs/:id", h.Get)

	launchPath := "/api/v2/ansible/job-templates/" + f.templateID + "/launch"
	jobCount := func(t *testing.T) int64 {
		t.Helper()
		var n int64
		if err := db.Model(&models.AnsibleJob{}).Where("template_id = ?", templateID).Count(&n).Error; err != nil {
			t.Fatalf("counting the template's jobs: %v", err)
		}
		return n
	}

	// launchedJob is what a launch stored, as the job endpoint reads it back.
	type launchedJob struct {
		Limit     string
		Tags      string
		SkipTags  string
		ExtraVars map[string]any
	}
	templateVars := map[string]any{"from_template": "yes", "shared": "template"}
	templateValues := launchedJob{
		Limit: "template-limit", Tags: "template-tag", SkipTags: "template-skip", ExtraVars: templateVars,
	}

	document := func(t *testing.T, attrs map[string]any) string {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "ansible-jobs", "attributes": attrs}})
		if err != nil {
			t.Fatalf("marshalling the launch document: %v", err)
		}
		return string(raw)
	}

	accepted := []struct {
		name string
		body string
		want launchedJob
	}{
		{"no body", "", templateValues},
		{"a body of whitespace", " \n", templateValues},
		{"an empty object", "{}", templateValues},
		{"a document with no attributes", `{"data":{"type":"ansible-jobs"}}`, templateValues},
		{
			"extra-vars are merged over the template's",
			document(t, map[string]any{"extra-vars": map[string]any{"shared": "launch", "from_launch": "yes"}}),
			launchedJob{
				Limit: "template-limit", Tags: "template-tag", SkipTags: "template-skip",
				ExtraVars: map[string]any{"from_template": "yes", "shared": "launch", "from_launch": "yes"},
			},
		},
		{
			"limit",
			document(t, map[string]any{"limit": "web:&production"}),
			launchedJob{Limit: "web:&production", Tags: "template-tag", SkipTags: "template-skip", ExtraVars: templateVars},
		},
		{
			"tags",
			document(t, map[string]any{"tags": "deploy,config"}),
			launchedJob{Limit: "template-limit", Tags: "deploy,config", SkipTags: "template-skip", ExtraVars: templateVars},
		},
		{
			"skip-tags",
			document(t, map[string]any{"skip-tags": "slow"}),
			launchedJob{Limit: "template-limit", Tags: "template-tag", SkipTags: "slow", ExtraVars: templateVars},
		},
		{
			"every override at once",
			document(t, map[string]any{
				"extra-vars": map[string]any{"from_launch": "yes"},
				"limit":      "db",
				"tags":       "migrate",
				"skip-tags":  "backup",
			}),
			launchedJob{
				Limit: "db", Tags: "migrate", SkipTags: "backup",
				ExtraVars: map[string]any{"from_template": "yes", "shared": "template", "from_launch": "yes"},
			},
		},
		{
			// An attribute that is present replaces the template's value even when it is empty:
			// that is how one launch runs without the limit the template carries.
			"explicit empty strings clear the template's values",
			document(t, map[string]any{"limit": "", "tags": "", "skip-tags": ""}),
			launchedJob{ExtraVars: templateVars},
		},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			code, body := storedAsSentCall(t, router, http.MethodPost, launchPath, f.owner.ID, tc.body)
			if code != http.StatusCreated {
				t.Fatalf("launch = %d, want 201 (%s)", code, body)
			}
			var created struct {
				Data storedAsSentResource `json:"data"`
			}
			if err := json.Unmarshal(body, &created); err != nil {
				t.Fatalf("decoding the launch response: %v\n%s", err, body)
			}

			code, body = storedAsSentCall(t, router, http.MethodGet, "/api/v2/ansible/jobs/"+created.Data.ID, f.owner.ID, "")
			if code != http.StatusOK {
				t.Fatalf("reading the job back = %d, want 200 (%s)", code, body)
			}
			var read struct {
				Data storedAsSentResource `json:"data"`
			}
			if err := json.Unmarshal(body, &read); err != nil {
				t.Fatalf("decoding the job: %v\n%s", err, body)
			}

			for where, attrs := range map[string]map[string]any{"launch response": created.Data.Attributes, "read back": read.Data.Attributes} {
				got := launchedJob{}
				got.Limit, _ = attrs["limit"].(string)
				got.Tags, _ = attrs["tags"].(string)
				got.SkipTags, _ = attrs["skip-tags"].(string)
				got.ExtraVars, _ = attrs["extra-vars"].(map[string]any)
				if !reflect.DeepEqual(got, tc.want) {
					t.Errorf("%s: the job does not carry what the launch asked for\n got: %+v\nwant: %+v", where, got, tc.want)
				}
			}
		})
	}

	refused := []struct {
		name       string
		body       string
		wantDetail string // a substring of errors[0].detail
	}{
		{"a body that is not JSON", `{"data":`, "unexpected"},
		{"a body that is not an object", `[]`, "request body must be a JSON:API document"},
		{
			"the flat body the launch dialog used to send",
			`{"extra_vars":{"from_launch":"yes"},"limit":"web","tags":"deploy","skip_tags":"slow"}`,
			"top-level fields are not accepted",
		},
		{"a flat body with dash-case keys", `{"extra-vars":{"from_launch":"yes"},"limit":"web"}`, "top-level fields are not accepted"},
		{
			"a flat key beside a document",
			`{"limit":"web","data":{"type":"ansible-jobs","attributes":{"limit":"db"}}}`,
			"top-level fields are not accepted",
		},
		{"an object with neither a document nor a known key", `{"verbosity":3}`, "request body must be a JSON:API document"},
		{"a document of another type", `{"data":{"type":"ansible-job-templates","attributes":{"limit":"web"}}}`, `data.type must be "ansible-jobs"`},
		{"a document without a type", `{"data":{"attributes":{"limit":"web"}}}`, `data.type must be "ansible-jobs"`},
		{"an attribute of the wrong JSON type", `{"data":{"type":"ansible-jobs","attributes":{"limit":5}}}`, "limit"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			before := jobCount(t)
			code, body := storedAsSentCall(t, router, http.MethodPost, launchPath, f.owner.ID, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("launch = %d, want 400 (%s)", code, body)
			}
			var doc struct {
				Errors []struct {
					Status string `json:"status"`
					Title  string `json:"title"`
					Detail string `json:"detail"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(body, &doc); err != nil || len(doc.Errors) != 1 {
				t.Fatalf("the response is not a JSON:API errors document with one error: %v\n%s", err, body)
			}
			if got := doc.Errors[0]; got.Status != "400" || got.Title != "Bad Request" || !strings.Contains(got.Detail, tc.wantDetail) {
				t.Errorf("error = %+v, want status 400, title Bad Request and a detail containing %q", got, tc.wantDetail)
			}
			if after := jobCount(t); after != before {
				t.Errorf("a refused launch created %d job(s)", after-before)
			}
		})
	}

	// A sliced template fans one launch out into several jobs, and the response is only the
	// first of them. Last, because it changes the template.
	t.Run("every slice of a sliced launch carries the overrides", func(t *testing.T) {
		if err := db.Model(&models.AnsibleJobTemplate{}).Where("id = ?", templateID).Update("job_slice_count", 3).Error; err != nil {
			t.Fatalf("slicing the template: %v", err)
		}
		code, body := storedAsSentCall(t, router, http.MethodPost, launchPath, f.owner.ID,
			document(t, map[string]any{"limit": "canary", "extra-vars": map[string]any{"from_launch": "yes"}}))
		if code != http.StatusCreated {
			t.Fatalf("launch = %d, want 201 (%s)", code, body)
		}
		var created struct {
			Data storedAsSentResource `json:"data"`
		}
		if err := json.Unmarshal(body, &created); err != nil {
			t.Fatalf("decoding the launch response: %v\n%s", err, body)
		}
		group, _ := created.Data.Attributes["slice-group-id"].(string)
		if group == "" {
			t.Fatalf("the launch response names no slice group: %s", body)
		}
		var slices []models.AnsibleJob
		if err := db.Where("slice_group_id = ?", group).Find(&slices).Error; err != nil {
			t.Fatalf("reading the slices back: %v", err)
		}
		if len(slices) != 3 {
			t.Fatalf("the launch created %d slice(s), want 3", len(slices))
		}
		for _, slice := range slices {
			if slice.Limit != "canary" || slice.Tags != "template-tag" || slice.ExtraVars["from_launch"] != "yes" {
				t.Errorf("slice %d/%d: limit %q, tags %q, extra vars %v; want limit canary, tags template-tag and from_launch among the vars",
					slice.SliceNumber, slice.SliceCount, slice.Limit, slice.Tags, slice.ExtraVars)
			}
		}
	})
}
