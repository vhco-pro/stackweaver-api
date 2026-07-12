// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package pagination

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func ctxWithQuery(rawQuery string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/?"+rawQuery, nil)
	c.Request = req
	return c
}

func TestParse(t *testing.T) {
	cases := []struct {
		name        string
		query       string
		wantPage    int
		wantPerPage int
	}{
		{"tfe form", "page[number]=3&page[size]=50", 3, 50},
		{"legacy form", "page=2&per_page=25", 2, 25},
		{"tfe wins over legacy", "page[number]=4&page[size]=40&page=1&per_page=10", 4, 40},
		{"defaults when absent", "", 1, 20},
		{"ignores zero/negative", "page[number]=0&page[size]=-5", 1, 20},
		{"ignores garbage", "page[number]=abc&page[size]=xyz", 1, 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, perPage := Parse(ctxWithQuery(tc.query), 20)
			if page != tc.wantPage || perPage != tc.wantPerPage {
				t.Errorf("Parse(%q) = (%d,%d), want (%d,%d)", tc.query, page, perPage, tc.wantPage, tc.wantPerPage)
			}
		})
	}
}
