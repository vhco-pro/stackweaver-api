// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Tests for the shared pagination block (#756, AC1).
//
// The boundary cases are ported from TestFullPaginationMeta in
// handlers/terraform/run_tasks.go, which was the only correct implementation in the tree before
// this converged the other eight variants onto it. Its comment recorded why the shorter
// variants are not enough: "a nil next-page terminates its loop".

package jsonapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPaginationMiddlePage(t *testing.T) {
	p := NewPaginationMeta(2, 20, 45).Pagination
	if p.CurrentPage != 2 || p.PageSize != 20 {
		t.Errorf("page/size: got %d/%d, want 2/20", p.CurrentPage, p.PageSize)
	}
	if p.TotalCount == nil || *p.TotalCount != 45 {
		t.Errorf("total-count: got %v, want 45", p.TotalCount)
	}
	if p.TotalPages == nil || *p.TotalPages != 3 {
		t.Errorf("total-pages for 45 items at 20 per page: got %v, want 3 (must round up)", p.TotalPages)
	}
	if p.PrevPage == nil || *p.PrevPage != 1 {
		t.Errorf("prev-page: got %v, want 1", p.PrevPage)
	}
	if p.NextPage == nil || *p.NextPage != 3 {
		t.Errorf("next-page: got %v, want 3", p.NextPage)
	}
}

func TestPaginationBoundaries(t *testing.T) {
	first := NewPaginationMeta(1, 20, 45).Pagination
	if first.PrevPage != nil {
		t.Errorf("prev-page on the first page must be null, got %v", *first.PrevPage)
	}

	last := NewPaginationMeta(3, 20, 45).Pagination
	if last.NextPage != nil {
		t.Errorf("next-page on the last page must be null, got %v", *last.NextPage)
	}
}

// An empty collection must report one page, not zero. A client seeing total-pages of 0 concludes
// there is nothing to fetch and skips the request entirely.
func TestPaginationEmptyCollectionReportsOnePage(t *testing.T) {
	p := NewPaginationMeta(1, 20, 0).Pagination
	if p.TotalPages == nil || *p.TotalPages != 1 {
		t.Errorf("total-pages for an empty collection: got %v, want 1", p.TotalPages)
	}
	if p.PrevPage != nil || p.NextPage != nil {
		t.Errorf("empty collection must have no prev/next: %+v", p)
	}
	if p.TotalCount == nil || *p.TotalCount != 0 {
		t.Errorf("total-count: got %v, want 0", p.TotalCount)
	}
}

// The wire shape is the whole point: go-tfe reads these member names, and null must survive
// rather than the member vanishing.
func TestPaginationSerialisesAllSixMembers(t *testing.T) {
	raw, err := json.Marshal(NewPaginationMeta(1, 20, 0))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Pagination map[string]any `json:"pagination"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, member := range []string{"current-page", "page-size", "prev-page", "next-page", "total-pages", "total-count"} {
		if _, present := doc.Pagination[member]; !present {
			t.Errorf("member %q is missing; go-tfe reads it and an absent member is not the same as null", member)
		}
	}
	if v, present := doc.Pagination["prev-page"]; !present || v != nil {
		t.Errorf("prev-page on page 1 must serialise as null, got %v", v)
	}
	if len(doc.Pagination) != 6 {
		t.Errorf("expected exactly 6 members, got %d: %v", len(doc.Pagination), doc.Pagination)
	}
}

// A zero total-count must survive serialisation. With omitempty it would vanish, and a client
// cannot tell "no results" from "the server did not say".
func TestPaginationZeroTotalIsEmittedNotDropped(t *testing.T) {
	raw, err := json.Marshal(NewPaginationMeta(1, 20, 0))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Pagination struct {
			TotalCount *int64 `json:"total-count"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Pagination.TotalCount == nil {
		t.Error("total-count of zero was dropped; a client reads that as unknown rather than empty")
	}
}

// Defensive: handlers derive page and size from user input, and a zero page size would divide
// by zero in the total-pages calculation.
func TestPaginationClampsNonsenseInput(t *testing.T) {
	p := NewPaginationMeta(0, 0, 10).Pagination
	if p.CurrentPage != 1 || p.PageSize != 1 {
		t.Errorf("expected clamping to 1/1, got %d/%d", p.CurrentPage, p.PageSize)
	}
	if p.TotalPages == nil || *p.TotalPages != 10 {
		t.Errorf("total-pages: got %v, want 10", p.TotalPages)
	}
}

// The totals became pointers so a provider page can say "unknown" (#858, D6). The blocks every
// existing collection emits must not move a byte: the golden corpus pins them.
func TestPaginationPointerTotalsMarshalUnchanged(t *testing.T) {
	tests := []struct {
		name string
		meta PaginationMeta
		want string
	}{
		{"middle page", NewPaginationMeta(2, 20, 45), `{"pagination":{"current-page":2,"page-size":20,"prev-page":1,"next-page":3,"total-pages":3,"total-count":45}}`},
		{"empty collection", NewPaginationMeta(1, 20, 0), `{"pagination":{"current-page":1,"page-size":20,"prev-page":null,"next-page":null,"total-pages":1,"total-count":0}}`},
		{"full page", NewFullPageMeta(4), `{"pagination":{"current-page":1,"page-size":4,"prev-page":null,"next-page":null,"total-pages":1,"total-count":4}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.meta)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != tt.want {
				t.Errorf("got  %s\nwant %s", raw, tt.want)
			}
		})
	}
}

// A provider page states what the server knows: the page it asked for, whether the provider
// filled it, and no totals, because the provider reports none (#858, D6).
func TestNewProviderPageMeta(t *testing.T) {
	tests := []struct {
		name               string
		page, perPage, got int
		want               string
	}{
		{"a full page has a next page", 2, 50, 50, `{"pagination":{"current-page":2,"page-size":50,"prev-page":1,"next-page":3,"total-pages":null,"total-count":null}}`},
		{"a short page is the last", 2, 50, 12, `{"pagination":{"current-page":2,"page-size":50,"prev-page":1,"next-page":null,"total-pages":null,"total-count":null}}`},
		{"the first page has no previous", 1, 30, 30, `{"pagination":{"current-page":1,"page-size":30,"prev-page":null,"next-page":2,"total-pages":null,"total-count":null}}`},
		{"nonsense input is clamped", 0, 0, 0, `{"pagination":{"current-page":1,"page-size":1,"prev-page":null,"next-page":null,"total-pages":null,"total-count":null}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(NewProviderPageMeta(tt.page, tt.perPage, tt.got))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != tt.want {
				t.Errorf("got  %s\nwant %s", raw, tt.want)
			}
		})
	}
}

func writtenBody(t *testing.T, fn func(c *gin.Context)) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	fn(c)
	return rec.Code, rec.Body.String()
}

// A value with no identity is a document with meta and no data member at all: not "data": null,
// which would say "the resource is absent" (#858, D1).
func TestWriteMetaHasNoDataMember(t *testing.T) {
	code, body := writtenBody(t, func(c *gin.Context) {
		WriteMeta(c, http.StatusOK, map[string]string{"install-url": "https://example.test/install"})
	})
	if code != http.StatusOK {
		t.Errorf("status: got %d, want 200", code)
	}
	want := `{"meta":{"install-url":"https://example.test/install"}}`
	if body != want {
		t.Errorf("body:\n got  %s\n want %s", body, want)
	}
}

// WriteDoc carries the members WriteDocument and WriteDocumentMeta do not take, so the two
// documents with included or links leave through the jsonapi package too (#858, D1).
func TestWriteDocPassesIncludedAndLinks(t *testing.T) {
	code, body := writtenBody(t, func(c *gin.Context) {
		WriteDoc(c, http.StatusCreated, Document{
			Data:     map[string]string{"type": "vars", "id": "v1"},
			Included: []map[string]string{{"type": "workspaces", "id": "w1"}},
			Links:    SelfLink{Self: "/api/v2/vars"},
		})
	})
	if code != http.StatusCreated {
		t.Errorf("status: got %d, want 201", code)
	}
	want := `{"data":{"id":"v1","type":"vars"},"included":[{"id":"w1","type":"workspaces"}],"links":{"self":"/api/v2/vars"}}`
	if body != want {
		t.Errorf("body:\n got  %s\n want %s", body, want)
	}
}

// An unpaged provider listing (a file tree the provider returns whole, or truncates without
// saying how much) is one page of what came back, with no next page and no totals (#858, Q11).
func TestNewProviderListMeta(t *testing.T) {
	tests := []struct {
		got  int
		want string
	}{
		{3, `{"pagination":{"current-page":1,"page-size":3,"prev-page":null,"next-page":null,"total-pages":null,"total-count":null}}`},
		{0, `{"pagination":{"current-page":1,"page-size":1,"prev-page":null,"next-page":null,"total-pages":null,"total-count":null}}`},
	}
	for _, tt := range tests {
		raw, err := json.Marshal(NewProviderListMeta(tt.got))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != tt.want {
			t.Errorf("NewProviderListMeta(%d):\n got  %s\n want %s", tt.got, raw, tt.want)
		}
	}
}
