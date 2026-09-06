// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Tests for the shared pagination block (#756, AC1).
//
// The boundary cases are ported from TestFullPaginationMeta in
// handlers/terraform/run_tasks.go, which was the only correct implementation in the tree before
// this converged the other eight variants onto it. Its comment recorded why the shorter
// variants are not enough: "a nil next-page terminates its loop".

package jsonapi

import (
	"encoding/json"
	"testing"
)

func TestPaginationMiddlePage(t *testing.T) {
	p := NewPaginationMeta(2, 20, 45).Pagination
	if p.CurrentPage != 2 || p.PageSize != 20 {
		t.Errorf("page/size: got %d/%d, want 2/20", p.CurrentPage, p.PageSize)
	}
	if p.TotalCount != 45 {
		t.Errorf("total-count: got %d, want 45", p.TotalCount)
	}
	if p.TotalPages != 3 {
		t.Errorf("total-pages for 45 items at 20 per page: got %d, want 3 (must round up)", p.TotalPages)
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
	if p.TotalPages != 1 {
		t.Errorf("total-pages for an empty collection: got %d, want 1", p.TotalPages)
	}
	if p.PrevPage != nil || p.NextPage != nil {
		t.Errorf("empty collection must have no prev/next: %+v", p)
	}
	if p.TotalCount != 0 {
		t.Errorf("total-count: got %d, want 0", p.TotalCount)
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
	if p.TotalPages != 10 {
		t.Errorf("total-pages: got %d, want 10", p.TotalPages)
	}
}
