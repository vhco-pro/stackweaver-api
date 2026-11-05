// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"strings"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// TestApplyPoolSettings_Limits: a pool's CPU and memory limits are checked when they are saved, in
// the forms both drivers read (#933, D4, AC24), rather than failing every job at launch. CPU is a
// number of cores or millicores from 0.01 (10m); memory is bytes or a number with Ki, Mi, Gi, Ti,
// K, M, G or T from 6Mi, the smallest limit Docker accepts. Empty clears a limit.
func TestApplyPoolSettings_Limits(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, cpu := range []string{"1", "0.5", "2.25", "500m", "10m", "16", ""} {
		pool := &models.AgentPool{}
		if detail := applyPoolSettings(pool, nil, str(cpu), nil, nil, nil); detail != "" {
			t.Errorf("cpu-limit %q refused: %s", cpu, detail)
		}
	}
	for _, mem := range []string{"512Mi", "2Gi", "1.5Gi", "1G", "6Mi", "8388608", "1Ti", ""} {
		pool := &models.AgentPool{}
		if detail := applyPoolSettings(pool, nil, nil, str(mem), nil, nil); detail != "" {
			t.Errorf("memory-limit %q refused: %s", mem, detail)
		}
	}
	for _, cpu := range []string{"abc", "lots", "-1", "0", "0m", "5m", "1.5m", "1e3", "2 cores", "1Gi"} {
		pool := &models.AgentPool{CPULimit: "1"}
		detail := applyPoolSettings(pool, nil, str(cpu), nil, nil, nil)
		if !strings.Contains(detail, "cpu-limit") {
			t.Errorf("cpu-limit %q accepted (detail %q)", cpu, detail)
		}
	}
	for _, mem := range []string{"abc", "lots", "-1Gi", "0", "1Mi", "1024", "1.5", "2GB", "1Pi", "Gi"} {
		pool := &models.AgentPool{MemoryLimit: "1Gi"}
		detail := applyPoolSettings(pool, nil, nil, str(mem), nil, nil)
		if !strings.Contains(detail, "memory-limit") {
			t.Errorf("memory-limit %q accepted (detail %q)", mem, detail)
		}
	}
}
