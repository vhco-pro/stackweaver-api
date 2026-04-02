// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
)

func TestExtractOutputsFromStateData_Nil(t *testing.T) {
	result := extractOutputsFromStateData(nil, false)
	if len(result) != 0 {
		t.Errorf("expected 0 outputs for nil version, got %d", len(result))
	}
}

func TestExtractOutputsFromStateData_NilStateData(t *testing.T) {
	v := &models.StateVersion{
		ID:        "sv-test",
		StateData: nil,
	}
	result := extractOutputsFromStateData(v, false)
	if len(result) != 0 {
		t.Errorf("expected 0 outputs for nil state data, got %d", len(result))
	}
}

func TestExtractOutputsFromStateData_NoOutputs(t *testing.T) {
	v := &models.StateVersion{
		ID: "sv-test",
		StateData: models.StateData{
			"version": float64(4),
		},
	}
	result := extractOutputsFromStateData(v, false)
	if len(result) != 0 {
		t.Errorf("expected 0 outputs when no outputs key, got %d", len(result))
	}
}

func TestExtractOutputsFromStateData_BasicOutputs(t *testing.T) {
	v := &models.StateVersion{
		ID: "sv-test123",
		StateData: models.StateData{
			"outputs": map[string]interface{}{
				"vpc_id": map[string]interface{}{
					"value": "vpc-abc123",
					"type":  "string",
				},
				"instance_count": map[string]interface{}{
					"value": float64(3),
					"type":  "number",
				},
			},
		},
	}

	result := extractOutputsFromStateData(v, false)
	if len(result) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(result))
	}

	// Find vpc_id output — attributes is gin.H
	found := false
	for _, output := range result {
		attrs, ok := output["attributes"].(gin.H)
		if !ok {
			continue
		}
		if attrs["name"] == "vpc_id" {
			found = true
			if attrs["value"] != "vpc-abc123" {
				t.Errorf("vpc_id value = %v, want vpc-abc123", attrs["value"])
			}
			if attrs["type"] != "string" {
				t.Errorf("vpc_id type = %v, want string", attrs["type"])
			}
			if output["type"] != "state-version-outputs" {
				t.Errorf("output type = %v, want state-version-outputs", output["type"])
			}
		}
	}
	if !found {
		t.Error("vpc_id output not found in results")
	}
}

func TestExtractOutputsFromStateData_SensitiveMasked(t *testing.T) {
	v := &models.StateVersion{
		ID: "sv-sens",
		StateData: models.StateData{
			"outputs": map[string]interface{}{
				"db_password": map[string]interface{}{
					"value":     "secret123",
					"type":      "string",
					"sensitive": true,
				},
				"public_ip": map[string]interface{}{
					"value": "10.0.0.1",
					"type":  "string",
				},
			},
		},
	}

	// With masking enabled
	result := extractOutputsFromStateData(v, true)

	for _, output := range result {
		attrs, ok := output["attributes"].(gin.H)
		if !ok {
			continue
		}
		if attrs["name"] == "db_password" {
			if attrs["value"] != nil {
				t.Errorf("sensitive value should be nil when masked, got %v", attrs["value"])
			}
			if attrs["sensitive"] != true {
				t.Errorf("sensitive flag should be true, got %v", attrs["sensitive"])
			}
		}
		if attrs["name"] == "public_ip" {
			if attrs["value"] != "10.0.0.1" {
				t.Errorf("non-sensitive value should be preserved, got %v", attrs["value"])
			}
		}
	}
}

func TestExtractOutputsFromStateData_SensitiveNotMasked(t *testing.T) {
	v := &models.StateVersion{
		ID: "sv-nomask",
		StateData: models.StateData{
			"outputs": map[string]interface{}{
				"db_password": map[string]interface{}{
					"value":     "secret123",
					"sensitive": true,
				},
			},
		},
	}

	// With masking disabled
	result := extractOutputsFromStateData(v, false)
	if len(result) != 1 {
		t.Fatalf("expected 1 output, got %d", len(result))
	}

	attrs, ok := result[0]["attributes"].(gin.H)
	if !ok {
		t.Fatal("attributes not found")
	}
	if attrs["value"] != "secret123" {
		t.Errorf("value should be visible when not masked, got %v", attrs["value"])
	}
}

func TestExtractOutputsFromStateData_OutputID(t *testing.T) {
	v := &models.StateVersion{
		ID: "sv-id-test",
		StateData: models.StateData{
			"outputs": map[string]interface{}{
				"my_output": map[string]interface{}{
					"value": "test",
				},
			},
		},
	}

	result := extractOutputsFromStateData(v, false)
	if len(result) != 1 {
		t.Fatalf("expected 1 output, got %d", len(result))
	}

	expectedID := "sv-id-test-my_output"
	if result[0]["id"] != expectedID {
		t.Errorf("output id = %v, want %v", result[0]["id"], expectedID)
	}
}

func TestExtractOutputsFromStateData_InvalidOutputEntries(t *testing.T) {
	v := &models.StateVersion{
		ID: "sv-invalid",
		StateData: models.StateData{
			"outputs": map[string]interface{}{
				"valid": map[string]interface{}{
					"value": "ok",
				},
				"invalid": "not-a-map",
			},
		},
	}

	result := extractOutputsFromStateData(v, false)
	// Should only get the valid output, skip the invalid one
	if len(result) != 1 {
		t.Fatalf("expected 1 output (skip invalid), got %d", len(result))
	}
}
