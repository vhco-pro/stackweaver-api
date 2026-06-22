// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
)

// buildMaterializedOutputs renders TFE state-version-outputs from the materialized rows
// (the State Storage Rework single source of truth). Value/Type are stored JSON-encoded
// and decoded back into real JSON values for the response. Extraction from raw state is
// covered by core/services/state extractor tests.

func TestBuildMaterializedOutputs_Empty(t *testing.T) {
	if result := buildMaterializedOutputs(nil, false, nil); len(result) != 0 {
		t.Errorf("expected 0 outputs for nil rows, got %d", len(result))
	}
}

func TestBuildMaterializedOutputs_ValueAndType(t *testing.T) {
	rows := []models.StateVersionOutput{
		{ID: "wsout-vpc", Name: "vpc_id", Value: `"vpc-abc123"`, Type: `"string"`},
		{ID: "wsout-cnt", Name: "instance_count", Value: `3`, Type: `"number"`},
	}
	result := buildMaterializedOutputs(rows, false, nil)
	if len(result) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(result))
	}

	found := false
	for _, output := range result {
		attrs, ok := output["attributes"].(gin.H)
		if !ok {
			continue
		}
		if attrs["name"] == "vpc_id" {
			found = true
			if attrs["value"] != "vpc-abc123" {
				t.Errorf("vpc_id value = %v, want vpc-abc123 (decoded)", attrs["value"])
			}
			if attrs["type"] != "string" {
				t.Errorf("vpc_id type = %v, want string", attrs["type"])
			}
			if output["type"] != "state-version-outputs" {
				t.Errorf("output type = %v, want state-version-outputs", output["type"])
			}
			if output["id"] != "wsout-vpc" {
				t.Errorf("output id = %v, want wsout-vpc", output["id"])
			}
		}
	}
	if !found {
		t.Error("vpc_id output not found in results")
	}
}

func TestBuildMaterializedOutputs_NumberDecoded(t *testing.T) {
	result := buildMaterializedOutputs([]models.StateVersionOutput{
		{ID: "wsout-n", Name: "count", Value: `3`},
	}, false, nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 output, got %d", len(result))
	}
	attrs := result[0]["attributes"].(gin.H)
	// JSON numbers decode to float64.
	if v, ok := attrs["value"].(float64); !ok || v != 3 {
		t.Errorf("count value = %v (%T), want float64(3)", attrs["value"], attrs["value"])
	}
}

func TestBuildMaterializedOutputs_SensitiveMasked(t *testing.T) {
	rows := []models.StateVersionOutput{
		{ID: "wsout-pw", Name: "db_password", Value: `"secret123"`, Type: `"string"`, Sensitive: true},
		{ID: "wsout-ip", Name: "public_ip", Value: `"10.0.0.1"`, Type: `"string"`},
	}
	result := buildMaterializedOutputs(rows, true, nil)

	for _, output := range result {
		attrs := output["attributes"].(gin.H)
		if attrs["name"] == "db_password" {
			if attrs["value"] != nil {
				t.Errorf("sensitive value should be nil when masked, got %v", attrs["value"])
			}
			if attrs["sensitive"] != true {
				t.Errorf("sensitive flag should be true, got %v", attrs["sensitive"])
			}
		}
		if attrs["name"] == "public_ip" && attrs["value"] != "10.0.0.1" {
			t.Errorf("non-sensitive value should be preserved, got %v", attrs["value"])
		}
	}
}

func TestBuildMaterializedOutputs_SensitiveNotMasked(t *testing.T) {
	result := buildMaterializedOutputs([]models.StateVersionOutput{
		{ID: "wsout-pw", Name: "db_password", Value: `"secret123"`, Sensitive: true},
	}, false, nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 output, got %d", len(result))
	}
	attrs := result[0]["attributes"].(gin.H)
	if attrs["value"] != "secret123" {
		t.Errorf("value should be visible when not masked, got %v", attrs["value"])
	}
}

func TestBuildMaterializedOutputs_EncryptedValueDecrypted(t *testing.T) {
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	ciphertext, err := cs.Encrypt(`"secret123"`)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	rows := []models.StateVersionOutput{
		{ID: "wsout-pw", Name: "db_password", Value: ciphertext, Sensitive: true, ValueEncrypted: true},
	}

	// With crypto and no masking, the encrypted value is decrypted back to plaintext.
	result := buildMaterializedOutputs(rows, false, cs)
	if v := result[0]["attributes"].(gin.H)["value"]; v != "secret123" {
		t.Errorf("encrypted value should decrypt to secret123, got %v", v)
	}

	// With crypto and masking, it is still nulled (TFE behaviour preserved).
	result = buildMaterializedOutputs(rows, true, cs)
	if v := result[0]["attributes"].(gin.H)["value"]; v != nil {
		t.Errorf("encrypted+masked value should be nil, got %v", v)
	}
}

func TestBuildMaterializedOutputs_EncryptedValueNeverLeaksWithoutKey(t *testing.T) {
	// An encrypted value with no crypto available must be nulled, never emitted as ciphertext.
	rows := []models.StateVersionOutput{
		{ID: "wsout-pw", Name: "db_password", Value: "Y2lwaGVydGV4dA==", Sensitive: true, ValueEncrypted: true},
	}
	result := buildMaterializedOutputs(rows, false, nil)
	if v := result[0]["attributes"].(gin.H)["value"]; v != nil {
		t.Errorf("encrypted value must be nil without a key, got %v", v)
	}
}
