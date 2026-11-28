// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"strings"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

func hostedEnv(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func validHostedEnv() map[string]string {
	return map[string]string{
		"STACKWEAVER_HOSTED_IDENTITY_NAME":            "hosted-workload-identity",
		"STACKWEAVER_HOSTED_IDENTITY_MECHANISM":       models.IdentityMechanismAzureWorkloadIdentity,
		"STACKWEAVER_HOSTED_IDENTITY_SERVICE_ACCOUNT": "stackweaver-hosted-identity",
		"STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS":     `{"azure.workload.identity/client-id":"11111111-2222-3333-4444-555555555555"}`,
	}
}

// The API reads the hosted binding from four variables at startup (#1113, D3, AC-05, AC-07): an
// empty name means none, and an invalid configuration stops the API with the reason, including a
// missing or malformed required annotation, which a synthesized reference binding would otherwise
// skip.
func TestHostedIdentityFromEnv(t *testing.T) {
	cfg, err := hostedIdentityFromEnv(hostedEnv(validHostedEnv()))
	if err != nil || cfg == nil {
		t.Fatalf("valid configuration = %+v, %v; want it parsed", cfg, err)
	}
	if cfg.Name != "hosted-workload-identity" || cfg.Mechanism != models.IdentityMechanismAzureWorkloadIdentity || cfg.ServiceAccount != "stackweaver-hosted-identity" ||
		cfg.Annotations["azure.workload.identity/client-id"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("parsed configuration = %+v", cfg)
	}

	if cfg, err := hostedIdentityFromEnv(hostedEnv(map[string]string{})); err != nil || cfg != nil {
		t.Errorf("no configuration = %+v, %v; want none and no error", cfg, err)
	}
	none := validHostedEnv()
	none["STACKWEAVER_HOSTED_IDENTITY_NAME"] = ""
	if cfg, err := hostedIdentityFromEnv(hostedEnv(none)); err != nil || cfg != nil {
		t.Errorf("empty name = %+v, %v; want none and no error", cfg, err)
	}

	cases := map[string]struct {
		key, value string
		want       string
	}{
		"missing client id":    {"STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS", `{}`, "the hosted binding (azure-workload-identity) needs the annotation azure.workload.identity/client-id"},
		"malformed client id":  {"STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS", `{"azure.workload.identity/client-id":"not-a-uuid"}`, "the hosted binding (azure-workload-identity) needs the annotation azure.workload.identity/client-id"},
		"annotations not JSON": {"STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS", `client-id=x`, "STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS"},
		"bad annotation key":   {"STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS", `{"azure.workload.identity/client-id":"11111111-2222-3333-4444-555555555555","bad key":"x"}`, "bad key"},
		"unknown mechanism":    {"STACKWEAVER_HOSTED_IDENTITY_MECHANISM", "kerberos", "mechanism"},
		"bad service account":  {"STACKWEAVER_HOSTED_IDENTITY_SERVICE_ACCOUNT", "Not_A_Name", "service-account"},
		"bad name":             {"STACKWEAVER_HOSTED_IDENTITY_NAME", "-leading-dash", "name"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			env := validHostedEnv()
			env[c.key] = c.value
			cfg, err := hostedIdentityFromEnv(hostedEnv(env))
			if err == nil {
				t.Fatalf("configuration accepted: %+v", cfg)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %q", err, c.want)
			}
		})
	}
}

// The annotations variable is a YAML mapping, and the chart's JSON rendering of that mapping
// configures the same binding (#1113, D3, AC-07). A value that is not a mapping stops the API with
// the reason.
func TestHostedIdentityAnnotationsAsYAML(t *testing.T) {
	forms := map[string]string{
		"YAML block mapping": "azure.workload.identity/client-id: \"11111111-2222-3333-4444-555555555555\"\nazure.workload.identity/tenant-id: \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n",
		"YAML flow mapping":  `{azure.workload.identity/client-id: 11111111-2222-3333-4444-555555555555, azure.workload.identity/tenant-id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}`,
		"chart JSON":         `{"azure.workload.identity/client-id":"11111111-2222-3333-4444-555555555555","azure.workload.identity/tenant-id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}`,
	}
	for name, raw := range forms {
		env := validHostedEnv()
		env["STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS"] = raw
		cfg, err := hostedIdentityFromEnv(hostedEnv(env))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Annotations["azure.workload.identity/client-id"] != "11111111-2222-3333-4444-555555555555" ||
			cfg.Annotations["azure.workload.identity/tenant-id"] != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" || len(cfg.Annotations) != 2 {
			t.Errorf("%s: annotations = %v", name, cfg.Annotations)
		}
	}
	for name, raw := range map[string]string{
		"a list":       "- azure.workload.identity/client-id\n",
		"a scalar":     "client-id",
		"nested value": "azure.workload.identity/client-id:\n  nested: x\n",
	} {
		env := validHostedEnv()
		env["STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS"] = raw
		if _, err := hostedIdentityFromEnv(hostedEnv(env)); err == nil || !strings.Contains(err.Error(), "STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS") {
			t.Errorf("%s: err = %v, want a startup error naming the variable", name, err)
		}
	}
}
