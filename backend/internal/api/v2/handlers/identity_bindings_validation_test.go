// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"strings"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// TestValidateBinding: a binding is refused at the save, not at a job's launch, when its name is
// not a plain name, an annotation key is not a Kubernetes annotation key, or a ServiceAccount the
// launcher creates lacks its mechanism's annotation (#933, D5, D8): IRSA's role ARN and Entra
// Workload ID's client id. A referenced account carries its annotations where it is declared.
func TestValidateBinding(t *testing.T) {
	const arn = "eks.amazonaws.com/role-arn"
	const clientID = "azure.workload.identity/client-id"
	base := func(mechanism string, ann map[string]any) *models.IdentityBinding {
		return &models.IdentityBinding{Name: "deploy", Mechanism: mechanism, ServiceAccount: "sw-deploy", Annotations: models.JSONB(ann)}
	}
	reference := func(b *models.IdentityBinding) *models.IdentityBinding { b.Reference = true; return b }
	perJob := func(b *models.IdentityBinding) *models.IdentityBinding {
		b.Reference, b.PerJobSA = true, true
		return b
	}
	named := func(name string) *models.IdentityBinding {
		b := base(models.IdentityMechanismAWSPodIdentity, nil)
		b.Name = name
		return b
	}

	for name, b := range map[string]*models.IdentityBinding{
		"an IRSA binding with its role ARN":        base(models.IdentityMechanismAWSIRSA, map[string]any{arn: "arn:aws:iam::123456789012:role/deploy"}),
		"an IRSA role in another partition":        base(models.IdentityMechanismAWSIRSA, map[string]any{arn: "arn:aws-us-gov:iam::1:role/x/y"}),
		"a referenced IRSA account":                reference(base(models.IdentityMechanismAWSIRSA, nil)),
		"an Entra binding with its client id":      base(models.IdentityMechanismAzureWorkloadIdentity, map[string]any{clientID: "00000000-0000-0000-0000-000000000000"}),
		"a Pod Identity binding, which needs none": base(models.IdentityMechanismAWSPodIdentity, nil),
		"a GKE binding without the optional one":   base(models.IdentityMechanismGCPWorkloadIdentity, nil),
		"a GKE binding with its service account":   base(models.IdentityMechanismGCPWorkloadIdentity, map[string]any{"iam.gke.io/gcp-service-account": "deploy@p.iam.gserviceaccount.com"}),
		"an extra annotation without a prefix":     base(models.IdentityMechanismAWSPodIdentity, map[string]any{"owner": "platform"}),
		"a name with dots, dashes and underscores": named("prod.deploy_role-1"),
	} {
		if detail := validateBinding(b); detail != "" {
			t.Errorf("%s refused: %s", name, detail)
		}
	}

	for name, tc := range map[string]struct {
		b    *models.IdentityBinding
		word string
	}{
		"an IRSA binding without its role ARN":           {base(models.IdentityMechanismAWSIRSA, nil), arn},
		"an IRSA binding with an empty role ARN":         {base(models.IdentityMechanismAWSIRSA, map[string]any{arn: " "}), arn},
		"an IRSA role ARN that is not a role ARN":        {base(models.IdentityMechanismAWSIRSA, map[string]any{arn: "deploy"}), arn},
		"a per-job clone of a referenced IRSA account":   {perJob(base(models.IdentityMechanismAWSIRSA, nil)), arn},
		"an Entra binding without its client id":         {base(models.IdentityMechanismAzureWorkloadIdentity, nil), clientID},
		"an Entra client id that is not an id":           {base(models.IdentityMechanismAzureWorkloadIdentity, map[string]any{clientID: "cid"}), clientID},
		"a name with spaces and punctuation":             {named("explore-1105 Bad Name!!"), "name"},
		"a name starting with a dash":                    {named("-deploy"), "name"},
		"an annotation key with a space":                 {base(models.IdentityMechanismAWSPodIdentity, map[string]any{"not a key": "v"}), "annotation"},
		"an annotation key with an empty name":           {base(models.IdentityMechanismAWSPodIdentity, map[string]any{"example.com/": "v"}), "annotation"},
		"an annotation key whose prefix is not a domain": {base(models.IdentityMechanismAWSPodIdentity, map[string]any{"Bad_Prefix/x": "v"}), "annotation"},
		"an annotation key whose name is too long":       {base(models.IdentityMechanismAWSPodIdentity, map[string]any{strings.Repeat("a", 64): "v"}), "annotation"},
	} {
		if detail := validateBinding(tc.b); !strings.Contains(detail, tc.word) {
			t.Errorf("%s: detail %q, want a refusal naming %q", name, detail, tc.word)
		}
	}
}
