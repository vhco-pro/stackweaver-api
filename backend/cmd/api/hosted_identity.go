// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gopkg.in/yaml.v3"
)

// hostedIdentityFromEnv reads the hosted binding an operator declares (#1113, D3), which the chart
// sets from launcher.hostedIdentity: STACKWEAVER_HOSTED_IDENTITY_NAME, _MECHANISM,
// _SERVICE_ACCOUNT and _ANNOTATIONS, a YAML mapping of annotation keys to string values (the chart
// renders it as JSON, which YAML reads the same). An empty name means no hosted binding. An
// invalid configuration is an error naming the reason, which stops the API at startup.
func hostedIdentityFromEnv(getenv func(string) string) (*repository.HostedBindingConfig, error) {
	name := strings.TrimSpace(getenv("STACKWEAVER_HOSTED_IDENTITY_NAME"))
	if name == "" {
		return nil, nil //nolint:nilnil // no hosted binding configured
	}
	cfg := &repository.HostedBindingConfig{
		Name:           name,
		Mechanism:      strings.TrimSpace(getenv("STACKWEAVER_HOSTED_IDENTITY_MECHANISM")),
		ServiceAccount: strings.TrimSpace(getenv("STACKWEAVER_HOSTED_IDENTITY_SERVICE_ACCOUNT")),
		Annotations:    map[string]string{},
	}
	if raw := strings.TrimSpace(getenv("STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS")); raw != "" {
		if err := yaml.Unmarshal([]byte(raw), &cfg.Annotations); err != nil {
			return nil, fmt.Errorf("STACKWEAVER_HOSTED_IDENTITY_ANNOTATIONS must be a YAML mapping of annotation keys to string values: %w", err)
		}
	}
	ann := models.JSONB{}
	for k, v := range cfg.Annotations {
		ann[k] = v
	}
	b := &models.IdentityBinding{Name: cfg.Name, Mechanism: cfg.Mechanism, ServiceAccount: cfg.ServiceAccount, Annotations: ann, Reference: true}
	if reason := handlers.ValidateHostedBinding(b); reason != "" {
		return nil, errors.New("the hosted identity binding (STACKWEAVER_HOSTED_IDENTITY_*) is invalid: " + reason)
	}
	return cfg, nil
}
