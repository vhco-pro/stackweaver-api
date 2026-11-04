// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/url"

	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/core/settings"
)

// DeploymentSettingsAttributes are the deployment-wide runner settings the API reads from the chart
// or the hand-managed env files (#933, D0, D15). They are read-only: nothing in the API writes
// them. The per-launcher settings (driver, network mode, hosted group) are on the runner rows.
type DeploymentSettingsAttributes struct {
	// ImagesAllowedRegistries is images.allowed_registries; empty means any registry (D6).
	ImagesAllowedRegistries []string `json:"images-allowed-registries"`
	// HostedDefaultMaxConcurrentJobs is hosted.default_max_concurrent_jobs; zero is unlimited (D9).
	HostedDefaultMaxConcurrentJobs int `json:"hosted-default-max-concurrent-jobs"`
	// RunTimeoutDefault and SyncTimeout are in seconds (D0, D2).
	RunTimeoutDefault int   `json:"run-timeout-default"`
	SyncTimeout       int   `json:"sync-timeout"`
	JobLogMaxBytes    int64 `json:"job-log-max-bytes"`
	// CacheSizeLimit is the per-organization cache bound in bytes when an organization sets none (D7).
	CacheSizeLimit  int64      `json:"cache-size-limit"`
	RunnerRateLimit RateBudget `json:"runner-rate-limit"`
	JobRateLimit    RateBudget `json:"job-rate-limit"`
	// Mirror is the deployment's mirror block (D2), nil when jobs use the public upstreams.
	Mirror *DeploymentMirror `json:"mirror"`
}

// RateBudget is a per-principal request budget of the runner control plane (D3).
type RateBudget struct {
	RPS   int `json:"rps"`
	Burst int `json:"burst"`
}

// DeploymentMirror is the mirror block without its secrets: Galaxy servers without their tokens,
// proxies without their user information, and whether a CA bundle is configured rather than the
// bundle.
type DeploymentMirror struct {
	TofuReleasesURL       string                   `json:"tofu-releases-url"`
	TofuVersionIndexURL   string                   `json:"tofu-version-index-url"`
	ProviderNetworkMirror string                   `json:"provider-network-mirror"`
	GalaxyServers         []DeploymentGalaxyServer `json:"galaxy-servers"`
	PipIndexURL           string                   `json:"pip-index-url"`
	PipTrustedHost        string                   `json:"pip-trusted-host"`
	HTTPProxy             string                   `json:"http-proxy"`
	HTTPSProxy            string                   `json:"https-proxy"`
	NoProxy               string                   `json:"no-proxy"`
	HasCACertificates     bool                     `json:"has-ca-certificates"`
}

// DeploymentGalaxyServer is one Galaxy server of the mirror block, without its token.
type DeploymentGalaxyServer struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	HasToken bool   `json:"has-token"`
}

// withoutUserinfo drops the user information of a URL; a value that is not one is returned as is.
func withoutUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

// deploymentSettings reads the deployment's runner settings through getenv and readFile.
func deploymentSettings(getenv func(string) string, readFile func(string) ([]byte, error)) DeploymentSettingsAttributes {
	budgets := middleware.RunnerRateBudgetsFrom(getenv)
	out := DeploymentSettingsAttributes{
		ImagesAllowedRegistries:        settings.AllowedRegistries(getenv),
		HostedDefaultMaxConcurrentJobs: settings.HostedDefaultMaxConcurrentJobs(getenv),
		RunTimeoutDefault:              settings.DeploymentRunTimeout(getenv),
		SyncTimeout:                    settings.SyncTimeout(getenv),
		JobLogMaxBytes:                 settings.JobLogMaxBytes(getenv),
		CacheSizeLimit:                 settings.DeploymentCacheSizeLimit(getenv),
		RunnerRateLimit:                RateBudget{RPS: budgets.RunnerRPS, Burst: budgets.RunnerBurst},
		JobRateLimit:                   RateBudget{RPS: budgets.JobRPS, Burst: budgets.JobBurst},
	}
	if out.ImagesAllowedRegistries == nil {
		out.ImagesAllowedRegistries = []string{}
	}
	if m := settings.MirrorFromEnv(getenv, readFile); m != nil {
		dm := &DeploymentMirror{
			TofuReleasesURL: m.TofuReleasesURL, TofuVersionIndexURL: m.TofuVersionIndexURL,
			ProviderNetworkMirror: m.ProviderNetworkMirror, GalaxyServers: []DeploymentGalaxyServer{},
			PipIndexURL: withoutUserinfo(m.PipIndexURL), PipTrustedHost: m.PipTrustedHost,
			HTTPProxy: withoutUserinfo(m.HTTPProxy), HTTPSProxy: withoutUserinfo(m.HTTPSProxy), NoProxy: m.NoProxy,
			HasCACertificates: m.CACertificates != "",
		}
		for _, g := range m.GalaxyServers {
			dm.GalaxyServers = append(dm.GalaxyServers, DeploymentGalaxyServer{Name: g.Name, URL: withoutUserinfo(g.URL), HasToken: g.Token != ""})
		}
		out.Mirror = dm
	}
	return out
}
